"""Wire codec for the UMIDIGI Uwatch 5S (LaiSi / lstech protocol).

Frame layout (see PROTOCOL.md §3):

    0xAA | flags | len_be16 | checksum | seq | cmd | 0x00 | key | clen_be16 | content

Outer header fields are big-endian; integers *inside* payloads are little-endian.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Sequence

MAGIC = 0xAA
HEADER_LEN = 6          # TL1
TL2_PREFIX_LEN = 5      # cmd, rsvd, key, clen_hi, clen_lo

FLAG_ERROR = 0x80
FLAG_ACK = 0x40
VERSION_MASK = 0x3F

# --- GATT ------------------------------------------------------------------
SERVICE_UART = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
CHAR_WRITE = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
CHAR_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
CHAR_NOTIFY_BULK = "6dda1206-bf42-4a68-bdb4-d045eb14a4cc"

MTU_REQUEST = 247
CHUNK_SIZE = 240
COMMAND_TIMEOUT_S = 5.0

# --- commands --------------------------------------------------------------
CMD_SESSION = 0x01
CMD_SET = 0x02
CMD_HISTORY = 0x03
CMD_GET = 0x04
CMD_DIAL = 0x08

KEY_BOND = 0x01
KEY_UNBOND = 0x02
KEY_LOGIN = 0x03

KEY_SET_ALARM = 0x02
KEY_FIND_DEVICE = 0x09
KEY_SET_PANEL = 0x0F
KEY_CMD_INTERVAL = 0x13
KEY_SET_NOTIFY = 0x19
KEY_SET_LANGUAGE = 0x1A
KEY_SET_UNIT = 0x25
KEY_SET_TIME = 0x26

KEY_HIST_EXERCISE = 0x01
KEY_HIST_HEART = 0x02
KEY_HIST_SLEEP = 0x03
KEY_HIST_STEPS = 0x05
KEY_HIST_SPO2 = 0x06
KEY_HIST_BP = 0x07

KEY_GET_POWER = 0x01
KEY_GET_VERSION = 0x02
KEY_GET_ALARM = 0x04
KEY_GET_PANEL = 0x0A
KEY_GET_RANDOM = 0x0D
KEY_GET_FUNCTION_TABLE = 0x19
KEY_GET_DEVICE_ID = 0x1A

MAX_ALARMS = 10
ALARM_RECORD_LEN = 4
ALARM_PAYLOAD_LEN = 1 + MAX_ALARMS * ALARM_RECORD_LEN   # 41

CMD_INTERVAL_SYNC = bytes([0x32, 0x24])
CMD_INTERVAL_IDLE = bytes([0xD6, 0xC8])


class ProtocolError(ValueError):
    pass


def checksum(data: bytes) -> int:
    """Sum of bytes, truncated to 8 bits (BleInstruction.getCheckSum)."""
    return sum(data) & 0xFF


def encode(command: int, key: int, content: bytes | None = None, seq: int = 1) -> bytes:
    """Build a frame. Mirrors BleInstruction.encode()."""
    content = content or b""
    clen = len(content)
    if clen > 0xFFFF:
        raise ProtocolError("content too long")
    payload = bytes([command & 0xFF, 0x00, key & 0xFF,
                     (clen >> 8) & 0xFF, clen & 0xFF]) + content
    header = bytes([MAGIC, 0x01,
                    (len(payload) >> 8) & 0xFF, len(payload) & 0xFF,
                    checksum(payload), seq & 0xFF])
    return header + payload


@dataclass
class Frame:
    command: int
    key: int
    content: bytes
    seq: int = 0
    version: int = 1
    error: bool = False
    ack: bool = False

    @property
    def tag(self) -> tuple[int, int]:
        return (self.command, self.key)


def decode(raw: bytes) -> Frame:
    """Parse a frame. Mirrors BleInstruction.decode(), raising instead of error codes."""
    if not raw or raw[0] != MAGIC:
        raise ProtocolError("invalid magic")
    if len(raw) < HEADER_LEN:
        raise ProtocolError("frame too short")
    declared = (raw[2] << 8) | raw[3]
    if declared != len(raw) - HEADER_LEN:
        raise ProtocolError(f"length mismatch: header says {declared}, got {len(raw) - HEADER_LEN}")
    if raw[4] != checksum(raw[HEADER_LEN:]):
        raise ProtocolError("checksum mismatch")
    if len(raw) < 11:
        raise ProtocolError("truncated TL2 header")

    clen = (raw[9] << 8) | raw[10]
    content = raw[11:11 + clen]
    if len(content) != clen:
        raise ProtocolError("truncated content")
    return Frame(command=raw[6], key=raw[8], content=content, seq=raw[5],
                 version=raw[1] & VERSION_MASK,
                 error=bool(raw[1] & FLAG_ERROR), ack=bool(raw[1] & FLAG_ACK))


def frame_total_length(raw: bytes) -> int | None:
    """Expected total length from a (possibly partial) buffer, for reassembly."""
    if len(raw) < 4:
        return None
    return HEADER_LEN + ((raw[2] << 8) | raw[3])


class Reassembler:
    """Notifications are MTU-sized; frames may span several. Feed bytes, get frames."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[Frame]:
        self._buf.extend(chunk)
        out: list[Frame] = []
        while self._buf:
            if self._buf[0] != MAGIC:                     # resync
                idx = self._buf.find(bytes([MAGIC]), 1)
                if idx < 0:
                    self._buf.clear()
                    break
                del self._buf[:idx]
                continue
            total = frame_total_length(bytes(self._buf))
            if total is None or len(self._buf) < total:
                break
            raw, self._buf = bytes(self._buf[:total]), bytearray(self._buf[total:])
            try:
                out.append(decode(raw))
            except ProtocolError:
                pass
        return out


# --- helpers ---------------------------------------------------------------
def u16le(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def read_u16le(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<H", data, offset)[0]


# ===========================================================================
#  Feature builders
# ===========================================================================
def get_random_number(seq: int = 1) -> bytes:
    return encode(CMD_GET, KEY_GET_RANDOM, seq=seq)


def bond(random_bytes: bytes, seq: int = 1) -> bytes:
    return encode(CMD_SESSION, KEY_BOND, random_bytes, seq=seq)


def device_login(auth_key: int, seq: int = 1) -> bytes:
    return encode(CMD_SESSION, KEY_LOGIN, struct.pack("<I", auth_key & 0xFFFFFFFF), seq=seq)


def set_cmd_interval(sync: bool, seq: int = 1) -> bytes:
    return encode(CMD_SET, KEY_CMD_INTERVAL,
                  CMD_INTERVAL_SYNC if sync else CMD_INTERVAL_IDLE, seq=seq)


def find_device(seq: int = 1) -> bytes:
    return encode(CMD_SET, KEY_FIND_DEVICE, seq=seq)


def get_battery(seq: int = 1) -> bytes:
    return encode(CMD_GET, KEY_GET_POWER, seq=seq)


def get_version(seq: int = 1) -> bytes:
    return encode(CMD_GET, KEY_GET_VERSION, seq=seq)


def get_function_table(seq: int = 1) -> bytes:
    return encode(CMD_GET, KEY_GET_FUNCTION_TABLE, seq=seq)


# --- 6.1 time ---------------------------------------------------------------
def build_set_time_payload(epoch_seconds: int, utc_offset_minutes: int) -> bytes:
    """Replicates LaiSiCmd.setTime(). Offset is the *total* UTC offset in minutes
    (DST included), e.g. +60 for CET summer, +330 for IST."""
    now = int(epoch_seconds)
    hours = int(utc_offset_minutes / 60)        # Java int division truncates toward 0
    if hours >= 11:
        now += (hours - 11) * 3600
        hours = 11
    if hours <= -11:
        now += (hours + 11) * 3600
        hours = -11
    sub_hour = (abs(utc_offset_minutes % 60) * 100) // 60
    return bytes([hours & 0xFF]) + struct.pack("<I", now & 0xFFFFFFFF) + bytes([sub_hour & 0xFF])


def set_time(when: datetime | None = None, seq: int = 1) -> bytes:
    """Set the watch clock. `when` must be timezone-aware; defaults to local now."""
    if when is None:
        when = datetime.now().astimezone()
    if when.tzinfo is None:
        raise ProtocolError("datetime must be timezone-aware")
    offset_minutes = int(when.utcoffset().total_seconds() // 60)
    payload = build_set_time_payload(int(when.timestamp()), offset_minutes)
    return encode(CMD_SET, KEY_SET_TIME, payload, seq=seq)


# --- 6.2 alarms -------------------------------------------------------------
MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY, SUNDAY = (1 << i for i in range(7))
EVERY_DAY = 0x7F
WEEKDAYS = MONDAY | TUESDAY | WEDNESDAY | THURSDAY | FRIDAY


@dataclass
class Alarm:
    minutes: int = 0            # minutes after midnight, 0..1439
    days: int = 0               # bit 0..6 week-day mask
    enabled: bool = False
    slot: int = 0

    @property
    def hour(self) -> int:
        return self.minutes // 60

    @property
    def minute(self) -> int:
        return self.minutes % 60

    @classmethod
    def at(cls, hour: int, minute: int, days: int = EVERY_DAY, enabled: bool = True) -> "Alarm":
        if not 0 <= hour <= 23 or not 0 <= minute <= 59:
            raise ProtocolError("invalid time")
        return cls(minutes=hour * 60 + minute, days=days & 0x7F, enabled=enabled)

    def __str__(self) -> str:
        state = "on " if self.enabled else "off"
        return f"[{self.slot}] {self.hour:02d}:{self.minute:02d} {state} days=0b{self.days:07b}"


def build_alarm_payload(alarms: Sequence[Alarm]) -> bytes:
    """41-byte payload: count byte + 10 fixed 4-byte slots."""
    if len(alarms) > MAX_ALARMS:
        raise ProtocolError(f"at most {MAX_ALARMS} alarms")
    buf = bytearray(ALARM_PAYLOAD_LEN)
    buf[0] = MAX_ALARMS
    for i, a in enumerate(alarms):
        days = a.days & 0x7F            # app does: if (days > 128) days &= 127
        base = 1 + i * ALARM_RECORD_LEN
        buf[base:base + 2] = u16le(a.minutes)
        buf[base + 2] = days
        buf[base + 3] = 1 if a.enabled else 0
    return bytes(buf)


def set_alarms(alarms: Sequence[Alarm], seq: int = 1) -> bytes:
    return encode(CMD_SET, KEY_SET_ALARM, build_alarm_payload(alarms), seq=seq)


def get_alarms(seq: int = 1) -> bytes:
    return encode(CMD_GET, KEY_GET_ALARM, seq=seq)


def parse_alarms(content: bytes) -> list[Alarm]:
    """Parse a 0x04/0x04 reply. A slot counts as present only when days != 0."""
    out: list[Alarm] = []
    body = content[1:]
    for i in range(len(body) // ALARM_RECORD_LEN):
        rec = body[i * ALARM_RECORD_LEN:(i + 1) * ALARM_RECORD_LEN]
        if rec[2] == 0:                 # app: toInt(rec[2:3]) > 0
            continue
        out.append(Alarm(minutes=read_u16le(rec, 0), days=rec[2] & 0x7F,
                         enabled=rec[3] == 1, slot=i))
    return out


# --- 6.3 steps --------------------------------------------------------------
STEPS_HEADER_LEN = 12
STEPS_RECORD_LEN = 116
STEPS_BUCKETS_START = 16
STEPS_BUCKETS_END = 112
HOURS_PER_DAY = 24


@dataclass
class DaySteps:
    index: int                      # 0 = today, 1 = yesterday, ...
    steps: int = 0
    secondary: int = 0              # calories / distance
    hourly: list[int] = field(default_factory=list)
    raw_header: bytes = b""

    def __str__(self) -> str:
        label = "today" if self.index == 0 else f"-{self.index}d"
        return f"{label:>6}: {self.steps:6d} steps  (secondary {self.secondary})"


def get_steps(seq: int = 1) -> bytes:
    return encode(CMD_HISTORY, KEY_HIST_STEPS, bytes(6), seq=seq)


def parse_steps(content: bytes) -> list[DaySteps]:
    """Parse a 0x03/0x05 reply: 12-byte header then N x 116-byte day records."""
    days: list[DaySteps] = []
    body = content[STEPS_HEADER_LEN:]
    for i in range(0, len(body), STEPS_RECORD_LEN):
        record = body[i:i + STEPS_RECORD_LEN]
        if len(record) < STEPS_BUCKETS_END:
            break
        buckets = record[STEPS_BUCKETS_START:STEPS_BUCKETS_END]
        hourly, steps, secondary = [], 0, 0
        for h in range(HOURS_PER_DAY):
            s = read_u16le(buckets, h * 4)
            o = read_u16le(buckets, h * 4 + 2)
            hourly.append(s)
            steps += s
            secondary += o
        days.append(DaySteps(index=i // STEPS_RECORD_LEN, steps=steps,
                             secondary=secondary, hourly=hourly,
                             raw_header=record[:STEPS_BUCKETS_START]))
    return days


# --- 6.4 watch face ---------------------------------------------------------
BUILTIN_DIAL_COUNT = 4


def set_panel(index: int, seq: int = 1) -> bytes:
    """Select a built-in watch face. `index` is 0-based (app sends id-1)."""
    if not 0 <= index < BUILTIN_DIAL_COUNT:
        raise ProtocolError(f"dial index must be 0..{BUILTIN_DIAL_COUNT - 1}")
    return encode(CMD_SET, KEY_SET_PANEL, bytes([index]), seq=seq)


def get_panel(seq: int = 1) -> bytes:
    return encode(CMD_GET, KEY_GET_PANEL, seq=seq)


# --- 6.5 notifications ------------------------------------------------------
MSG_SMS, MSG_WHATSAPP, MSG_TELEGRAM, MSG_OTHER = 2, 7, 11, 128


def set_notification(title: str, body: str, msg_type: int = MSG_OTHER, seq: int = 1) -> bytes:
    b = body.encode("utf-8")[:96]
    t = title.encode("utf-8")[:60]
    payload = bytes([msg_type & 0xFF, (len(b) + 1 + len(t) + 1) & 0xFF]) \
        + b + b"\x00" + t + b"\x00\xA5"
    return encode(CMD_SET, KEY_SET_NOTIFY, payload, seq=seq)


def chunk(frame: bytes, size: int = CHUNK_SIZE) -> Iterable[bytes]:
    """Split a frame into GATT writes."""
    for i in range(0, len(frame), size):
        yield frame[i:i + size]
