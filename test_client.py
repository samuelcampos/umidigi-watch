"""Client-level tests that exercise the session logic against a fake watch.

No hardware and no Bluetooth stack involved: a FakeWatch decodes the frames the
client writes and pushes replies back through the notification callback.
"""
import asyncio

import pytest

from uwatch import auth, protocol as p
from uwatch.client import ConnectionError_, Uwatch, _mac_from_advertisement

MAC = "AA:BB:CC:DD:EE:FF"
RANDOM = 0x12345678


class FakeWatch:
    """Stands in for BleakClient. Replies to frames the way the watch would."""

    mtu_size = 247

    def __init__(self, chunk_replies=1, drop=()):
        self.on_notify = None
        self.written = []
        self.rx = p.Reassembler()   # the watch reassembles chunks across writes
        self.chunk_replies = chunk_replies
        self.drop = set(drop)
        self.alarms = bytes([10]) + bytes(40)
        self.panel = 2
        self.logged_in = False
        self.auth_key_seen = None

    async def write_gatt_char(self, _char, data, response=False):
        self.written.append(bytes(data))
        for frame in self.rx.feed(bytes(data)):
            for reply in self._respond(frame):
                self._emit(reply)

    def _emit(self, raw):
        step = max(1, len(raw) // self.chunk_replies)
        for i in range(0, len(raw), step):
            self.on_notify(None, bytearray(raw[i:i + step]))

    def _respond(self, f):
        if f.tag in self.drop:
            return []
        if f.tag == (p.CMD_GET, p.KEY_GET_RANDOM):
            return [p.encode(*f.tag, RANDOM.to_bytes(4, "little"))]
        if f.tag == (p.CMD_SESSION, p.KEY_BOND):
            return [p.encode(*f.tag, f.content)]
        if f.tag == (p.CMD_SESSION, p.KEY_LOGIN):
            self.auth_key_seen = int.from_bytes(f.content, "little")
            self.logged_in = self.auth_key_seen == auth.auth_key(MAC, RANDOM)
            if not self.logged_in:
                bad = bytearray(p.encode(*f.tag))
                bad[1] |= p.FLAG_ERROR
                bad[4] = p.checksum(bad[6:])
                return [bytes(bad)]
            return [p.encode(*f.tag)]
        if f.tag == (p.CMD_GET, p.KEY_GET_POWER):
            return [p.encode(*f.tag, bytes([0, 0x77, 0xEE, 0x5F, 77]))]
        if f.tag == (p.CMD_GET, p.KEY_GET_VERSION):
            return [p.encode(*f.tag, b"V1.2.3\x00")]
        if f.tag == (p.CMD_GET, p.KEY_GET_ALARM):
            return [p.encode(*f.tag, self.alarms)]
        if f.tag == (p.CMD_SET, p.KEY_SET_ALARM):
            self.alarms = f.content
            return [p.encode(*f.tag)]
        if f.tag == (p.CMD_GET, p.KEY_GET_PANEL):
            return [p.encode(*f.tag, bytes([self.panel]))]
        if f.tag == (p.CMD_SET, p.KEY_SET_PANEL):
            self.panel = f.content[0]
            return [p.encode(*f.tag)]
        if f.tag == (p.CMD_HISTORY, p.KEY_HIST_STEPS):
            # an unsolicited notification arrives mid-sync, then two data frames
            day = bytearray(p.STEPS_RECORD_LEN)
            for hour in range(24):
                off = p.STEPS_BUCKETS_START + hour * 4
                day[off:off + 2] = p.u16le(100)
            return [p.encode(p.CMD_GET, p.KEY_GET_POWER, bytes([50])),
                    p.encode(*f.tag, bytes(p.STEPS_HEADER_LEN) + bytes(day)),
                    p.encode(*f.tag, bytes(day))]
        return [p.encode(*f.tag)]           # generic ack

    async def disconnect(self):
        return None


@pytest.fixture
def watch():
    w = Uwatch("fake-address", MAC)
    fake = FakeWatch()
    fake.on_notify = w._on_notify
    w._client = fake
    w._write_char = "write-char"
    w.fake = fake
    return w


# --- login ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_login_completes_handshake(watch):
    await watch.login()
    assert watch.fake.logged_in
    assert watch.fake.auth_key_seen == auth.auth_key(MAC, RANDOM)


@pytest.mark.asyncio
async def test_login_skips_bond_on_an_already_paired_watch(watch):
    await watch.login()
    tags = [(f[6], f[8]) for f in watch.fake.written]
    assert tags == [(p.CMD_GET, p.KEY_GET_RANDOM), (p.CMD_SESSION, p.KEY_LOGIN)]


@pytest.mark.asyncio
async def test_first_time_pairing_sends_bond(watch):
    await watch.login(pair=True)
    tags = [(f[6], f[8]) for f in watch.fake.written]
    assert tags == [(p.CMD_GET, p.KEY_GET_RANDOM), (p.CMD_SESSION, p.KEY_BOND),
                    (p.CMD_SESSION, p.KEY_LOGIN)]


@pytest.mark.asyncio
async def test_login_without_mac_is_rejected():
    w = Uwatch("fake-address", None)
    with pytest.raises(ConnectionError_, match="MAC"):
        await w.login()


@pytest.mark.asyncio
async def test_wrong_mac_raises_on_error_flag(watch):
    watch.mac = "00:11:22:33:44:55"
    with pytest.raises(ConnectionError_, match="rejected"):
        await watch.login()


@pytest.mark.asyncio
async def test_timeout_when_watch_ignores_us(watch):
    watch.fake.drop = {(p.CMD_GET, p.KEY_GET_RANDOM)}
    with pytest.raises(TimeoutError):
        await watch.request(p.get_random_number(), (p.CMD_GET, p.KEY_GET_RANDOM), timeout=0.2)


# --- features ---------------------------------------------------------------
@pytest.mark.asyncio
async def test_battery_and_version(watch):
    assert await watch.battery() == 77
    assert await watch.version() == "V1.2.3"


@pytest.mark.asyncio
async def test_set_time_is_acked(watch):
    await watch.set_time()
    assert (watch.fake.written[-1][6], watch.fake.written[-1][8]) == (p.CMD_SET, p.KEY_SET_TIME)


@pytest.mark.asyncio
async def test_alarm_write_then_read_back(watch):
    await watch.set_alarms([p.Alarm.at(7, 30, p.WEEKDAYS), p.Alarm.at(21, 0, p.EVERY_DAY)])
    alarms = await watch.get_alarms()
    assert [(a.hour, a.minute) for a in alarms] == [(7, 30), (21, 0)]
    assert alarms[0].days == p.WEEKDAYS


@pytest.mark.asyncio
async def test_panel_roundtrip(watch):
    await watch.set_panel(3)
    assert await watch.get_panel() == 3


@pytest.mark.asyncio
async def test_steps_collects_multiple_frames_and_ignores_unrelated(watch):
    days = await watch.steps()
    assert len(days) == 2
    assert all(d.steps == 2400 for d in days)


@pytest.mark.asyncio
async def test_steps_brackets_the_sync_with_interval_commands(watch):
    await watch.steps()
    intervals = [f[11:] for f in watch.fake.written if (f[6], f[8]) == (p.CMD_SET, p.KEY_CMD_INTERVAL)]
    assert intervals == [p.CMD_INTERVAL_SYNC, p.CMD_INTERVAL_IDLE]


@pytest.mark.asyncio
async def test_notifications_split_across_packets_are_reassembled(watch):
    watch.fake.chunk_replies = 7
    assert await watch.battery() == 77


@pytest.mark.asyncio
async def test_large_frames_are_chunked_to_the_mtu(watch):
    watch._client.mtu_size = 23
    await watch.notify("title", "b" * 90)
    assert all(len(w) <= 20 for w in watch.fake.written)


@pytest.mark.asyncio
async def test_malformed_notification_does_not_wedge_the_session(watch):
    watch._on_notify(None, bytearray(b"\xde\xad\xbe\xef"))
    assert await watch.battery() == 77


# --- mac recovery -----------------------------------------------------------
class Adv:
    def __init__(self, data):
        self.manufacturer_data = data


def test_mac_extracted_from_manufacturer_data():
    mac = _mac_from_advertisement(Adv({0x4C: bytes([0xA4, 0xC1, 0x38, 0x11, 0x22, 0x33])}))
    assert mac is not None and len(mac.split(":")) == 6


def test_no_mac_from_empty_or_uniform_advertisement():
    assert _mac_from_advertisement(Adv({})) is None
    assert _mac_from_advertisement(Adv({1: bytes(8)})) is None
