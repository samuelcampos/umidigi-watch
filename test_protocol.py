"""Tests for the Uwatch 5S protocol codec.

Expected values are derived from the decompiled OyeFit code, not from this
implementation, so they pin the behaviour of the real watch.
"""
import struct
from datetime import datetime, timedelta, timezone

import pytest

from uwatch import auth, protocol as p


# --- auth -------------------------------------------------------------------
@pytest.mark.parametrize("mac,rnd,expected", auth.TEST_VECTORS)
def test_feal_matches_native_library(mac, rnd, expected):
    assert auth.auth_key(mac, rnd) == expected


def test_feal_is_deterministic_and_mac_sensitive():
    a = auth.auth_key("AA:BB:CC:DD:EE:FF", 0x1234)
    assert a == auth.auth_key("AA:BB:CC:DD:EE:FF", 0x1234)
    assert a != auth.auth_key("AA:BB:CC:DD:EE:FE", 0x1234)


# --- framing ----------------------------------------------------------------
def test_encode_layout_matches_bleinstruction():
    frame = p.encode(0x02, 0x26, bytes([1, 2, 3]), seq=7)
    assert frame[0] == 0xAA                     # magic
    assert frame[1] == 0x01                     # version 1, no flags
    assert (frame[2] << 8) | frame[3] == len(frame) - 6
    assert frame[4] == sum(frame[6:]) & 0xFF    # checksum over TL2
    assert frame[5] == 7                        # seq
    assert frame[6] == 0x02 and frame[7] == 0x00 and frame[8] == 0x26
    assert (frame[9] << 8) | frame[10] == 3     # content length, big-endian
    assert frame[11:] == bytes([1, 2, 3])
    assert len(frame) == 11 + 3


def test_encode_empty_content():
    frame = p.encode(0x04, 0x01)
    assert len(frame) == 11
    assert (frame[9] << 8) | frame[10] == 0


def test_roundtrip():
    payload = bytes(range(40))
    f = p.decode(p.encode(0x03, 0x05, payload, seq=9))
    assert (f.command, f.key, f.content, f.seq) == (0x03, 0x05, payload, 9)
    assert not f.error and not f.ack


def test_decode_flags():
    frame = bytearray(p.encode(0x01, 0x03, b"\x01"))
    frame[1] = 0x01 | p.FLAG_ERROR | p.FLAG_ACK
    f = p.decode(bytes(frame))
    assert f.error and f.ack and f.version == 1


@pytest.mark.parametrize("mutate,msg", [
    (lambda b: b"\x00" + b[1:], "magic"),
    (lambda b: b[:4], "short"),
    (lambda b: b + b"\x00", "length"),
])
def test_decode_rejects_corruption(mutate, msg):
    with pytest.raises(p.ProtocolError, match=msg):
        p.decode(mutate(p.encode(0x02, 0x09)))


def test_decode_rejects_bad_checksum():
    frame = bytearray(p.encode(0x02, 0x09, b"\x01\x02"))
    frame[4] ^= 0xFF
    with pytest.raises(p.ProtocolError, match="checksum"):
        p.decode(bytes(frame))


def test_reassembler_handles_split_and_merged_notifications():
    frames = [p.encode(0x04, 0x01), p.encode(0x03, 0x05, bytes(200)), p.encode(0x02, 0x09)]
    stream = b"".join(frames)
    r = p.Reassembler()
    got = []
    for i in range(0, len(stream), 20):          # arbitrary MTU-ish slicing
        got.extend(r.feed(stream[i:i + 20]))
    assert [(f.command, f.key) for f in got] == [(0x04, 0x01), (0x03, 0x05), (0x02, 0x09)]


# --- login ------------------------------------------------------------------
def test_device_login_sends_authkey_little_endian():
    f = p.decode(p.device_login(0x539EAACE))
    assert f.tag == (0x01, 0x03)
    assert f.content == bytes([0xCE, 0xAA, 0x9E, 0x53])


def test_bond_echoes_random_bytes():
    rnd = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    assert p.decode(p.bond(rnd)).content == rnd


def test_cmd_interval_values():
    assert p.decode(p.set_cmd_interval(True)).content == bytes([0x32, 0x24])
    assert p.decode(p.set_cmd_interval(False)).content == bytes([0xD6, 0xC8])


# --- time -------------------------------------------------------------------
def test_set_time_payload_layout():
    ts = 1_700_000_000
    payload = p.build_set_time_payload(ts, 60)          # UTC+1
    assert len(payload) == 6
    assert payload[0] == 1                              # offset hours
    assert struct.unpack("<I", payload[1:5])[0] == ts   # little-endian epoch
    assert payload[5] == 0                              # no sub-hour part


def test_set_time_half_hour_zone():
    # India UTC+5:30 -> hours=5, sub-hour = 30*100/60 = 50
    payload = p.build_set_time_payload(1_700_000_000, 330)
    assert payload[0] == 5 and payload[5] == 50


def test_set_time_negative_zone():
    payload = p.build_set_time_payload(1_700_000_000, -210)   # UTC-3:30
    assert struct.unpack("b", payload[0:1])[0] == -3
    assert payload[5] == 50


def test_set_time_clamps_extreme_zone_and_folds_into_timestamp():
    ts = 1_700_000_000
    payload = p.build_set_time_payload(ts, 13 * 60)     # UTC+13 -> clamp to +11
    assert payload[0] == 11
    assert struct.unpack("<I", payload[1:5])[0] == ts + 2 * 3600


def test_set_time_uses_dst_aware_offset():
    tz = timezone(timedelta(hours=2))
    when = datetime(2024, 7, 1, 12, 0, tzinfo=tz)
    f = p.decode(p.set_time(when))
    assert f.tag == (0x02, 0x26)
    assert f.content[0] == 2
    assert struct.unpack("<I", f.content[1:5])[0] == int(when.timestamp())


def test_set_time_rejects_naive_datetime():
    with pytest.raises(p.ProtocolError):
        p.set_time(datetime(2024, 1, 1, 0, 0))


# --- alarms -----------------------------------------------------------------
def test_alarm_payload_is_41_bytes_with_10_slots():
    payload = p.build_alarm_payload([p.Alarm.at(7, 30)])
    assert len(payload) == p.ALARM_PAYLOAD_LEN == 41
    assert payload[0] == 10


def test_alarm_record_encoding():
    payload = p.build_alarm_payload([p.Alarm.at(7, 30, days=p.WEEKDAYS)])
    assert p.read_u16le(payload, 1) == 7 * 60 + 30      # little-endian minutes
    assert payload[3] == 0b0011111                      # Mon..Fri
    assert payload[4] == 1                              # enabled


def test_alarm_unused_slots_are_zeroed():
    payload = p.build_alarm_payload([p.Alarm.at(6, 0)])
    assert payload[5:] == bytes(len(payload) - 5)


def test_alarm_day_mask_is_clamped_to_7_bits():
    payload = p.build_alarm_payload([p.Alarm(minutes=60, days=0xFF, enabled=True)])
    assert payload[3] == 0x7F


def test_alarm_roundtrip_through_parser():
    alarms = [p.Alarm.at(7, 30, p.WEEKDAYS), p.Alarm.at(9, 0, p.SATURDAY | p.SUNDAY, enabled=False)]
    parsed = p.parse_alarms(p.build_alarm_payload(alarms))
    assert len(parsed) == 2
    assert (parsed[0].hour, parsed[0].minute, parsed[0].enabled) == (7, 30, True)
    assert (parsed[1].hour, parsed[1].minute, parsed[1].enabled) == (9, 0, False)
    assert parsed[1].days == p.SATURDAY | p.SUNDAY
    assert [a.slot for a in parsed] == [0, 1]


def test_parse_alarms_skips_slots_with_no_day_mask():
    assert p.parse_alarms(bytes([10]) + bytes(40)) == []


def test_too_many_alarms_rejected():
    with pytest.raises(p.ProtocolError):
        p.build_alarm_payload([p.Alarm.at(1, 0)] * 11)


def test_alarm_at_validates_time():
    with pytest.raises(p.ProtocolError):
        p.Alarm.at(24, 0)


# --- steps ------------------------------------------------------------------
def _fake_steps_reply(days):
    """days: list of 24-element (steps, secondary) tuples."""
    out = bytearray(p.STEPS_HEADER_LEN)
    for buckets in days:
        rec = bytearray(p.STEPS_RECORD_LEN)
        for h, (s, o) in enumerate(buckets):
            off = p.STEPS_BUCKETS_START + h * 4
            rec[off:off + 2] = p.u16le(s)
            rec[off + 2:off + 4] = p.u16le(o)
        out += rec
    return bytes(out)


def test_get_steps_request_shape():
    f = p.decode(p.get_steps())
    assert f.tag == (0x03, 0x05)
    assert f.content == bytes(6)


def test_parse_steps_sums_24_hourly_buckets():
    today = [(100, 5)] * 24
    yesterday = [(50, 2)] * 24
    days = p.parse_steps(_fake_steps_reply([today, yesterday]))
    assert len(days) == 2
    assert days[0].index == 0 and days[0].steps == 2400 and days[0].secondary == 120
    assert days[1].index == 1 and days[1].steps == 1200
    assert len(days[0].hourly) == 24


def test_parse_steps_handles_empty_and_partial_payloads():
    assert p.parse_steps(bytes(p.STEPS_HEADER_LEN)) == []
    assert p.parse_steps(bytes(p.STEPS_HEADER_LEN + 40)) == []


def test_parse_steps_reads_buckets_little_endian():
    buckets = [(0, 0)] * 24
    buckets[3] = (0x0102, 0)
    day = p.parse_steps(_fake_steps_reply([buckets]))[0]
    assert day.hourly[3] == 0x0102 and day.steps == 0x0102


# --- watch face -------------------------------------------------------------
def test_set_panel_is_single_zero_based_byte():
    f = p.decode(p.set_panel(2))
    assert f.tag == (0x02, 0x0F)
    assert f.content == bytes([2])


@pytest.mark.parametrize("bad", [-1, 4, 99])
def test_set_panel_rejects_out_of_range(bad):
    with pytest.raises(p.ProtocolError):
        p.set_panel(bad)


def test_get_panel_tag():
    assert p.decode(p.get_panel()).tag == (0x04, 0x0A)


# --- notifications ----------------------------------------------------------
def test_notification_layout_and_terminator():
    f = p.decode(p.set_notification("Mum", "Dinner", p.MSG_SMS))
    c = f.content
    assert f.tag == (0x02, 0x19)
    assert c[0] == p.MSG_SMS
    assert c[1] == len(b"Dinner") + 1 + len(b"Mum") + 1
    assert c[2:8] == b"Dinner" and c[8] == 0
    assert c[9:12] == b"Mum"
    assert c[-2] == 0x00 and c[-1] == 0xA5


def test_notification_truncates_long_fields():
    c = p.decode(p.set_notification("T" * 200, "B" * 300)).content
    assert c.count(b"B"[0]) == 96 and c.count(b"T"[0]) == 60


# --- misc -------------------------------------------------------------------
def test_simple_commands_have_no_payload():
    for builder, tag in [(p.find_device, (0x02, 0x09)), (p.get_battery, (0x04, 0x01)),
                         (p.get_version, (0x04, 0x02)), (p.get_alarms, (0x04, 0x04)),
                         (p.get_random_number, (0x04, 0x0D)),
                         (p.get_function_table, (0x04, 0x19))]:
        f = p.decode(builder())
        assert f.tag == tag and f.content == b""


def test_chunking_respects_mtu():
    frame = p.encode(0x06, 0x01, bytes(600))
    chunks = list(p.chunk(frame))
    assert all(len(c) <= p.CHUNK_SIZE for c in chunks)
    assert b"".join(chunks) == frame
