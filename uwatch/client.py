"""Async BLE client for the UMIDIGI Uwatch 5S (LaiSi 9000 protocol)."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from dataclasses import dataclass
from datetime import datetime

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from . import auth, protocol as p

log = logging.getLogger("uwatch")

NAME_HINTS = ("uwatch", "urun")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
NAME_MAC_RE = re.compile(r"[-_]([0-9A-Fa-f]{12})$")


class ConnectionError_(RuntimeError):
    pass


@dataclass
class Discovered:
    device: BLEDevice
    name: str
    rssi: int
    mac: str | None          # real BD_ADDR if we could recover it
    address: str             # what bleak needs to connect (UUID on macOS)


def _mac_from_name(name: str) -> str | None:
    """These watches advertise as e.g. 'Uwatch 5S-AABBCCDDEEFF' - that suffix is
    the BD_ADDR, which macOS otherwise refuses to tell us."""
    match = NAME_MAC_RE.search(name.strip())
    if not match:
        return None
    digits = match.group(1).upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _mac_from_advertisement(adv: AdvertisementData) -> str | None:
    """macOS hides the BD_ADDR, but many LaiSi watches put it in the
    manufacturer-specific advertising data. Look for a 6-byte run."""
    for payload in adv.manufacturer_data.values():
        for blob in (payload, payload[::-1]):
            for start in range(0, max(0, len(blob) - 5)):
                candidate = blob[start:start + 6]
                if len(candidate) == 6 and any(candidate) and len(set(candidate)) > 1:
                    return ":".join(f"{b:02X}" for b in candidate)
    return None


async def scan(timeout: float = 6.0, all_devices: bool = False) -> list[Discovered]:
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    out: list[Discovered] = []
    for address, (device, adv) in found.items():
        name = adv.local_name or device.name or ""
        if not all_devices and not any(h in name.lower() for h in NAME_HINTS):
            continue
        mac = (address if MAC_RE.match(address) else None) \
            or _mac_from_name(name) or _mac_from_advertisement(adv)
        out.append(Discovered(device, name or "(unnamed)", adv.rssi or -999, mac, address))
    out.sort(key=lambda d: -d.rssi)
    return out


async def find_connected(address: str | None = None) -> Discovered | None:
    """A watch that macOS is already connected to stops advertising, so no scan
    will ever see it. Ask CoreBluetooth for it directly instead.

    This reaches into bleak's backend, so any failure just falls back to scanning.
    """
    try:
        from CoreBluetooth import CBUUID
        from bleak.backends.corebluetooth.CentralManagerDelegate import (
            CentralManagerDelegate,
        )
    except ImportError:
        return None

    try:
        manager = CentralManagerDelegate()
        await manager.wait_until_ready()
        peripherals = manager.central_manager.retrieveConnectedPeripheralsWithServices_(
            [CBUUID.UUIDWithString_(p.SERVICE_UART)]
        )
    except Exception as err:                       # pragma: no cover - platform glue
        log.debug("could not query connected peripherals: %s", err)
        return None

    for peripheral in peripherals or []:
        identifier = str(peripheral.identifier().UUIDString())
        name = str(peripheral.name() or "")
        if address and identifier != address:
            continue
        if not address and not any(h in name.lower() for h in NAME_HINTS):
            continue
        device = BLEDevice(identifier, name or None, (peripheral, manager))
        log.debug("reusing already-connected peripheral %s", identifier)
        return Discovered(device, name or "(unnamed)", 0, _mac_from_name(name), identifier)
    return None


async def find(address: str | None = None, timeout: float = 20.0) -> Discovered | None:
    """CoreBluetooth can only connect to a peripheral it has just seen, and this
    watch only advertises in short bursts - so return the instant it shows up
    instead of waiting out the whole scan window."""
    already = await find_connected(address)
    if already is not None:
        return already

    seen: dict[str, AdvertisementData] = {}

    def matches(device: BLEDevice, adv: AdvertisementData) -> bool:
        name = adv.local_name or device.name or ""
        if not any(h in name.lower() for h in NAME_HINTS):
            return False
        if address and device.address != address:
            return False
        seen[device.address] = adv
        return True

    device = await BleakScanner.find_device_by_filter(matches, timeout=timeout)
    if device is None:
        return None
    adv = seen.get(device.address)
    name = (adv.local_name if adv else None) or device.name or ""
    mac = (device.address if MAC_RE.match(device.address) else None) or _mac_from_name(name) \
        or (_mac_from_advertisement(adv) if adv else None)
    rssi = (adv.rssi if adv else None) or -999
    return Discovered(device, name or "(unnamed)", rssi, mac, device.address)


class Uwatch:
    """Connected session. Use as an async context manager."""

    def __init__(self, address: str | BLEDevice, mac: str | None = None):
        self._address = address
        self.mac = mac
        self._client = BleakClient(address, timeout=20.0)
        self._rx = p.Reassembler()
        self._queue: asyncio.Queue[p.Frame] = asyncio.Queue()
        self._write_char = None
        self._write_response = False

    async def __aenter__(self) -> "Uwatch":
        await self._client.connect()
        svc = self._client.services.get_service(p.SERVICE_UART)
        if svc is None:
            raise ConnectionError_(
                "Nordic UART service not found - this does not look like a Uwatch 5S")
        self._write_char = svc.get_characteristic(p.CHAR_WRITE)
        if self._write_char is None:
            raise ConnectionError_("UART write characteristic missing")
        self._write_response = "write" in self._write_char.properties

        await self._client.start_notify(p.CHAR_NOTIFY, self._on_notify)
        with contextlib.suppress(Exception):          # bulk channel is optional
            await self._client.start_notify(p.CHAR_NOTIFY_BULK, self._on_notify)
        log.debug("connected, mtu=%s", self._client.mtu_size)
        return self

    async def __aexit__(self, *exc) -> None:
        with contextlib.suppress(Exception):
            await self._client.disconnect()

    def _on_notify(self, _char, data: bytearray) -> None:
        try:
            frames = self._rx.feed(bytes(data))
        except p.ProtocolError as err:
            log.warning("dropping malformed notification: %s", err)
            self._rx.reset()
            return
        for frame in frames:
            log.debug("<- %02X/%02X %s", frame.command, frame.key, frame.content.hex())
            self._queue.put_nowait(frame)

    async def send(self, frame: bytes) -> None:
        log.debug("-> %s", frame.hex())
        for part in p.chunk(frame, min(p.CHUNK_SIZE, max(20, self._client.mtu_size - 3))):
            await self._client.write_gatt_char(self._write_char, part,
                                               response=self._write_response)

    async def _next_reply(self, timeout: float, expect: tuple[int, int]) -> p.Frame:
        """Wait for one queued reply, always failing with the built-in TimeoutError.

        Before 3.11 asyncio.TimeoutError is its own class rather than an alias of
        the built-in, so letting wait_for's exception escape would slip straight
        past the `except TimeoutError` handlers in cli.py on those versions.
        """
        try:
            return await asyncio.wait_for(self._queue.get(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"no reply to {expect[0]:02X}/{expect[1]:02X}") from None

    async def request(self, frame: bytes, expect: tuple[int, int] | None = None,
                      timeout: float = p.COMMAND_TIMEOUT_S) -> p.Frame:
        """Send a frame and wait for the matching reply."""
        if expect is None:
            expect = (frame[6], frame[8])
        await self.send(frame)
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"no reply to {expect[0]:02X}/{expect[1]:02X}")
            reply = await self._next_reply(remaining, expect)
            if reply.tag == expect:
                if reply.error:
                    raise ConnectionError_(
                        f"watch rejected {expect[0]:02X}/{expect[1]:02X}")
                return reply
            log.debug("ignoring unsolicited %02X/%02X", reply.command, reply.key)

    async def collect(self, frame: bytes, expect: tuple[int, int],
                      quiet: float = 1.5, timeout: float = 30.0) -> list[p.Frame]:
        """Send a frame and gather every matching reply until the watch goes quiet.
        History payloads can arrive as several frames."""
        await self.send(frame)
        frames: list[p.Frame] = []
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            loop_now = asyncio.get_running_loop().time()
            window = min(quiet if frames else timeout, deadline - loop_now)
            if window <= 0:
                break
            try:
                reply = await asyncio.wait_for(self._queue.get(), window)
            except asyncio.TimeoutError:
                break
            if reply.tag == expect:
                frames.append(reply)
        if not frames:
            raise TimeoutError(f"no reply to {expect[0]:02X}/{expect[1]:02X}")
        return frames

    # --- session ---------------------------------------------------------
    async def login(self, mac: str | None = None, pair: bool = False) -> None:
        """Ask the watch for a challenge and answer it.

        `pair` additionally sends the bond command, which the official app only
        does the very first time a watch is added; an already-paired watch
        rejects it and drops the link.
        """
        mac = mac or self.mac
        if not mac:
            raise ConnectionError_(
                "the watch MAC address is required to log in (see --mac)")
        self.mac = mac
        rnd = await self.request(p.get_random_number(), (p.CMD_GET, p.KEY_GET_RANDOM))
        random_code = int.from_bytes(rnd.content[:4].ljust(4, b"\x00"), "little")
        log.debug("random=%08X", random_code)
        if pair:
            await self.request(p.bond(rnd.content), (p.CMD_SESSION, p.KEY_BOND))
        key = auth.auth_key(mac, random_code)
        log.debug("authKey=%08X", key)
        await self.request(p.device_login(key), (p.CMD_SESSION, p.KEY_LOGIN))

    # --- features --------------------------------------------------------
    async def battery(self) -> int:
        content = (await self.request(p.get_battery(), (p.CMD_GET, p.KEY_GET_POWER))).content
        return content[4] if len(content) > 4 else content[0]   # app reads byte 4

    async def version(self) -> str:
        content = (await self.request(p.get_version(), (p.CMD_GET, p.KEY_GET_VERSION))).content
        text = content.split(b"\x00")[0].decode("ascii", "replace").strip()
        return text or content.hex()

    async def set_time(self, when: datetime | None = None) -> None:
        await self.request(p.set_time(when), (p.CMD_SET, p.KEY_SET_TIME))

    async def get_alarms(self) -> list[p.Alarm]:
        reply = await self.request(p.get_alarms(), (p.CMD_GET, p.KEY_GET_ALARM))
        return p.parse_alarms(reply.content)

    async def set_alarms(self, alarms) -> None:
        await self.request(p.set_alarms(alarms), (p.CMD_SET, p.KEY_SET_ALARM))

    async def steps(self) -> list[p.DaySteps]:
        await self.request(p.set_cmd_interval(True), (p.CMD_SET, p.KEY_CMD_INTERVAL))
        try:
            frames = await self.collect(p.get_steps(), (p.CMD_HISTORY, p.KEY_HIST_STEPS))
        finally:
            with contextlib.suppress(Exception):
                await self.request(p.set_cmd_interval(False),
                                   (p.CMD_SET, p.KEY_CMD_INTERVAL))
        return p.parse_steps(b"".join(f.content for f in frames))

    async def get_panel(self) -> int:
        return (await self.request(p.get_panel(), (p.CMD_GET, p.KEY_GET_PANEL))).content[0]

    async def set_panel(self, index: int) -> None:
        await self.request(p.set_panel(index), (p.CMD_SET, p.KEY_SET_PANEL))

    async def find(self) -> None:
        await self.request(p.find_device(), (p.CMD_SET, p.KEY_FIND_DEVICE))

    async def notify(self, title: str, body: str, msg_type: int = p.MSG_OTHER) -> None:
        await self.request(p.set_notification(title, body, msg_type),
                           (p.CMD_SET, p.KEY_SET_NOTIFY))
