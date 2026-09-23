"""Command line interface for the UMIDIGI Uwatch 5S."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from . import client as bleclient, protocol as p

CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "uwatch5s.json"

DAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAY_BITS = dict(zip(DAY_NAMES, [p.MONDAY, p.TUESDAY, p.WEDNESDAY,
                                p.THURSDAY, p.FRIDAY, p.SATURDAY, p.SUNDAY]))
DAY_ALIASES = {"daily": p.EVERY_DAY, "everyday": p.EVERY_DAY, "all": p.EVERY_DAY,
               "weekdays": p.WEEKDAYS, "weekends": p.SATURDAY | p.SUNDAY,
               "once": 0x7F}


def load_config() -> dict:
    try:
        return json.loads(CONFIG.read_text())
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict) -> None:
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(cfg, indent=2) + "\n")


def parse_days(text: str) -> int:
    text = text.strip().lower()
    if text in DAY_ALIASES:
        return DAY_ALIASES[text]
    mask = 0
    for token in text.replace("+", ",").split(","):
        token = token.strip()[:3]
        if token not in DAY_BITS:
            raise SystemExit(f"unknown day '{token}'; use {'/'.join(DAY_NAMES)} or daily/weekdays/weekends")
        mask |= DAY_BITS[token]
    return mask


def format_days(mask: int) -> str:
    if mask == p.EVERY_DAY:
        return "every day"
    if mask == p.WEEKDAYS:
        return "weekdays"
    if mask == p.SATURDAY | p.SUNDAY:
        return "weekends"
    names = [n for n, bit in DAY_BITS.items() if mask & bit]
    return ",".join(names) if names else "once"


def parse_time(text: str) -> tuple[int, int]:
    try:
        hour, minute = text.split(":")
        return int(hour), int(minute)
    except ValueError:
        raise SystemExit(f"bad time '{text}', expected HH:MM")


def show_alarms(alarms) -> None:
    if not alarms:
        print("no alarms set")
        return
    print(f"{'slot':<5} {'time':<6} {'state':<9} days")
    for a in alarms:
        state = "on" if a.enabled else "off"
        print(f"{a.slot:<5} {a.hour:02d}:{a.minute:02d}  {state:<9} {format_days(a.days)}")


async def resolve_target(args):
    """Find the watch and remember it. CoreBluetooth insists on a fresh scan
    before it will connect, so this runs every time."""
    cfg = load_config()
    address = args.address or cfg.get("address")

    print("looking for the watch (wake it if nothing happens)...", file=sys.stderr)
    budget = args.connect_timeout
    device = await bleclient.find(address, timeout=budget * 0.6 if address else budget)
    if device is None and address:
        device = await bleclient.find(None, timeout=budget * 0.4)
    if device is None:
        raise SystemExit("no Uwatch found. Wake the watch, keep it close, and make sure "
                         "the OyeFit app is not connected to it.")

    mac = args.mac or device.mac or cfg.get("mac")
    cfg["address"] = device.address
    if mac:
        cfg["mac"] = mac
    save_config(cfg)
    return device.device, mac


def mac_candidates(mac: str | None) -> list[str]:
    """The watch advertises a MAC in its name, but it is not always the exact
    byte order the login cipher expects - try the plausible variants."""
    if not mac:
        return []
    raw = bytes(int(part, 16) for part in mac.split(":"))
    out = [mac, ":".join(f"{b:02X}" for b in raw[::-1])]
    for delta in (-1, 1):
        bumped = bytearray(raw)
        bumped[5] = (bumped[5] + delta) & 0xFF
        out.append(":".join(f"{b:02X}" for b in bumped))
    seen, unique = set(), []
    for item in out:
        if item.upper() not in seen:
            seen.add(item.upper())
            unique.append(item)
    return unique


async def probe(args, address, mac) -> int:
    """Work out what this watch actually needs: is a login required at all, and
    if so, which MAC spelling satisfies it."""
    print(f"watch reports mac {mac or 'unknown'}")
    print("\n1. trying to read without logging in")
    unauthenticated = []
    async with bleclient.Uwatch(address, mac) as watch:
        for label, builder, tag in [
            ("version", p.get_version, (p.CMD_GET, p.KEY_GET_VERSION)),
            ("battery", p.get_battery, (p.CMD_GET, p.KEY_GET_POWER)),
            ("alarms", p.get_alarms, (p.CMD_GET, p.KEY_GET_ALARM)),
        ]:
            try:
                reply = await watch.request(builder(), tag, timeout=3.0)
                print(f"   {label:<8} OK  {reply.content.hex()}")
                unauthenticated.append(label)
            except (TimeoutError, bleclient.ConnectionError_) as err:
                print(f"   {label:<8} no  ({err})")
    if len(unauthenticated) == 3:
        print("\nthis watch answers without a login - no authentication needed")
        return 0

    print("\n2. trying to log in with each plausible MAC")
    for candidate in mac_candidates(mac):
        try:
            found = await bleclient.find(None, timeout=args.connect_timeout)
            if found is None:
                print("   watch stopped advertising, wake it and retry")
                return 1
            async with bleclient.Uwatch(found.device, candidate) as watch:
                await watch.login()
                print(f"   {candidate}  ACCEPTED")
                cfg = load_config()
                cfg["mac"] = candidate
                save_config(cfg)
                print(f"\nsaved. run `uwatch info` now.")
                return 0
        except (TimeoutError, bleclient.ConnectionError_, OSError) as err:
            print(f"   {candidate}  rejected ({err})")
        await asyncio.sleep(2)
    print("\nnone worked - the watch is probably still bonded to the phone.")
    return 1


async def run(args) -> int:
    if args.command == "scan":
        found = await bleclient.scan(timeout=args.scan_timeout, all_devices=args.all)
        if not found:
            print("nothing found")
            return 1
        for d in found:
            mac = d.mac or "unknown (read it from the watch: Settings > About)"
            print(f"{d.name:<20} rssi={d.rssi:>4} dBm  address={d.address}  mac={mac}")
        return 0

    address, mac = await resolve_target(args)

    if args.command == "probe":
        return await probe(args, address, mac)
    if args.login and not mac:
        raise SystemExit(
            "logging in needs the watch's Bluetooth MAC address.\n"
            "macOS hides it, so read it on the watch (Settings > About / QR code screen)\n"
            "and pass it with:  uwatch --mac AA:BB:CC:DD:EE:FF --login " + args.command)

    async with bleclient.Uwatch(address, mac) as watch:
        # Uwatch 5S firmware answers unauthenticated; other LaiSi builds may not.
        if args.login or args.pair:
            await watch.login(pair=args.pair)
        print("connected", file=sys.stderr)

        if args.command == "info":
            print(f"battery   {await watch.battery()}%")
            print(f"firmware  {await watch.version()}")
            print(f"watchface {await watch.get_panel() + 1} of {p.BUILTIN_DIAL_COUNT}")

        elif args.command == "time":
            await watch.set_time()
            now = datetime.now().astimezone()
            print(f"clock set to {now:%Y-%m-%d %H:%M:%S %Z} (UTC{now:%z})")

        elif args.command == "alarms":
            show_alarms(await watch.get_alarms())

        elif args.command == "alarm-add":
            hour, minute = parse_time(args.time)
            alarms = await watch.get_alarms()
            if len(alarms) >= p.MAX_ALARMS:
                raise SystemExit(f"the watch only holds {p.MAX_ALARMS} alarms")
            alarms.append(p.Alarm.at(hour, minute, parse_days(args.days)))
            alarms.sort(key=lambda a: a.minutes)
            await watch.set_alarms(alarms)
            show_alarms(await watch.get_alarms())

        elif args.command == "alarm-rm":
            alarms = await watch.get_alarms()
            if not any(a.slot == args.slot for a in alarms):
                raise SystemExit(f"no alarm in slot {args.slot}")
            await watch.set_alarms([a for a in alarms if a.slot != args.slot])
            show_alarms(await watch.get_alarms())

        elif args.command == "alarm-clear":
            await watch.set_alarms([])
            print("all alarms cleared")

        elif args.command == "steps":
            days = await watch.steps()
            if not days:
                print("no step data returned")
                return 1
            for day in days[:args.days_back]:
                label = {0: "today", 1: "yesterday"}.get(day.index, f"{day.index} days ago")
                print(f"{label:<14} {day.steps:>7} steps")
                if args.hourly:
                    for hour, value in enumerate(day.hourly):
                        if value:
                            print(f"    {hour:02d}:00  {value:>6}")

        elif args.command == "face":
            if args.index is None:
                print(f"current watch face: {await watch.get_panel() + 1}")
            else:
                await watch.set_panel(args.index - 1)
                print(f"watch face set to {args.index}")

        elif args.command == "find":
            await watch.find()
            print("the watch should be buzzing now")

        elif args.command == "notify":
            await watch.notify(args.title, args.body)
            print("notification sent")

    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="uwatch", description="Control a UMIDIGI Uwatch 5S over BLE.")
    ap.add_argument("--address", help="BLE address/UUID to connect to (remembered)")
    ap.add_argument("--mac", help="the watch's Bluetooth MAC, needed for login (remembered)")
    ap.add_argument("--scan-timeout", type=float, default=6.0,
                    help="how long the scan command looks around")
    ap.add_argument("--connect-timeout", type=float, default=25.0,
                    help="how long to wait for the watch to advertise before connecting")
    ap.add_argument("--login", action="store_true",
                    help="authenticate before sending commands (not needed on Uwatch 5S)")
    ap.add_argument("--pair", action="store_true",
                    help="send the bond command (only for a watch that has never been paired)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="look for nearby watches")
    s.add_argument("--all", action="store_true", help="list every BLE device, not just watches")

    sub.add_parser("info", help="battery, firmware and current watch face")
    sub.add_parser("probe", help="diagnose what the watch needs to accept commands")
    sub.add_parser("time", help="sync the clock and timezone from this Mac")
    sub.add_parser("alarms", help="list the alarms stored on the watch")

    a = sub.add_parser("alarm-add", help="add an alarm")
    a.add_argument("time", help="HH:MM")
    a.add_argument("--days", default="daily",
                   help="daily | weekdays | weekends | mon,tue,... (default: daily)")

    a = sub.add_parser("alarm-rm", help="remove an alarm by slot number")
    a.add_argument("slot", type=int)

    sub.add_parser("alarm-clear", help="remove every alarm")

    s = sub.add_parser("steps", help="read the step history")
    s.add_argument("--days-back", type=int, default=7)
    s.add_argument("--hourly", action="store_true", help="show the hourly breakdown")

    f = sub.add_parser("face", help="get or set the watch face (1-4)")
    f.add_argument("index", nargs="?", type=int, choices=range(1, p.BUILTIN_DIAL_COUNT + 1))

    sub.add_parser("find", help="make the watch vibrate")

    n = sub.add_parser("notify", help="push a notification to the watch")
    n.add_argument("title")
    n.add_argument("body")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except (TimeoutError, bleclient.ConnectionError_, p.ProtocolError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
