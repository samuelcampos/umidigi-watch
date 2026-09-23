# Agent notes

Orientation for an AI agent picking this project up cold. `README.md` is for the
human user, `PROTOCOL.md` is the protocol spec — **this file is the stuff that
will waste your afternoon if you don't know it.**

Read `PROTOCOL.md` §0 ("Confirmed against real hardware") before changing
anything in `uwatch/protocol.py`.

## What this is

A local macOS CLI that configures a UMIDIGI Uwatch 5S over BLE, replacing the
vendor's OyeFit Android app. The protocol was recovered by decompiling that app.
The hardware belongs to the user's kid and is a real, in-use device.

The four features the user actually asked for — all built, all verified live:
set time/timezone, get/set alarms, read step stats, set watch face.

## Layout

```
uwatch/protocol.py   frame codec + command table (pure, no I/O, heavily tested)
uwatch/auth.py       FEAL-32 login cipher + 10 ground-truth vectors
uwatch/client.py     BLE session; all macOS-specific discovery lives here
uwatch/cli.py        argparse front end, one function per subcommand
test_protocol.py     50 tests, codec + crypto
test_client.py       17 tests, session logic against a FakeWatch
build_app.sh         builds Uwatch.app — encodes the whole macOS TCC workaround
bundle_main.py       entry point that runs *inside* the bundle
uwatch_run.sh        LaunchServices bridge, streams bundle output to the terminal
research/            reverse-engineering material (bulk is gitignored)
```

## Commands you will need

```sh
python3.13 -m venv .venv && .venv/bin/pip install -e . pytest pytest-asyncio
.venv/bin/python -m pytest -q          # 67 tests, no hardware needed
./build_app.sh                         # rebuild the bundle after ANY code change
./Uwatch.app/Contents/MacOS/uwatch-run info -v
```

`build_app.sh` recreates the bundle's venv from scratch, so **pytest is wiped
from the bundle every build**. Always run tests from the separate `.venv/`.

`Uwatch.app/` is gitignored and its internal paths are absolute — it must be
rebuilt after a clone or a move.

## Trap 1: macOS will not let you touch Bluetooth

This cost the bulk of the original session. Three independent barriers, **all**
of which must be cleared. Symptom of any of them: `Abort trap: 6` with
**completely empty stderr**. The real reason only appears in
`~/Library/Logs/DiagnosticReports/*.ips` — check `TCC`, `procPath` and
`responsibleProc` there before theorising.

1. **The process's own bundle** needs `NSBluetoothAlwaysUsageDescription`.
   A plain `python foo.py` has no bundle, so it is killed instantly.
2. **Framework Python re-execs.** Homebrew's `bin/python3.13` is a ~52 KB stub
   that execs `Python.framework/.../Resources/Python.app/Contents/MacOS/Python`,
   which carries *its own* Info.plist and discards yours. Fix: copy that final
   binary into `Uwatch.app/Contents/MacOS/python3.13`. Safe because `otool -L`
   shows it links the framework by absolute path.
3. **TCC blames the responsible process**, not the running one. Launched from a
   terminal or from the Copilot app, `responsibleProc` is *that* app and the
   grant never applies. Fix: launch via
   `open -n -a Uwatch.app --args <script> <outfile> <args...>`, which makes the
   app responsible for itself. Args pass through verbatim to the interpreter.

Bundle layout trick: `python3 -m venv --copies Uwatch.app/Contents`, then
`mv Contents/bin Contents/MacOS` (Python finds `pyvenv.cfg` one level above the
executable). `--copies` matters: a symlinked interpreter reintroduces trap 2.
`pip` recreates `Contents/bin`; the build script deletes it. Then
`codesign --force --deep --sign -`, which fails if the main executable is a
symlink.

**Do not try to "simplify" any of this.** Every step is load-bearing and was
arrived at by elimination.

## Trap 2: the watch's actual behaviour

* **No authentication is needed.** Firmware `UWATCH5S_A0_V1.06_A00_0825_YM`
  answers `0x04/*` reads and `0x02/*` writes on a bare connection.
  `bond` (`0x01/0x01`) is **first-pairing only** — sending it to an
  already-bonded watch makes it error and **drop the link**. `deviceLogin`
  (`0x01/0x03`) with a freshly-read random number is *also* rejected, because
  the real app reuses the `randomCode` it stored at binding time rather than
  re-reading it. Login is therefore opt-in behind `--login` / `--pair`, kept
  only for a factory-reset pairing path. The FEAL-32 implementation itself is
  correct — verified byte-exact against `libauth.so`. Don't "fix" it.
* **A connected watch stops advertising.** macOS holds the link open between
  runs, so every subsequent scan finds nothing and it looks like the watch
  died. `client.find_connected()` retrieves the peripheral macOS already holds
  via `retrieveConnectedPeripheralsWithServices_`, and is tried *before*
  scanning. This uses bleak-private API (`CentralManagerDelegate`), so it is
  wrapped in try/except with a scan fallback — if a bleak upgrade breaks it,
  that fallback is where to look. `BLEDevice.details` must be the tuple
  `(CBPeripheral, CentralManagerDelegate)`.
* **It only advertises in short bursts while awake.** Use
  `BleakScanner.find_device_by_filter` (returns on first sight), never
  `discover(timeout=...)`, which waits out the whole window and usually misses.
* **macOS hides the BD_ADDR**, but the advertised name embeds it:
  `Uwatch 5S-AABBCCDDEEFF` → `AA:BB:CC:DD:EE:FF`. That is how `--mac` is
  obtained. `_mac_from_advertisement()` is an untested heuristic fallback; the
  name path has always won.
* **One connection at a time.** If commands time out, the phone is connected.
  Tell the user to close OyeFit or disable the phone's Bluetooth.
* `uwatch probe` is the diagnostic that revealed all of the above. Reach for it
  before guessing.

## Trap 3: the launcher plumbing

* **Bash strings cannot contain NUL.** A `$'\x00…'` sentinel silently evaluates
  to empty and breaks the `sed` that drives output streaming. The marker is the
  literal string `__UWATCH_EXIT__` for this reason — leave it alone.
* The tail loop **must flush remaining bytes after spotting the exit marker**,
  or the final line of output is silently swallowed.
* `bundle_main.py` must explicitly print `SystemExit`'s string payload,
  otherwise user-facing error messages vanish into the void.
* `resolve_target()` calls `find()` twice (by address, then fallback), so the
  budget is split 60/40 to respect `--connect-timeout` overall.

## Testing against real hardware

The device is a child's watch in daily use. Be considerate:

* Ask the user to wake the watch; it must be within a couple of metres.
* **Record the original state first** (`uwatch info` and `uwatch alarms`) and
  **restore it when finished**. Last known good state: watch face 2, no alarms.
* Prefer the offline tests. `FakeWatch` in `test_client.py` covers the session
  logic; hardware is only needed to confirm genuinely new commands.
* `FakeWatch` must keep a **persistent `Reassembler` across writes** — building
  a fresh one per write breaks the MTU-chunking tests.

## Protocol corrections already applied

These were wrong in early drafts and are right now — don't regress them:

* Battery is `content[4]`, not `content[0]` (`WatchHomeActivity.java:286`).
* The firmware version reply is plain ASCII with **no NUL terminator**.
* `ExtensionKt.toLong()` reverses bytes like `toInt()` — everything is
  little-endian (`ExtensionKt.java:133`).
* Alarms: 10 slots × 4 bytes, confirmed live.
* Steps: `copyOfRange(content, 12, len)`, split into 116-byte per-day records,
  each holding 24 × 4-byte hourly buckets, little-endian u16
  (`WatchHomeActivity.java:342`).

## Known unknowns

Nothing here is blocking; the user's original request is complete.

* The 16-byte per-day steps record header is undecoded, so days are labelled by
  position (index 0 = today) rather than by real date. Decoding it is the single
  most useful remaining improvement.
* The second u16 in each hourly bucket is unidentified — calories or distance.
* `notify` has never been tested on hardware.
* Whether `getRandomNumber` returns a stored or a fresh value is unknown; login
  was abandoned once it proved unnecessary.
* Custom watch faces are a proprietary image blob fetched from UMIDIGI servers
  and are not supported. Only the four built-in faces can be selected.
* An Android/Kotlin port was floated but not started. The protocol work
  transfers directly and none of the macOS traps above would apply.

## Scope and conduct

This is interoperability work on hardware the user owns, derived from a freely
distributed APK. No vendor code is redistributed — the cipher was reimplemented
from scratch. Keep it that way: do not commit the APK, DEX, native libraries or
decompiled sources (`.gitignore` already blocks `research/oyefit/`).
