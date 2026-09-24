# Uwatch 5S — local control from your Mac

A small offline tool that talks directly to a UMIDIGI Uwatch 5S over Bluetooth LE,
so you don't need the OyeFit app. Nothing leaves your machine — no account, no cloud.

* Set the clock and timezone
* List, add and remove alarms
* Read the step history
* Switch the watch face
* Make the watch buzz, push a notification

The protocol was recovered from UMIDIGI's own app; see [PROTOCOL.md](PROTOCOL.md).

## Install

```bash
./build_app.sh
ln -sf "$PWD/Uwatch.app/Contents/MacOS/uwatch-run" /usr/local/bin/uwatch
```

This builds `Uwatch.app`. The bundle is not cosmetic: macOS refuses Bluetooth to
any process whose app bundle lacks `NSBluetoothAlwaysUsageDescription`, and it
blames the *launching* app, so a plain `python script.py` is killed on the spot.
The launcher starts the bundle through LaunchServices and pipes the output back
to your terminal. The first run raises a "Uwatch would like to use Bluetooth"
prompt — allow it.

## First run

The watch must be advertising, so **close OyeFit on the phone** (or turn the
phone's Bluetooth off) — the watch only accepts one connection at a time, and it
only advertises while it is awake. If a command says it cannot find the watch,
tap the screen to wake it and run it again.

```bash
uwatch scan
uwatch info
```

No pairing, no login, no account: this firmware answers on a bare connection.
The watch is remembered in `~/.config/uwatch5s.json`.

If your watch turns out to need authentication, `uwatch probe` will tell you,
and `--login` enables the handshake (it needs the MAC, which is usually already
in the advertised name).

## Everyday use

```bash
uwatch info                              # battery, firmware, current watch face
uwatch time                              # sync clock + timezone from this Mac
uwatch alarms                            # list alarms
uwatch alarm-add 07:15 --days weekdays   # daily | weekends | mon,tue,wed...
uwatch alarm-rm 0                        # remove by slot number
uwatch alarm-clear
uwatch steps --days-back 3               # step history
uwatch steps --hourly                    # with the hourly breakdown
uwatch face                              # show the current watch face
uwatch face 2                            # switch to watch face 2 (1-4)
uwatch find                              # make the watch vibrate
uwatch notify "Mum" "Dinner is ready"
```

Add `-v` to any command to see the raw frames going back and forth.

## Notes and limits

* Alarm labels are not stored on the watch — the official app keeps them on the
  phone, so they are not shown here.
* Only the four built-in watch faces can be selected. Custom faces are uploaded
  as a proprietary image blob from UMIDIGI's servers and are not supported.
* Step records are returned newest-first; the per-day header holds a date field
  that has not been decoded, so days are labelled by position.
* If a command times out, the watch is probably connected to the phone.
* The watch stops advertising once something is connected to it, so the tool
  reuses the connection macOS already holds instead of scanning. The first run
  of the day may still need you to wake the watch.

## Development

```bash
python3.13 -m venv .venv && .venv/bin/pip install -e . pytest pytest-asyncio
.venv/bin/python -m pytest -q
```

67 tests cover the frame codec, the FEAL-32 login crypto (against vectors taken
from UMIDIGI's own native library), and the session logic driven by a fake watch.
No hardware needed — there is no Bluetooth in the test suite at all, so it runs
anywhere, including CI.

Every PR is checked by GitHub Actions: the suite runs on Linux against Python
3.10 and 3.13, `Uwatch.app` is built and verified on macOS, and a guard rejects
any commit containing a real watch address.

Every feature above was also confirmed on a real Uwatch 5S running firmware
`UWATCH5S_A0_V1.06_A00_0825_YM`: clock, alarms, step history and watch face.

## Legal

Interoperability work on hardware you own, derived from the freely distributed
OyeFit APK. No UMIDIGI code is redistributed here — the login cipher was
reimplemented from scratch.
