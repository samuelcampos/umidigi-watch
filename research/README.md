# Reverse-engineering material

Everything in `PROTOCOL.md` was derived from the official UMIDIGI companion
app, **OyeFit** (`com.hyst.oyefit`), which is freely distributed. The bulk of
that working material is **not committed** — it is ~300 MB of APK, DEX, native
libraries and decompiled Java.

## What is tracked here

| File | Purpose |
|---|---|
| `feal.py` | Standalone pure-Python implementation of the FEAL-32 cipher used by the watch's login handshake, reconstructed from the decompiled sources. |
| `emu_auth.py` | Harness that emulates the ARM64 `libauth.so` with [Unicorn](https://www.unicorn-engine.org/) and compares its output against `feal.py`. Used to prove the reimplementation is byte-exact (3,010 matching vectors). |

The production copy of the cipher lives in `../uwatch/auth.py`, together with
ten ground-truth vectors captured from the emulator.

## What is ignored

- `oyefit/` — the working directory:
  - `oyefit.xapk`, `xapk/` — the app package as downloaded
  - `dex/` — extracted DEX files
  - `libs/` — native `.so` libraries, including `libauth.so`
  - `jadx-out/` — ~12,900 decompiled Java sources
- `web/` — saved vendor/support pages gathered while identifying the device.

## Recreating `oyefit/`

```sh
mkdir -p research/oyefit && cd research/oyefit
# 1. obtain com.hyst.oyefit as an .xapk / .apk from any APK mirror
unzip -o oyefit.xapk -d xapk
unzip -o xapk/com.hyst.oyefit.apk -d dex     # classes*.dex
unzip -o xapk/*.apk 'lib/arm64-v8a/*' -d libs
jadx -d jadx-out xapk/com.hyst.oyefit.apk    # brew install jadx
```

## Key source files

Referenced throughout `PROTOCOL.md`, relative to `oyefit/jadx-out/sources/`:

| Path | Why it matters |
|---|---|
| `com/hyst/oyefit/view/devices/WatchHomeActivity.java` | Battery is `content[4]` (line 286); steps records split at offset 12 into 116-byte chunks (line 342). |
| `com/lstech/auth/Authorization.java` | MAC string → 6 key bytes, parsed in order. |
| `com/hyst/oyefit/utils/ExtensionKt.java` | `toInt()` / `toLong()` both reverse bytes — the protocol is little-endian (line 133). |
