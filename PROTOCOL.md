# UMIDIGI Uwatch 5S — BLE Protocol (reverse-engineered)

Source: **OyeFit v1.2.0 (20231206.1)**, package `com.hyst.oyefit`, versionCode 65
(APKPure XAPK, 32 MB). Decompiled with `jadx`; native crypto recovered from
`libdevice_auth.so` (arm64-v8a) by disassembly **and verified by emulation**.

Everything below is taken from the app's own code, not guessed.

---

## 0. Confirmed against real hardware

Verified on a physical Uwatch 5S, firmware `UWATCH5S_A0_V1.06_A00_0825_YM`,
from macOS via CoreBluetooth:

| Observation | Result |
|---|---|
| Advertised name | `Uwatch 5S-AABBCCDDEEFF` — **the suffix is the BD_ADDR** |
| Nordic UART service + both notify characteristics | present, MTU 247 granted |
| Frame format of §3 | accepted; replies decode with a valid checksum |
| `getVersion` `0x04/0x02` | `UWATCH5S_A0_V1.06_A00_0825_YM` (plain ASCII, no NUL) |
| `getPower` `0x04/0x01` | `00 77 EE 5F 61` — battery % is **byte 4** (0x61 = 97 %) |
| `getAlarm` `0x04/0x04` | `0A` + 40 zero bytes — exactly the 10 × 4 layout of §6.2 |
| `setTime` `0x02/0x26` | accepted; watch clock updated |
| `setAlarm` / `getAlarm` | written and read back, survives reconnects |
| `getHisStepsData` `0x03/0x05` | real history decoded; hourly buckets line up with a normal day |
| `setPanel` / `getPanel` | watch face switched and confirmed |
| **Login** | **not required** — see below |

### Authentication is optional on this firmware

The watch answers `0x04/*` reads and `0x02/*` writes on a bare connection, with
no `deviceLogin` beforehand. Two further findings:

* `bond` (`0x01/0x01`) is **first-pairing only**. Sending it to a watch that is
  already bonded to a phone returns the error flag and the watch drops the link.
  The app only calls it from `DeviceBindingActivity`; every reconnect path
  (`MainActivity`, `DeviceReconnectActivity`, `WatchHomeActivity`) goes straight
  to `deviceLogin`.
* `deviceLogin` (`0x01/0x03`) with a key derived from the freshly issued random
  number was **rejected**. The app never re-reads the random number on reconnect
  — it reuses the `randomCode` stored at binding time — so the value returned by
  `getRandomNumber` is not what an already-bonded watch validates against.

Practical consequence: skip the handshake entirely. The FEAL-32 implementation
in §4.1 is still correct (it matches the native library on 3,010 vectors) and is
needed if you ever bind a factory-reset watch yourself.

### Advertising behaviour

The watch advertises only in short bursts while it is awake, and stops as soon
as the screen sleeps or something connects to it. A scanner must therefore run
continuously and connect on first sight rather than collecting for a fixed
window. On macOS this matters twice over, because CoreBluetooth will only
connect to a peripheral it has seen during the current process's scan.

The bigger trap: **once the host is connected, the watch stops advertising**, so
after the first session every later scan finds nothing even though the watch is
sitting right there. macOS keeps the link open between runs. The fix is to ask
CoreBluetooth for the peripheral instead of scanning for it:

```python
manager.central_manager.retrieveConnectedPeripheralsWithServices_(
    [CBUUID.UUIDWithString_("6e400001-b5a3-f393-e0a9-e50e24dcca9e")])
```

Doing this first makes reconnection instant and removes the need to keep poking
the watch awake. The equivalent on Android/Linux is to reuse the existing GATT
connection rather than re-scanning.

---

## 1. Which protocol does the Uwatch 5S speak?

OyeFit bundles **two** unrelated watch stacks. `com.hyst.hyble.Producter` picks
between them purely from the advertised BLE name:

```java
public static boolean isLaisiProtocol(String name) {
    return name != null && (name.toLowerCase().contains("uwatch")
                         || name.toLowerCase().contains("urun"));
}
public static boolean isIdoProtocol(String name) {   // NOT us
    return name.startsWith("ID") || name.startsWith("UFit Pro") || name.endsWith("_OTA");
}
```

| Family | Constant | Transport | Used by |
|---|---|---|---|
| **LaiSi** | `DEVICE_PROTOCOL_LAISI = 9000` | Nordic UART | **Uwatch\*, Urun\*** ← **the Uwatch 5S** |
| IDO | `DEVICE_PROTOCOL_IDO = 9001` | `0x0AF6`/`0x0AF7` + `libVeryFitMulti.so` | ID*, UFit Pro |

Anything advertising a name containing `Uwatch` uses the **LaiSi** protocol.
Implementation lives in `com/hyst/ble/LaiSiCmd.java` + `BleInstruction.java`.

The vendor is **"lstech" (LaiSi Tech)** — see the JNI package `com.lstech.auth`.
The silicon is **Realtek RTL8762x**: the APK embeds the Realsil DFU SDK
(`com.realsil.sdk.dfu`) with service `0xFFD0` / `0000d0ff-3c17-d293-8e48-14fe2e4da212`.
Those are **OTA-only** and are not used for normal operation.

---

## 2. GATT layer

```
Service  6e400001-b5a3-f393-e0a9-e50e24dcca9e   (Nordic UART Service)
  Write  6e400002-b5a3-f393-e0a9-e50e24dcca9e   (write, app -> watch)
  Notify 6e400003-b5a3-f393-e0a9-e50e24dcca9e   (notify, watch -> app)   [main]
Notify2  6dda1206-bf42-4a68-bdb4-d045eb14a4cc   (notify, bulk/file channel)
CCCD     00002902-0000-1000-8000-00805f9b34fb
```

Connection setup used by the app (`MyBleManager`, built on the
**Nordic Android BLE Library** `no.nordicsemi.android.ble`):

| Parameter | Value |
|---|---|
| MTU request | **247** (`DsBluetoothConnector.setMTU(247)`) |
| Chunk size | **240** bytes if MTU > 23, else 20 |
| Command timeout | **5000 ms** (`commandTimeoutMill = 5000L`) |
| Scan filter | device **name contains `Uwatch`** (no service-UUID filter) |

Enable notifications on **both** `6e400003` and `6dda1206`. Normal
command replies arrive on `6e400003`; bulk history/file data on `6dda1206`.

### Throttling
`setCmdInterval` (`0x02/0x13`) tells the watch how fast the app will talk:

* before a bulk sync: payload `{0x32, 0x24}` (50, 36)
* normal operation:   payload `{0xD6, 0xC8}` (214, 200)

---

## 3. Frame format

Two nested TLV layers. **Outer header is big-endian; payload integers are
little-endian.** (`ExtensionKt.toInt()` hex-parses the byte array *reversed*.)

```
         +--------- TL1 header (6 bytes) ---------+------------ TL2 payload -----------+
offset   0      1        2   3        4         5 | 6        7      8      9  10   11..
        +------+--------+--------+-----------+----+---------+------+------+-------+----+
        | 0xAA | flags  | length | checksum  | seq| command | rsvd | key  | clen  |data|
        +------+--------+--------+-----------+----+---------+------+------+-------+----+
          magic  ver/err  BE u16     u8       u8     u8      0x00    u8    BE u16
```

| Field | Notes |
|---|---|
| `0xAA` | `MAGIC_NUMBER` |
| `flags` | bit7 `0x80` = **error**, bit6 `0x40` = **ack**, bits0–5 = version. App always sends `0x01`. |
| `length` | big-endian u16 = `len(frame) - 6` = `clen + 5` |
| `checksum` | `sum(frame[6:]) & 0xFF` — sum of the **whole TL2 payload** |
| `seq` | sequence id |
| `command` | 0x01–0x08, see §5 |
| `rsvd` | always `0x00` on transmit; **ignored** by the decoder |
| `key` | sub-command |
| `clen` | big-endian u16 = content length |

Total frame length = `11 + clen`.

Encoder (`BleInstruction.encode`) and decoder (`BleInstruction.decode`) verbatim:

```java
// encode
byte[] p = new byte[len + 5];
p[0]=command; p[1]=0; p[2]=key; p[3]=(byte)((len>>8)&255); p[4]=(byte)(len&255);
System.arraycopy(rawContent, 0, p, 5, len);
byte[] out = new byte[len + 11];
System.arraycopy(new byte[]{ -86, 1, (byte)((p.length>>8)&255), (byte)(p.length&255),
                             getCheckSum(p,0), sequenceId }, 0, out, 0, 6);
System.arraycopy(p, 0, out, 6, p.length);

// getCheckSum: (sum of bytes from offset) & 0xFF
```

Decoder error codes: `1` bad magic, `2` too short (<6), `3` length mismatch,
`4` checksum mismatch.

> **Bug worth copying-around:** `LaiSiCmd.getSequenceId()` computes
> `sequenceId + 1` but **never stores it**, so the shipping app transmits
> `seq = 1` on *every* frame. The watch clearly does not validate it.

---

## 4. Pairing / login handshake

The watch will reject most commands until you log in.

```
  app                                         watch
   |-- 0x04/0x0D  getRandomNumber  ----------->|
   |<-- 0x04/0x0D  content = random bytes -----|   randomCode = LE-int(content)
   |-- 0x01/0x01  bond(content)   ------------>|   echo the random bytes back
   |<-- 0x01/0x01 ok --------------------------|
   |-- 0x01/0x03  deviceLogin(authKey_LE32) -->|
   |<-- 0x01/0x03 ok --------------------------|
```

`authKey` comes from the bundled native library:

```java
// com.lstech.auth.Authorization
int authKey = Authorization.getAuthKey(context, mac /*"AA:BB:.."*/, randomCode);
LaiSiCmd.deviceLogin(ble, new byte[]{ (byte)authKey, (byte)(authKey>>8),
                                      (byte)(authKey>>16), (byte)(authKey>>24) });
```

### 4.1 `libdevice_auth.so` → it is **FEAL-32**

Exports: `FealCipher`, `Mn_FealExkey`, `Mn_FealF`, `Mn_FealFK`, `Mn_FealS0`, `Mn_FealS1`.

The JNI entry point ignores `context` entirely — the "wrong APK" package-name
check is **pure Java** and trivially bypassed. It computes:

```
authKey = FealCipher(mac6, randomCode & 0xFFFFFFFF)
```

(when an optional serial string is supplied, `mac6[i % 6] ^= serial[i]` first;
OyeFit always passes `null`, so plain MAC bytes are used.)

`FealCipher(mac6, value)`:

1. **Key**: 8 bytes = `0x00 || mac[0..5] || 0x00`
2. **Key schedule** = standard FEAL `fK` iterated **20×** → 80 bytes = 40 × 16-bit subkeys (FEAL-N, N=32)
3. **Plaintext** (64-bit) = `value` bytes followed by the *same bytes reversed*
   → `L = value`, `R = byteswap32(value)`
4. `L ^= SK[64:68]`; `R ^= SK[68:72]`; `R ^= L`
5. **32 Feistel rounds**: `L, R = R, L ^ f(R, SK[2i:2i+2])`
6. **Return** `R ^ SK[72:76]` (32-bit)

S-boxes are textbook FEAL:
`S0(a,b) = rot2((a+b) & 0xFF)`, `S1(a,b) = rot2((a+b+1) & 0xFF)`, `rot2(x) = ((x<<2)|(x>>6)) & 0xFF`.

A pure-Python reimplementation is in `uwatch/auth.py`. It was diffed against the
real ARM64 library under Unicorn emulation across **3 010 random vectors — all match**,
so you never need to ship the `.so`.

Test vectors:

| MAC | randomCode | authKey |
|---|---|---|
| `AA:BB:CC:DD:EE:FF` | `0x12345678` | `0x539EAACE` |
| `AA:BB:CC:DD:EE:FF` | `0x00000000` | `0xE80B1E62` |
| `00:00:00:00:00:00` | `0x00000000` | `0x2E37C687` |
| `01:02:03:04:05:06` | `0xDEADBEEF` | `0x039D0D27` |
| `12:34:56:78:9A:BC` | `0x11223344` | `0xB3BF2DD3` |

---

## 5. Command table

`CMD` = byte 6, `KEY` = byte 8. Replies reuse the same `CMD`/`KEY`.
Labels are the app's own (Chinese) debug strings, translated.

### CMD 0x01 — session
| KEY | Method | Payload |
|---|---|---|
| 0x01 | `bond` | echo of the random bytes |
| 0x02 | `unBond` | — |
| 0x03 | `deviceLogin` | `authKey` as LE u32 |

### CMD 0x02 — settings (write)
| KEY | Method | Payload |
|---|---|---|
| 0x02 | `setAlarm` | see §6.2 (41 bytes) |
| 0x03 | `setSedentary` | sedentary reminder |
| 0x04 | `setUserInfo` | height/weight/age/sex |
| 0x05 | `setStepGoal` | step goal |
| 0x07 | `setWear` | wrist: 0 close, 1 auto, 2 left, 3 right |
| 0x09 | `findDevice` | *(none)* — makes the watch buzz |
| 0x0A | `dataDelete` | delete already-synced data |
| 0x0B | `setIntoDFU` | *(none)* — enter Realtek OTA |
| 0x0C | `setRaise` | raise-to-wake |
| 0x0E | `setHeartRateWarning` | HR monitoring + alarm thresholds |
| 0x0F | `setPanel` | **1 byte = builtin dial index (0-based)** — §6.4 |
| 0x13 | `setCmdInterval` | `{0x32,0x24}` sync / `{0xD6,0xC8}` idle |
| 0x17 | `setMedicine` | medication reminder |
| 0x18 | `setWater` | drink reminder |
| 0x19 | `setNotify` | app notification push — §6.5 |
| 0x1A | `setLanguage` | language string, UTF-8 |
| 0x1B | `setWeather` | weather |
| 0x1C | `setPhone` | incoming-call notification |
| 0x1E | `setBloodPressure` | BP calibration |
| 0x1F | `setDisturb` | do-not-disturb |
| 0x20 | `setPhysiological` | menstrual cycle |
| 0x21 | `setBleStatus` | disconnect alert |
| 0x25 | `setUnit` | `0` = miles, `1` = km |
| **0x26** | **`setTime`** | **6 bytes — §6.1** |
| 0x27 | `setSleepBOOpen` | sleep SpO2 toggle |

### CMD 0x03 — health history (read, bulk)
| KEY | Method | Request payload |
|---|---|---|
| 0x01 | `getExerciseData` | caller-supplied |
| 0x02 | `getHeartRateData` | caller-supplied |
| 0x03 | `getSleepData` | `00 00 00 00 00 00` |
| **0x05** | **`getHisStepsData`** | `00 00 00 00 00 00` — §6.3 |
| 0x06 | `getBloodOxygenData` | `00 00 00 00 00 00` |
| 0x07 | `getBloodPressureData` | `00 00 00 00 00 00` |

### CMD 0x04 — settings (read) — all take **no payload**
| KEY | Method | | KEY | Method |
|---|---|---|---|---|
| 0x01 | `getPower` (battery) | | 0x15 | `getBloodPressure` |
| 0x02 | `getVersion` | | 0x16 | `getDisturb` |
| **0x04** | **`getAlarm`** | | 0x17 | `getPhysiological` |
| 0x07 | `getHeartRateWarning` | | 0x18 | `getBleStatus` |
| 0x08 | `getSedentary` | | 0x19 | `getFunctionTable` |
| 0x09 | `getRaise` | | 0x1A | `getDeviceId` |
| **0x0A** | **`getPanel`** | | 0x1C | `getSleepBOOpen` |
| 0x0B | `getWear` | | 0x12 | `getMedicine` |
| **0x0D** | **`getRandomNumber`** | | 0x13 | `getWater` |

### CMD 0x05 / 0x06 / 0x08 — file transfer
| CMD/KEY | Method |
|---|---|
| 0x05/0x01–0x03 | u-blox GPS assistance file (`startUbloxFileTra`, `goOn…`, `getUbloxFileInfo`) |
| 0x06/0x01–0x04 | resource file (`startResourceFileTra`, `goOn…`, `getResourceFileInfo`, `getResourceFileVersion`) |
| 0x08/0x01 | `setDial` — begin custom watch-face upload |
| 0x08/0x02 | `getDialInfo` |
| 0x08/0x03 | `goOnDialTransmission` |

Bulk transfers stream 240-byte chunks on the write characteristic; a chunk
shorter than 240 marks the end of a burst.

---

## 6. Payload formats for the features you asked for

### 6.1 Set time — `0x02 / 0x26` (6 bytes)

```java
long  now    = System.currentTimeMillis() / 1000;              // UTC epoch seconds
int   offset = tz.getOffset(millis) / 1000 / 60;               // total offset in MINUTES
int   hours  = offset / 60;                                    // clamped to [-11, +11]
// if |hours| > 11 the excess is folded into `now` instead
byte[] p = {
    (byte) hours,                       // [0] signed timezone hours, -11..+11
    (byte) ( now        & 0xFF),        // [1] epoch seconds, LITTLE-endian u32
    (byte) ((now >>  8) & 0xFF),        // [2]
    (byte) ((now >> 16) & 0xFF),        // [3]
    (byte) ((now >> 24) & 0xFF),        // [4]
    (byte) ((Math.abs(offset % 60) * 100) / 60)   // [5] sub-hour offset as 1/100 h
};
```

Note `[5]`: a 30-minute zone (e.g. IST) sends `50`, a 45-minute zone sends `75`.
If the zone is beyond ±11 h the surplus is added to the timestamp and the hour
field is clamped — so the watch still shows the right wall-clock time.

DST is already included because `TimeZone.getOffset(millis)` is used.

### 6.2 Alarms — set `0x02 / 0x02`, get `0x04 / 0x04`

Fixed **41-byte** payload — a full rewrite of all 10 slots every time:

```
[0]                 = 0x0A            (10 slots)
[1 + i*4 + 0]       = minutes & 0xFF        ] minutes after midnight,
[1 + i*4 + 1]       = (minutes >> 8) & 0xFF ] LITTLE-endian u16 (0..1439)
[1 + i*4 + 2]       = day bitmask
[1 + i*4 + 3]       = enabled (1 / 0)
```

`getAlarm` replies with the identical layout: `content[0]` = slot count, then
4-byte records. The app treats a record as *present* only when byte 2 (the day
mask) is non-zero.

Day bitmask: the app masks with `0x7F` (`if (days > 128) days &= 127`), so bit 7
is reserved and bits 0–6 are the week days. Slot `i` is disabled by zeroing the
record.

### 6.3 Steps / activity — `0x03 / 0x05` (`getHisStepsData`)

Request payload: `00 00 00 00 00 00`.

Reply (arrives on the bulk notify characteristic, reassembled):

```
content[0..11]              12-byte header
content[12..]               N records of 116 bytes, newest first (index 0 = today)

  per 116-byte record:
    [0..15]     header (date etc.)
    [16..111]   24 hourly buckets x 4 bytes:
                    u16 LE  steps in that hour
                    u16 LE  secondary metric (calories / distance)
    [112..115]  trailer
```

The app computes the daily total by summing the 24 buckets:

```java
byte[] day = copyOfRange(record, 16, 113);
for (int i = 0; i < day.length - 4; i += 4) {
    steps += toInt(copyOfRange(day, i,     i + 2));   // LE u16
    other += toInt(copyOfRange(day, i + 2, i + 4));   // LE u16
}
```

Record 0 is today, record 1 yesterday, and so on.

### 6.4 Watch face / theme

**Built-in faces — trivial.** `setPanel` = `0x02 / 0x0F`, payload is a **single byte**:

```java
laiSiCmd.setPanel(ble, new byte[]{ (byte)(id - 1) });   // id is 1-based in the UI
```

The Uwatch resources ship 4 built-in dials (`uwatch_dial_1` … `uwatch_dial_4`),
so valid values are `0x00`–`0x03`. Read the current one with `getPanel`
(`0x04 / 0x0A`).

**Custom faces — hard.** CMD `0x08` uploads a proprietary binary dial produced
by UMIDIGI's backend (`app-eu.umidigi.com/oyefit/…`). Use the built-in path
unless you want to reverse the dial container too.

### 6.5 Notifications — `0x02 / 0x19` (bonus)

```
[0]                 msgType
[1]                 1 + len(body) + 1 + len(title)      (single byte!)
[2 .. 2+b-1]        body,  UTF-8, truncated to 96 bytes
[2+b]               0x00
[3+b .. ]           title, UTF-8, truncated to 60 bytes
[len-2]             0x00
[len-1]             0xA5                                 (terminator)
```

msgType: `2` SMS, `4` WeChat, `5` QQ, `6` Weibo, `7` WhatsApp, `8` Line,
`9` Twitter, `10` Facebook, `11` Telegram, `12` Instagram, `13` Skype,
`14` KakaoTalk, `128` other. Incoming calls use `setPhone` (`0x02/0x1C`).

---

## 7. Recommended startup sequence

```
connect -> request MTU 247 -> enable notify on 6e400003 and 6dda1206
  -> 0x04/0x0D  getRandomNumber
  -> 0x01/0x01  bond(random)
  -> 0x01/0x03  deviceLogin(FealCipher(mac, random))
  -> 0x02/0x26  setTime
  -> 0x04/0x19  getFunctionTable     (what this unit actually supports)
  -> 0x04/0x01  getPower             (battery)
  ... your commands ...
```

Send **one command at a time** and wait for the matching `CMD`/`KEY` reply or the
5 s timeout — the firmware does not tolerate pipelining.

---

## 8. Legal note

This documents interoperability with a device you own, derived from the
manufacturer's own freely-distributed APK. It contains no UMIDIGI/HYST code —
only a description of the wire format plus a clean-room reimplementation of a
published cipher (FEAL). Don't redistribute their APK or `.so`.
