"""Portable re-implementation of libdevice_auth.so's FealCipher (FEAL-32).

Derived from the AArch64 disassembly of libdevice_auth.so shipped in
OyeFit 1.2.0 (com.hyst.oyefit). Produces the 32-bit `authKey` used by the
LaiSi/Uwatch BLE login handshake:

    authKey = FealCipher(mac_bytes[6], randomCode_u32)

Verified byte-for-byte against the real library under Unicorn emulation.
"""
import struct


def _rot2(x: int) -> int:
    x &= 0xFF
    return ((x << 2) | (x >> 6)) & 0xFF


def _s0(a: int, b: int) -> int:
    return _rot2((a + b) & 0xFF)


def _s1(a: int, b: int) -> int:
    return _rot2((a + b + 1) & 0xFF)


def _feal_f(alpha: bytes, beta: bytes) -> bytearray:
    """FEAL f-function. alpha: 4 bytes, beta: 2 bytes -> 4 bytes."""
    out = bytearray(4)
    f1 = (alpha[1] ^ beta[0]) & 0xFF
    f2 = (alpha[2] ^ beta[1]) & 0xFF
    f1 = (f1 ^ alpha[0]) & 0xFF
    f2 = (f2 ^ alpha[3]) & 0xFF
    f1 = _s1(f1, f2)
    f2 = _s0(f2, f1)
    out[0] = _s0(alpha[0], f1)
    out[3] = _s1(alpha[3], f2)
    out[1] = f1
    out[2] = f2
    return out


def _feal_fk(alpha: bytes, beta: bytes) -> bytearray:
    """FEAL fK-function (key schedule). alpha: 4 bytes, beta: 4 bytes -> 4 bytes."""
    out = bytearray(4)
    fk1 = (alpha[0] ^ alpha[1]) & 0xFF
    fk2 = (alpha[3] ^ alpha[2]) & 0xFF
    fk1 = _s1(fk1, fk2 ^ beta[0])
    fk2 = _s0(fk2, fk1 ^ beta[1])
    out[0] = _s0(alpha[0], fk1 ^ beta[2])
    out[3] = _s1(alpha[3], fk2 ^ beta[3])
    out[1] = fk1
    out[2] = fk2
    return out


def _feal_exkey(key8: bytes) -> bytearray:
    """Expand an 8-byte key into 80 bytes (40 x 16-bit subkeys) for FEAL-32."""
    A = [bytearray(key8[0:4]), bytearray(4)]
    B = [bytearray(key8[4:8]), bytearray(4)]
    D = [bytearray(4), bytearray(4)]
    out = bytearray()
    for i in range(1, 21):                    # 20 iterations -> 80 bytes
        t, u = i & 1, (i & 1) ^ 1
        D[t] = bytearray(A[u])                # D[t] = A[u]
        prev_A_u = bytearray(A[u])
        beta = bytes(d ^ b for d, b in zip(D[u], B[u]))
        A[t] = bytearray(B[u])                # A[t] = B[u]
        B[t] = _feal_fk(prev_A_u, beta)       # FK(alpha=A[u], beta) -> B[t]
        out += bytes(B[t])
    return out


def feal_cipher(mac6: bytes, value: int) -> int:
    """authKey = FealCipher(mac6, value). Returns unsigned 32-bit."""
    assert len(mac6) == 6
    value &= 0xFFFFFFFF

    # 8-byte key = 0x00 || mac[0..5] || 0x00
    key8 = bytes([0]) + bytes(mac6) + bytes([0])
    sk = _feal_exkey(key8)

    # 64-bit plaintext = value bytes, then the same bytes reversed
    v = struct.pack("<I", value)
    L = struct.unpack("<I", v)[0]                    # value
    R = struct.unpack("<I", bytes(reversed(v)))[0]   # byteswap(value)

    L ^= struct.unpack_from("<I", sk, 64)[0]
    R ^= struct.unpack_from("<I", sk, 68)[0]
    R ^= L

    Lb, Rb = bytearray(struct.pack("<I", L)), bytearray(struct.pack("<I", R))
    for i in range(32):
        tmp = _feal_f(Rb, sk[2 * i:2 * i + 2])
        new_R = bytearray(l ^ t for l, t in zip(Lb, tmp))
        Lb, Rb = Rb, new_R

    return (struct.unpack("<I", bytes(Rb))[0] ^ struct.unpack_from("<I", sk, 72)[0]) & 0xFFFFFFFF


def auth_key(mac: str, random_code: int) -> int:
    """Convenience wrapper taking 'AA:BB:CC:DD:EE:FF'."""
    mac6 = bytes(int(x, 16) for x in mac.split(":"))
    return feal_cipher(mac6, random_code)

# Ground-truth vectors captured from the real libdevice_auth.so under emulation.
TEST_VECTORS = [
    ("AA:BB:CC:DD:EE:FF", 0x12345678, 0x539EAACE),
    ("AA:BB:CC:DD:EE:FF", 0x00000000, 0xE80B1E62),
    ("AA:BB:CC:DD:EE:FF", 0xFFFFFFFF, 0xC3120D14),
    ("00:00:00:00:00:00", 0x00000000, 0x2E37C687),
    ("01:02:03:04:05:06", 0xDEADBEEF, 0x039D0D27),
    ("C0:1A:FF:12:34:56", 0x0000002A, 0x9FA9F23E),
    ("12:34:56:78:9A:BC", 0x11223344, 0xB3BF2DD3),
    ("FF:EE:DD:CC:BB:AA", 0x0BADF00D, 0x5FB91238),
    ("A4:C1:38:11:22:33", 0x7FFFFFFF, 0x998D0CE4),
    ("00:11:22:33:44:55", 0x80000000, 0x48FC7F39),
]
