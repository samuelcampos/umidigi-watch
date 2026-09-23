"""Emulate libdevice_auth.so (AArch64) with Unicorn to obtain ground-truth
FealCipher() outputs for the OyeFit / LaiSi watch login handshake."""
import struct, sys
from unicorn import *
from unicorn.arm64_const import *

SO = "libs/lib/arm64-v8a/libdevice_auth.so"
BASE = 0x00000000
IMG = 0x40000          # mapped image size
STACK = 0x70000000
STACK_SZ = 0x100000
SCRATCH = 0x80000000   # for __stack_chk_guard target

blob = open(SO, "rb").read()

# ---- minimal ELF64 parsing -------------------------------------------------
e_shoff, = struct.unpack_from("<Q", blob, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", blob, 0x3A)

sections = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name, typ, flags, addr, off, size, link, info, align, entsz = struct.unpack_from("<IIQQQQIIQQ", blob, o)
    sections.append(dict(name=name, type=typ, addr=addr, off=off, size=size, link=link, entsize=entsz))

shstr = sections[e_shstrndx]
def sname(s):
    o = shstr["off"] + s["name"]
    return blob[o:blob.index(b"\0", o)].decode()
for s in sections:
    s["sname"] = sname(s)

def sec(n):
    for s in sections:
        if s["sname"] == n:
            return s
    return None

# ---- program headers -> map image -----------------------------------------
e_phoff, = struct.unpack_from("<Q", blob, 0x20)
e_phentsize, e_phnum = struct.unpack_from("<HH", blob, 0x36)

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(BASE, IMG)
mu.mem_map(STACK, STACK_SZ)
mu.mem_map(SCRATCH, 0x1000)

for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags, p_off, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", blob, o)
    if p_type == 1:  # PT_LOAD
        mu.mem_write(BASE + p_vaddr, blob[p_off:p_off + p_filesz])

# ---- symbols ---------------------------------------------------------------
dynsym, dynstr = sec(".dynsym"), sec(".dynstr")
syms = []
n = dynsym["size"] // 24
for i in range(n):
    o = dynsym["off"] + i * 24
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", blob, o)
    so_ = dynstr["off"] + st_name
    nm = blob[so_:blob.index(b"\0", so_)].decode()
    syms.append(dict(name=nm, value=st_value, shndx=st_shndx))

# ---- relocations -----------------------------------------------------------
R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE = 257, 1025, 1026, 1027
guard_ptr = SCRATCH + 0x100
mu.mem_write(guard_ptr, struct.pack("<Q", 0xDEADBEEF12345678))

for rs in (".rela.dyn", ".rela.plt"):
    s = sec(rs)
    if not s:
        continue
    for i in range(s["size"] // 24):
        o = s["off"] + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", blob, o)
        rtype = r_info & 0xFFFFFFFF
        rsym = r_info >> 32
        if rtype == R_AARCH64_RELATIVE:
            val = BASE + r_addend
        elif rtype in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64):
            sy = syms[rsym]
            if sy["shndx"] != 0:
                val = BASE + sy["value"]
            elif sy["name"] == "__stack_chk_guard":
                val = guard_ptr           # GOT holds pointer to the guard
            else:
                val = SCRATCH + 0x800     # unused libc imports
        else:
            continue
        mu.mem_write(BASE + r_offset, struct.pack("<Q", val))

FEALCIPHER = BASE + next(s["value"] for s in syms if s["name"] == "FealCipher" and s["shndx"])
RET_MAGIC = 0x50000000
mu.mem_map(RET_MAGIC & ~0xFFF, 0x1000)


def feal_cipher(mac6: bytes, value: int) -> int:
    """Call FealCipher(uint8 *mac6, uint32 value) -> int32"""
    assert len(mac6) == 6
    buf = SCRATCH + 0x200
    mu.mem_write(buf, mac6)
    sp = STACK + STACK_SZ - 0x2000
    mu.reg_write(UC_ARM64_REG_SP, sp)
    mu.reg_write(UC_ARM64_REG_X0, buf)
    mu.reg_write(UC_ARM64_REG_X1, value & 0xFFFFFFFF)
    mu.reg_write(UC_ARM64_REG_LR, RET_MAGIC)
    mu.emu_start(FEALCIPHER, RET_MAGIC)
    return mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF


if __name__ == "__main__":
    vectors = [
        ("AA:BB:CC:DD:EE:FF", 0x12345678),
        ("AA:BB:CC:DD:EE:FF", 0x00000000),
        ("AA:BB:CC:DD:EE:FF", 0xFFFFFFFF),
        ("00:00:00:00:00:00", 0x00000000),
        ("01:02:03:04:05:06", 0xDEADBEEF),
        ("C0:1A:FF:12:34:56", 0x0000002A),
        ("12:34:56:78:9A:BC", 0x11223344),
    ]
    print("ground truth from libdevice_auth.so (FealCipher):")
    for mac, v in vectors:
        m = bytes(int(x, 16) for x in mac.split(":"))
        r = feal_cipher(m, v)
        print(f"  mac={mac}  random=0x{v:08X}  ->  authKey=0x{r:08X} ({struct.unpack('<i', struct.pack('<I', r))[0]})")
