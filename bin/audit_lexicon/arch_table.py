"""
Linux audit "arch" field decoding.

The SYSCALL record's `arch` field is not a syscall-table selector by name —
it is the raw `AUDIT_ARCH_*` word the kernel puts on the audit record, built
from the ELF machine code plus two flag bits:

    __AUDIT_ARCH_64BIT = 0x80000000
    __AUDIT_ARCH_LE    = 0x40000000

`ausearch -i` resolves this by exact match against the known constants
rather than by decoding the bit flags generically, because a handful of
combinations (e.g. big-endian PowerPC) don't follow the LE-flag pattern.
We do the same: a flat table of known values, sourced from the Linux
audit-userspace project's `interpret.c` (ARCH_TABLE) and
<linux/audit.h>. Extend this table for architectures you actually see in
your environment.

Keys are the lowercase, zero-padded 8-hex-digit form of the field as it
appears in raw auditd events (e.g. "c000003e").
"""

ARCH_TABLE = {
    "c000003e": "x86_64",
    "40000003": "i386",
    "c00000b7": "aarch64",
    "40000028": "arm",
    "40000032": "armeb",
    "80000015": "ppc64",
    "c0000015": "ppc64le",
    "00000014": "ppc",
    "80000016": "s390x",
    "00000016": "s390",
    "00000008": "mips",
    "40000008": "mipsel",
    "80000008": "mips64",
    "c0000008": "mips64n32",
    "c00000f3": "riscv64",
    "000000f3": "riscv32",
    "00000032": "sparc",
    "8000002b": "sparc64",
    "00000028": "sh",
    "4000002a": "sheb",
}


def normalize_arch_code(value):
    """Return an 8-digit lowercase hex string for lookups, or None."""
    if value is None:
        return None
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    if not v or any(c not in "0123456789abcdef" for c in v):
        return None
    return v.rjust(8, "0")


def resolve_arch(raw_value):
    """Return (friendly_name, normalized_code) for a raw arch field value."""
    code = normalize_arch_code(raw_value)
    if code is None:
        return f"unknown(0x{raw_value})", raw_value
    name = ARCH_TABLE.get(code)
    if name is None:
        return f"unknown(0x{code})", code
    return name, code
