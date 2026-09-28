from . import x86_64 as _x86_64
from . import aarch64 as _aarch64

SYSCALL_TABLES = {
    "x86_64": _x86_64.TABLE,
    "aarch64": _aarch64.TABLE,
}


DEFAULT_ARCH = "x86_64"
