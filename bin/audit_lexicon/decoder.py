"""
Turn a parsed auditd field dict into an interpreted one, the same job
`ausearch -i` does, but reusable as a library function so the search
command (or future commands/modes) can call it per-event.

Nothing here shells out, evals, or executes decoded content. Every
function takes strings in and returns strings out.
"""

import os
import time

from .arch_table import resolve_arch
from .syscall_tables import SYSCALL_TABLES, DEFAULT_ARCH
from .proctitle import decode_proctitle

NUMERIC_ID_FIELDS = frozenset({
    "uid", "euid", "suid", "fsuid", "oauid",
    "gid", "egid", "sgid", "fsgid",
    "auid", "pid", "ppid", "tid", "ses",
    "items", "item", "inode", "ouid", "ogid",
})

_SPECIALLY_HANDLED = frozenset({
    "arch", "syscall", "proctitle", "exit",
    "audit_epoch", "audit_serial",
})

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _maybe_hex_decode(value):

    if not value or len(value) < 4 or len(value) % 2 != 0:
        return None
    if any(c not in _HEX_CHARS for c in value):
        return None

    if not any(c in "abcdefABCDEF" for c in value):
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t\x00")
    if printable / len(text) < 0.9:
        return None
    return text.replace("\x00", " ").strip()


def _interpret_exit(value):
    try:
        code = int(value)
    except (TypeError, ValueError):
        return None
    if code >= 0:
        return None
    try:
        return "{} ({})".format(code, os.strerror(-code))
    except ValueError:
        return None


def humanize_epoch(epoch_str):

    try:
        seconds = float(epoch_str)
    except (TypeError, ValueError):
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(seconds)) + " UTC"


def interpret_record(fields, default_arch=DEFAULT_ARCH):

    arch_name = None
    if "arch" in fields:
        arch_name, _ = resolve_arch(fields["arch"])
        fields["arch_raw"] = fields["arch"]
        fields["arch"] = arch_name

    if "syscall" in fields:
        table = SYSCALL_TABLES.get(arch_name) or SYSCALL_TABLES.get(default_arch, {})
        try:
            num = int(fields["syscall"])
        except ValueError:
            num = None
        if num is not None:
            fields["syscall_raw"] = fields["syscall"]
            fields["syscall"] = table.get(num, "syscall_{}".format(num))

    if "proctitle" in fields:
        decoded = decode_proctitle(fields["proctitle"])
        if decoded is not None:
            fields["proctitle_raw"] = fields["proctitle"]
            fields["proctitle"] = decoded

    if "exit" in fields:
        decoded_exit = _interpret_exit(fields["exit"])
        if decoded_exit is not None:
            fields["exit_raw"] = fields["exit"]
            fields["exit"] = decoded_exit

    if "audit_epoch" in fields:
        human = humanize_epoch(fields["audit_epoch"])
        if human is not None:
            fields["audit_time"] = human

    for key in list(fields.keys()):
        if key in NUMERIC_ID_FIELDS or key in _SPECIALLY_HANDLED:
            continue
        if key.endswith("_raw"):
            continue
        decoded = _maybe_hex_decode(fields[key])
        if decoded is not None:
            fields[key + "_raw"] = fields[key]
            fields[key] = decoded

    return fields
