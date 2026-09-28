"""
Decode the auditd PROCTITLE record's `proctitle` field.

The kernel writes the full argv of the process (as captured from the
kernel's copy of the command line, similar to /proc/<pid>/cmdline) as
NUL-separated arguments, then auditd hex-encodes the whole blob because it
contains embedded NUL bytes. This mirrors `ausearch -i`'s "interpret
proctitle" behaviour: split on NUL, then re-join into a single
shell-quoted-looking string for display.

This module never executes, evals, or shells out on the decoded content —
it only produces a display string. Treat the result as untrusted text.
"""

import shlex


def decode_proctitle(hex_value):

    if not hex_value:
        return None
    value = hex_value.strip()
    if len(value) < 2 or len(value) % 2 != 0:
        return None
    if any(c not in "0123456789abcdefABCDEF" for c in value):
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None

    parts = [p for p in raw.split(b"\x00") if p != b""]
    if not parts:
        return None

    decoded_parts = [p.decode("utf-8", errors="replace") for p in parts]
    return " ".join(shlex.quote(p) for p in decoded_parts)
