"""
Protocol-level regression test for the `-i` / `-correlate` bare-flag
syntax advertised throughout the README and docstrings.

splunklib's default SCP v2 argument parser only understands `name=value`
tokens (`SearchCommand._protocol_v2_option_parser` does
`arg.split("=", 1)`). A bare "-i" has no "=" in it, so *without* the
`_protocol_v2_option_parser` override in auditsearch.py, "-i" silently
becomes a projected fieldname called "-i" instead of setting the `i`
option — no error, no crash, it just silently does nothing. This test
drives auditsearch.py over the real chunked wire protocol (no live Splunk
instance required) so that regression can never reappear silently.
"""

import json
import os
import subprocess
import sys
import unittest

BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "bin")
COMMAND_PATH = os.path.join(BIN_DIR, "auditsearch.py")

RAW_EVENT = (
    "type=PROCTITLE msg=audit(1790161433.999:77208959): "
    "proctitle=67726570002F6574632F636C6F75646C696E75782D72656C65617365"
)


def _chunk(meta, body=""):
    meta_json = json.dumps(meta)
    header = "chunked 1.0,%d,%d\n" % (len(meta_json), len(body))
    return header + meta_json + body


def run_command(args, raw_value=RAW_EVENT):
    getinfo = _chunk({
        "action": "getinfo",
        "preview": False,
        "searchinfo": {
            "args": args,
            "raw_args": args,
            "dispatch_dir": "/tmp",
            "sid": "test_sid",
            "app": "auditsearch",
            "owner": "admin",
            "username": "admin",
            "session_key": "",
            "splunk_version": "9.4.0",
            "splunkd_uri": "https://127.0.0.1:8089",
            "earliest_time": 0.0,
            "latest_time": 0.0,
            "search": "search index=x | " + " ".join(args),
        },
    })
    escaped = raw_value.replace('"', '""')
    body = '_raw\r\n"%s"\r\n' % escaped
    execute = _chunk({"action": "execute", "preview": False, "finished": True}, body)

    proc = subprocess.run(
        [sys.executable, COMMAND_PATH],
        input=(getinfo + execute).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=BIN_DIR,
    )
    return proc.returncode, proc.stdout.decode(errors="replace")


@unittest.skipUnless(
    os.path.exists(os.path.join(BIN_DIR, "splunklib", "searchcommands", "__init__.py")),
    "vendored splunklib not present",
)
class TestBareFlagSyntax(unittest.TestCase):
    def test_bare_dash_i_interprets(self):
        rc, out = run_command(["auditsearch", "-i"])
        self.assertEqual(rc, 0)
        self.assertIn("grep /etc/cloudlinux-release", out)
        # the "-i" token must never leak through as a literal fieldname
        self.assertNotIn("-i,", out.split("\r\n", 1)[0])

    def test_i_equals_t_interprets(self):
        rc, out = run_command(["auditsearch", "i=t"])
        self.assertEqual(rc, 0)
        self.assertIn("grep /etc/cloudlinux-release", out)

    def test_no_flag_leaves_hex_undecoded(self):
        rc, out = run_command(["auditsearch"])
        self.assertEqual(rc, 0)
        self.assertIn(
            "67726570002F6574632F636C6F75646C696E75782D72656C65617365", out
        )
        self.assertNotIn("grep /etc/cloudlinux-release", out)

    def test_bare_dash_i_combined_with_filter(self):
        rc, out = run_command(["auditsearch", "-i", "type=PROCTITLE"])
        self.assertEqual(rc, 0)
        self.assertIn("grep /etc/cloudlinux-release", out)

    def test_dash_k_two_token_matches(self):
        raw = ('type=SYSCALL msg=audit(1790200000.100:1): arch=c000003e '
               'syscall=2 key="rootcmd" comm="bash"')
        rc, out = run_command(["auditsearch", "-i", "-k", "rootcmd"], raw_value=raw)
        self.assertEqual(rc, 0)
        self.assertIn("rootcmd", out)
        self.assertIn("open", out)  # syscall=2 interpreted

    def test_dash_k_two_token_non_matching_is_filtered(self):
        raw = ('type=SYSCALL msg=audit(1790200000.100:1): arch=c000003e '
               'syscall=2 key="not_rootcmd" comm="bash"')
        rc, out = run_command(["auditsearch", "-i", "-k", "rootcmd"], raw_value=raw)
        self.assertEqual(rc, 0)
        self.assertNotIn("not_rootcmd", out)
        self.assertNotIn("SYSCALL", out)

    def test_dash_k_order_independent(self):
        raw = ('type=SYSCALL msg=audit(1790200000.100:1): arch=c000003e '
               'syscall=2 key="rootcmd" comm="bash"')
        rc1, out1 = run_command(["auditsearch", "-k", "rootcmd", "-i"], raw_value=raw)
        rc2, out2 = run_command(["auditsearch", "-i", "-k", "rootcmd"], raw_value=raw)
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        self.assertIn("rootcmd", out1)
        self.assertIn("rootcmd", out2)

    def test_dash_k_attached_value_form(self):
        raw = ('type=SYSCALL msg=audit(1790200000.100:1): arch=c000003e '
               'syscall=2 key="rootcmd" comm="bash"')
        rc, out = run_command(["auditsearch", "-k=rootcmd", "-i"], raw_value=raw)
        self.assertEqual(rc, 0)
        self.assertIn("rootcmd", out)

    def test_dash_k_missing_value_reports_error_not_crash(self):
        raw = ('type=SYSCALL msg=audit(1790200000.100:1): arch=c000003e '
               'syscall=2 key="rootcmd" comm="bash"')
        rc, out = run_command(["auditsearch", "-k"], raw_value=raw)
        self.assertEqual(rc, 0)  # reports via inspector, doesn't crash
        self.assertIn("Missing value after -k", out)


if __name__ == "__main__":
    unittest.main()
