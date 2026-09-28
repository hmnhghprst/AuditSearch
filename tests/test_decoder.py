import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from audit_lexicon.parser import parse_audit_line
from audit_lexicon.decoder import interpret_record, humanize_epoch
from audit_lexicon.arch_table import resolve_arch
from audit_lexicon.proctitle import decode_proctitle


class TestArchTable(unittest.TestCase):
    def test_x86_64(self):
        name, _ = resolve_arch("c000003e")
        self.assertEqual(name, "x86_64")

    def test_aarch64(self):
        name, _ = resolve_arch("c00000b7")
        self.assertEqual(name, "aarch64")

    def test_unknown_arch(self):
        name, _ = resolve_arch("deadbeef")
        self.assertTrue(name.startswith("unknown("))


class TestProctitle(unittest.TestCase):
    def test_decode_simple_argv(self):
        # "/bin/ls\0-la\0" -> "/bin/ls -la"
        blob = "2F62696E2F6C7300612D6C6100"
        # note: real proctitle blobs use NUL separators, not literal 'a'
        blob = "/bin/ls\0-la\0".encode().hex()
        self.assertEqual(decode_proctitle(blob), "/bin/ls -la")

    def test_quotes_args_with_spaces(self):
        blob = "/usr/bin/find\0/var/log\0-name\0*.log\0".encode().hex()
        decoded = decode_proctitle(blob)
        self.assertIn("/usr/bin/find", decoded)
        self.assertIn("/var/log", decoded)

    def test_not_hex_returns_none(self):
        self.assertIsNone(decode_proctitle("not-hex!!"))

    def test_odd_length_returns_none(self):
        self.assertIsNone(decode_proctitle("abc"))


class TestInterpretRecord(unittest.TestCase):
    def test_full_syscall_record(self):
        raw = (
            'type=SYSCALL msg=audit(1700000000.500:99): arch=c000003e '
            'syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 a3=4 items=2 '
            'ppid=1 pid=2 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 '
            'egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" '
            'exe="/bin/bash" '
            'key=' + '6175646974636865636b'
        )
        fields = parse_audit_line(raw)
        interpret_record(fields)

        self.assertEqual(fields["arch"], "x86_64")
        self.assertEqual(fields["arch_raw"], "c000003e")
        self.assertEqual(fields["syscall"], "execve")
        self.assertEqual(fields["syscall_raw"], "59")
        # id fields must never be hex-decoded
        self.assertEqual(fields["uid"], "0")
        self.assertEqual(fields["auid"], "1000")
        # key was hex for "auditcheck"
        self.assertEqual(fields["key"], "auditcheck")
        self.assertIn("audit_time", fields)

    def test_negative_exit_resolves_errno(self):
        fields = {"exit": "-13"}
        interpret_record(fields)
        self.assertIn("Permission denied", fields["exit"])
        self.assertEqual(fields["exit_raw"], "-13")

    def test_positive_exit_untouched(self):
        fields = {"exit": "0"}
        interpret_record(fields)
        self.assertEqual(fields["exit"], "0")
        self.assertNotIn("exit_raw", fields)

    def test_proctitle_in_full_record(self):
        blob = "/usr/sbin/sshd\0-D\0".encode().hex()
        fields = {"type": "PROCTITLE", "proctitle": blob}
        interpret_record(fields)
        self.assertEqual(fields["proctitle"], "/usr/sbin/sshd -D")
        self.assertEqual(fields["proctitle_raw"], blob)

    def test_humanize_epoch(self):
        text = humanize_epoch("1700000000.0")
        self.assertTrue(text.endswith("UTC"))

    def test_unresolvable_syscall_falls_back(self):
        fields = {"arch": "c000003e", "syscall": "999999"}
        interpret_record(fields)
        self.assertEqual(fields["syscall"], "syscall_999999")

    def test_pure_digit_numeric_field_never_hex_decoded(self):
        fields = {"type": "PATH", "inode": "445566", "ouid": "33", "ogid": "33"}
        interpret_record(fields)
        self.assertEqual(fields["inode"], "445566")
        self.assertNotIn("inode_raw", fields)
        self.assertEqual(fields["ouid"], "33")
        self.assertEqual(fields["ogid"], "33")

    def test_execve_argv_fields_are_decoded(self):

        blob = "/var/www/html".encode().hex()
        fields = {"type": "EXECVE", "argc": "1", "a0": blob}
        interpret_record(fields)
        self.assertEqual(fields["a0"], "/var/www/html")
        self.assertEqual(fields["a0_raw"], blob)

    def test_syscall_register_args_not_corrupted(self):

        fields = {"type": "SYSCALL", "a0": "7fff1234"}
        interpret_record(fields)
        self.assertEqual(fields["a0"], "7fff1234")
        self.assertNotIn("a0_raw", fields)


if __name__ == "__main__":
    unittest.main()
