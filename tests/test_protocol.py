import unittest
from lab.protocol import authenticated_line, verify_line


class ProtocolTests(unittest.TestCase):
    def test_legitimate_command(self):
        self.assertEqual(verify_line(authenticated_line(1, "STATUS").rstrip(b"\n"), 1), "STATUS")

    def test_plain_injection_rejected(self):
        self.assertIsNone(verify_line(b"ADMIN_WIPE", 2))

    def test_tampering_rejected(self):
        wire = authenticated_line(1, "STATUS").rstrip(b"\n").replace(b"STATUS", b"ADMIN_WIPE")
        self.assertIsNone(verify_line(wire, 1))

    def test_replay_rejected(self):
        wire = authenticated_line(1, "STATUS").rstrip(b"\n")
        self.assertIsNone(verify_line(wire, 2))

    def test_invalid_encoding_rejected(self):
        self.assertIsNone(verify_line(b"\xff", 1))
