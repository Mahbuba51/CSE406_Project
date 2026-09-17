import socket
import struct
import unittest
from lab.packets import checksum, craft_packet, parse_frame, timestamps


class PacketTests(unittest.TestCase):
    def packet(self, **kw):
        args = dict(src="10.0.0.10", dst="10.0.0.30", sport=49152,
                    dport=8080, seq=0xfffffff9, ack=12345, window=4096, payload=b"ADMIN_WIPE\n")
        args.update(kw)
        return craft_packet(**args)

    def frame(self, packet=None):
        return bytes.fromhex("001122334455aabbccddeeff0800") + (packet or self.packet())

    def test_checksum_known_vector(self):
        # Published standard Internet-checksum arithmetic example.
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220d)
        self.assertEqual(checksum(b"\x01"), 0xfeff)

    def test_header_and_checksums_independently(self):
        packet = self.packet()
        self.assertEqual(packet[0], 0x45)
        self.assertEqual(struct.unpack_from("!H", packet, 2)[0], len(packet))
        tcp = packet[20:]
        pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
        # An independent byte-wise one's-complement sum, not the implementation under test.
        for raw in (packet[:20], pseudo + tcp):
            raw += b"\0" * (len(raw) % 2)
            total = sum((raw[i] << 8) | raw[i+1] for i in range(0, len(raw), 2))
            while total > 65535:
                total = (total & 65535) + (total >> 16)
            self.assertEqual(total, 65535)
        self.assertEqual(tcp[13], 0x18)

    def test_parse_and_wraparound(self):
        segment = parse_frame(self.frame())
        self.assertEqual(segment.payload, b"ADMIN_WIPE\n")
        self.assertEqual(segment.next_seq, 4)
        self.assertEqual((segment.sport, segment.dport), (49152, 8080))

    def test_timestamp_option(self):
        options = b"\x01\x01\x08\x0a" + struct.pack("!II", 987, 654)
        segment = parse_frame(self.frame(self.packet(options=options)))
        self.assertEqual(timestamps(segment.options), (987, 654))
        self.assertIsNone(timestamps(b"\x08\x00"))
        self.assertIsNone(timestamps(b"\x08\x0a\x00"))

    def test_truncated_frames(self):
        frame = self.frame()
        for length in range(len(frame)):
            self.assertIsNone(parse_frame(frame[:length]))

    def test_fragment_and_invalid_tcp_offset(self):
        packet = bytearray(self.packet())
        packet[6:8] = b"\x20\x00"
        self.assertIsNone(parse_frame(self.frame(packet)))
        packet = bytearray(self.packet())
        packet[32] = 0x40
        self.assertIsNone(parse_frame(self.frame(packet)))

    def test_vlan_and_ethernet_padding(self):
        frame = self.frame()
        vlan = frame[:12] + b"\x81\x00\x00\x01\x08\x00" + frame[14:] + b"\0" * 12
        self.assertEqual(parse_frame(vlan).payload, b"ADMIN_WIPE\n")


if __name__ == "__main__":
    unittest.main()
