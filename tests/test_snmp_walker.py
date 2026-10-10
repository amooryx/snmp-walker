import socket
import unittest

import snmp_walker as walker


def response(request_id, oid, value_tag=0x04, value=b"device", status=0):
    binding = walker._tlv(
        0x30,
        walker._tlv(0x06, walker._encode_oid(oid)) + walker._tlv(value_tag, value),
    )
    pdu = walker._tlv(
        0xA2,
        walker._encode_integer(request_id)
        + walker._encode_integer(status)
        + walker._encode_integer(1 if status else 0)
        + walker._tlv(0x30, binding),
    )
    return walker._tlv(
        0x30,
        walker._encode_integer(1) + walker._tlv(0x04, b"read-only") + pdu,
    )


class FakeSocket:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.connected_to = None
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.connected_to = address

    def send(self, packet):
        self.sent.append(packet)

    def recv(self, size):
        self.asserted_recv_size = size
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


class SNMPWalkerTests(unittest.TestCase):
    root = (1, 3, 6, 1, 2, 1)
    community = "read-only"

    def walker(self, replies, **kwargs):
        fake = FakeSocket(replies)
        max_rows = kwargs.pop("max_rows", 200)
        result = walker.walk_host(
            "192.0.2.10",
            161,
            self.community,
            "1.3.6.1.2.1",
            2,
            1,
            max_rows,
            socket_factory=lambda family, kind: fake,
        )
        return result, fake

    def test_walks_subtree_and_stops_before_next_subtree(self):
        rows = [
            (1, 3, 6, 1, 2, 1, 1, 1, 0),
            (1, 3, 6, 1, 2, 2, 1, 1, 0),
        ]
        result, fake = self.walker([
            response(1, rows[0], value=b"router"),
            response(2, rows[1], value=b"outside"),
        ])

        self.assertEqual([row["oid"] for row in result["rows"]], [".".join(map(str, rows[0]))])
        self.assertFalse(result["truncated"])
        self.assertEqual(len(fake.sent), 2)
        self.assertEqual(fake.connected_to, ("192.0.2.10", 161))
        self.assertEqual(fake.timeout, 2)
        self.assertEqual(fake.asserted_recv_size, 65535)
        _, message, _ = walker._read_tlv(fake.sent[0])
        _, _, offset = walker._read_tlv(message)
        _, _, offset = walker._read_tlv(message, offset)
        self.assertEqual(walker._read_tlv(message, offset)[0], 0xA1)

    def test_maximum_rows_marks_report_truncated(self):
        first = (1, 3, 6, 1, 2, 1, 1, 1, 0)
        result, fake = self.walker(
            [response(1, first)],
            max_rows=1,
        )

        self.assertEqual(len(result["rows"]), 1)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(fake.sent), 1)

    def test_retries_only_after_timeout(self):
        first = (1, 3, 6, 1, 2, 1, 1, 1, 0)
        result, fake = self.walker([
            socket.timeout(),
            response(1, first),
            response(2, (1, 3, 6, 1, 2, 2, 1)),
        ])

        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(len(fake.sent), 3)
        self.assertEqual(fake.sent[0], fake.sent[1])
        self.assertNotEqual(fake.sent[1], fake.sent[2])

    def test_final_timeout_is_reported(self):
        fake = FakeSocket([socket.timeout(), socket.timeout()])
        with self.assertRaisesRegex(walker.SNMPError, "timed out after 2 attempt"):
            walker.walk_host(
                "192.0.2.10", 161, self.community, "1.3.6.1.2.1", 2, 1, 200,
                socket_factory=lambda family, kind: fake,
            )

    def test_failure_preserves_rows_already_collected(self):
        first = (1, 3, 6, 1, 2, 1, 1, 1, 0)
        fake = FakeSocket([response(1, first), socket.timeout(), socket.timeout()])
        with self.assertRaisesRegex(walker.SNMPError, "timed out") as raised:
            walker.walk_host(
                "192.0.2.10", 161, self.community, "1.3.6.1.2.1", 2, 1, 200,
                socket_factory=lambda family, kind: fake,
            )

        self.assertEqual(len(raised.exception.rows), 1)
        self.assertEqual(raised.exception.rows[0]["oid"], ".".join(map(str, first)))

    def test_agent_error_status_is_reported_by_name(self):
        fake = FakeSocket([response(1, self.root + (1,), status=6)])
        with self.assertRaisesRegex(walker.SNMPError, "noAccess"):
            walker.walk_host(
                "192.0.2.10", 161, self.community, "1.3.6.1.2.1", 2, 0, 200,
                socket_factory=lambda family, kind: fake,
            )

    def test_large_value_is_truncated_before_output(self):
        binding = walker.decode_response(
            response(1, self.root + (1,), value=b"x" * (walker.MAX_VALUE_BYTES + 8)),
            self.community,
            1,
        )

        self.assertTrue(binding["value_truncated"])
        self.assertEqual(len(binding["value"]), walker.MAX_VALUE_BYTES + 1)
        self.assertTrue(binding["value"].endswith("…"))

    def test_decodes_signed_and_unsigned_values(self):
        self.assertEqual(walker._decode_value(0x02, b"\xff", 256), ("Integer32", -1, False))
        self.assertEqual(
            walker._decode_value(0x46, b"\x00\x80\x00\x00\x00\x00\x00\x00\x00", 256),
            ("Counter64", 1 << 63, False),
        )

    def test_rejects_invalid_inputs_before_opening_socket(self):
        factory = lambda family, kind: self.fail("socket must not be created")
        cases = [
            ("not a host", 161, "read-only", "1.3.6.1.2.1", 2, 0, 1),
            ("192.0.2.10", 0, "read-only", "1.3.6.1.2.1", 2, 0, 1),
            ("192.0.2.10", 161, "", "1.3.6.1.2.1", 2, 0, 1),
            ("192.0.2.10", 161, "read-only", "1.3..6", 2, 0, 1),
            ("192.0.2.10", 161, "read-only", "1.3.6.1.2.1", 31, 0, 1),
            ("192.0.2.10", 161, "read-only", "1.3.6.1.2.1", 2, 6, 1),
            ("192.0.2.10", 161, "read-only", "1.3.6.1.2.1", 2, 0, 501),
        ]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                walker.walk_host(*args, socket_factory=factory)

    def test_requires_matching_community_and_request_id(self):
        packet = response(1, self.root + (1,))
        with self.assertRaisesRegex(walker.SNMPError, "community"):
            walker.decode_response(packet, "wrong", 1)
        with self.assertRaisesRegex(walker.SNMPError, "request ID"):
            walker.decode_response(packet, self.community, 2)


if __name__ == "__main__":
    unittest.main()
