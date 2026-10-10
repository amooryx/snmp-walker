#!/usr/bin/env python3
"""Bounded, read-only SNMPv2c subtree inventory walker."""

import argparse
import ipaddress
import json
import re
import socket
import sys
import time

MAX_HOSTS = 32
MAX_ROWS = 500
MAX_TIMEOUT = 30.0
MAX_RETRIES = 5
MAX_WALK_SECONDS = 300.0
MAX_COMMUNITY_BYTES = 255
MAX_VALUE_BYTES = 256
MAX_OID_BYTES = 128
DEFAULT_ROOT_OID = "1.3.6.1.2.1"
ERROR_STATUSES = {
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}
VALUE_TYPES = {
    0x02: "Integer32",
    0x04: "OctetString",
    0x05: "Null",
    0x06: "ObjectIdentifier",
    0x40: "IpAddress",
    0x41: "Counter32",
    0x42: "Gauge32",
    0x43: "TimeTicks",
    0x44: "Opaque",
    0x46: "Counter64",
    0x80: "NoSuchObject",
    0x81: "NoSuchInstance",
    0x82: "EndOfMibView",
}


class SNMPError(Exception):
    """An SNMP encoding, protocol, or transport error."""

    def __init__(self, message):
        super().__init__(message)
        self.rows = []


def _encode_length(length):
    if length < 0:
        raise ValueError("BER length cannot be negative")
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag, value):
    return bytes([tag]) + _encode_length(len(value)) + value


def _read_tlv(data, offset=0):
    if offset >= len(data):
        raise SNMPError("Truncated BER tag")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise SNMPError("Truncated BER length")
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        count = first_length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise SNMPError("Invalid or truncated BER length")
        if data[offset] == 0:
            raise SNMPError("Non-canonical BER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        if length < 128:
            raise SNMPError("Non-canonical BER length")
        offset += count
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise SNMPError("Truncated BER value")
    return tag, data[offset:end], end


def _read_expected(data, offset, expected_tag, description):
    tag, value, end = _read_tlv(data, offset)
    if tag != expected_tag:
        raise SNMPError(f"Expected {description} (tag 0x{expected_tag:02x}), got 0x{tag:02x}")
    return value, end


def _encode_base128(number):
    if number < 0:
        raise ValueError("OID arcs cannot be negative")
    result = [number & 0x7F]
    number >>= 7
    while number:
        result.insert(0, (number & 0x7F) | 0x80)
        number >>= 7
    return bytes(result)


def parse_oid(oid):
    if (
        not isinstance(oid, str)
        or len(oid) > 4096
        or not re.fullmatch(r"\.?[0-9]+(?:\.[0-9]+)+\.?", oid)
    ):
        raise ValueError(f"Invalid object identifier: {oid!r}")
    arcs = tuple(int(part) for part in oid.strip(".").split("."))
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39):
        raise ValueError(f"Invalid object identifier: {oid!r}")
    if any(arc > 0xFFFFFFFFFFFFFFFF for arc in arcs):
        raise ValueError("OID arcs may not exceed 64 bits")
    if len(_encode_oid(arcs)) > MAX_OID_BYTES:
        raise ValueError(f"Object identifier exceeds {MAX_OID_BYTES} encoded bytes")
    return arcs


def _encode_oid(arcs):
    encoded = bytearray(_encode_base128(arcs[0] * 40 + arcs[1]))
    for arc in arcs[2:]:
        encoded.extend(_encode_base128(arc))
    return bytes(encoded)


def _decode_oid(encoded):
    if not encoded:
        raise SNMPError("Empty object identifier")
    if len(encoded) > MAX_OID_BYTES:
        raise SNMPError(f"Response OID exceeds {MAX_OID_BYTES} encoded bytes")
    values = []
    current = 0
    continuing = False
    for byte in encoded:
        current = (current << 7) | (byte & 0x7F)
        continuing = bool(byte & 0x80)
        if not continuing:
            values.append(current)
            current = 0
    if continuing:
        raise SNMPError("Truncated object identifier arc")
    first = values.pop(0)
    if first < 40:
        return (0, first, *values)
    if first < 80:
        return (1, first - 40, *values)
    return (2, first - 80, *values)


def _encode_integer(number):
    if number < 0:
        raise ValueError("SNMP request integers cannot be negative")
    encoded = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _tlv(0x02, encoded)


def encode_getnext_request(community, oid, request_id):
    community_bytes = community.encode("utf-8")
    varbind = _tlv(0x30, _tlv(0x06, _encode_oid(oid)) + _tlv(0x05, b""))
    varbind_list = _tlv(0x30, varbind)
    pdu = _tlv(
        0xA1,
        _encode_integer(request_id) + _encode_integer(0) + _encode_integer(0) + varbind_list,
    )
    return _tlv(0x30, _encode_integer(1) + _tlv(0x04, community_bytes) + pdu)


def _decode_integer(encoded, description):
    if not encoded or len(encoded) > 4:
        raise SNMPError(f"Invalid {description}")
    if len(encoded) > 1 and (
        (encoded[0] == 0 and encoded[1] < 0x80)
        or (encoded[0] == 0xFF and encoded[1] >= 0x80)
    ):
        raise SNMPError(f"Non-canonical {description}")
    return int.from_bytes(encoded, "big", signed=True)


def _decode_value(tag, value, max_value_bytes):
    name = VALUE_TYPES.get(tag, f"Unknown(0x{tag:02x})")
    if tag == 0x02:
        return name, _decode_integer(value, name), False
    if tag in (0x41, 0x42, 0x43, 0x46):
        maximum_bytes = 9 if tag == 0x46 else 5
        maximum_value = 0xFFFFFFFFFFFFFFFF if tag == 0x46 else 0xFFFFFFFF
        if not value or len(value) > maximum_bytes:
            raise SNMPError(f"Invalid {name} value")
        if len(value) > 1 and value[0] == 0 and value[1] < 0x80:
            raise SNMPError(f"Non-canonical {name} value")
        number = int.from_bytes(value, "big")
        if number > maximum_value:
            raise SNMPError(f"Invalid {name} value")
        return name, number, False
    if tag in (0x80, 0x81, 0x82):
        return name, None, False
    if tag == 0x05:
        if value:
            raise SNMPError("Invalid NULL value")
        return name, None, False
    if tag == 0x06:
        return name, ".".join(map(str, _decode_oid(value))), False
    truncated = len(value) > max_value_bytes
    value = value[:max_value_bytes]
    if tag == 0x40:
        if len(value) != 4 or truncated:
            raise SNMPError("Invalid IpAddress value")
        return name, ".".join(map(str, value)), False
    if tag in (0x04, 0x44) or tag not in VALUE_TYPES:
        text = value.decode("utf-8", errors="replace")
        if any(not character.isprintable() for character in text):
            rendered = "0x" + value.hex()
        else:
            rendered = text
        if truncated:
            rendered += "…"
        return name, rendered, truncated
    return name, "0x" + value.hex(), truncated


def decode_response(data, expected_community, expected_request_id, max_value_bytes=MAX_VALUE_BYTES):
    tag, message, end = _read_tlv(data)
    if tag != 0x30 or end != len(data):
        raise SNMPError("Malformed SNMP message sequence")
    offset = 0
    version_bytes, offset = _read_expected(message, offset, 0x02, "version")
    version = _decode_integer(version_bytes, "version")
    if version != 1:
        raise SNMPError(f"Unexpected SNMP version {version}; expected SNMPv2c")
    community, offset = _read_expected(message, offset, 0x04, "community")
    if community != expected_community.encode("utf-8"):
        raise SNMPError("Response community does not match request")
    pdu_tag, pdu, offset = _read_tlv(message, offset)
    if offset != len(message) or pdu_tag != 0xA2:
        raise SNMPError("Expected an SNMP GET-RESPONSE PDU")
    pdu_offset = 0
    request_bytes, pdu_offset = _read_expected(pdu, pdu_offset, 0x02, "request ID")
    request_id = _decode_integer(request_bytes, "request ID")
    if request_id != expected_request_id:
        raise SNMPError(f"Response request ID {request_id} does not match request {expected_request_id}")
    status_bytes, pdu_offset = _read_expected(pdu, pdu_offset, 0x02, "error status")
    error_status = _decode_integer(status_bytes, "error status")
    index_bytes, pdu_offset = _read_expected(pdu, pdu_offset, 0x02, "error index")
    error_index = _decode_integer(index_bytes, "error index")
    bindings_bytes, pdu_offset = _read_expected(pdu, pdu_offset, 0x30, "variable bindings")
    if pdu_offset != len(pdu):
        raise SNMPError("Unexpected trailing data in response PDU")
    bindings = []
    bindings_offset = 0
    while bindings_offset < len(bindings_bytes):
        binding_tag, binding, bindings_offset = _read_tlv(bindings_bytes, bindings_offset)
        if binding_tag != 0x30:
            raise SNMPError("Malformed variable binding")
        binding_offset = 0
        oid_bytes, binding_offset = _read_expected(binding, binding_offset, 0x06, "binding OID")
        value_tag, value_bytes, binding_offset = _read_tlv(binding, binding_offset)
        if binding_offset != len(binding):
            raise SNMPError("Unexpected trailing data in variable binding")
        value_type, value, truncated = _decode_value(value_tag, value_bytes, max_value_bytes)
        bindings.append({
            "oid_arcs": _decode_oid(oid_bytes),
            "type": value_type,
            "value": value,
            "value_truncated": truncated,
        })
    if error_status:
        status_name = ERROR_STATUSES.get(error_status, f"unknownError({error_status})")
        raise SNMPError(f"SNMP agent returned {status_name} (error index {error_index})")
    if len(bindings) != 1:
        raise SNMPError(f"Expected one variable binding, received {len(bindings)}")
    return bindings[0]


def validate_host(host):
    if not host or len(host) > 253 or any(character.isspace() for character in host):
        raise ValueError(f"Invalid host: {host!r}")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", host):
            raise ValueError(f"Invalid IPv4 address: {host!r}") from None
        if ":" in host or not re.fullmatch(
            r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*",
            host,
        ):
            raise ValueError(f"Invalid IPv4 address or hostname: {host!r}") from None
    else:
        if address.version != 4:
            raise ValueError("Only IPv4 targets are supported")
    return host


def validate_community(community):
    if not community or "\x00" in community:
        raise ValueError("Community must be non-empty and may not contain NUL")
    if len(community.encode("utf-8")) > MAX_COMMUNITY_BYTES:
        raise ValueError(f"Community exceeds {MAX_COMMUNITY_BYTES} UTF-8 bytes")
    return community


def walk_host(host, port, community, root_oid, timeout, retries, max_rows, socket_factory=socket.socket):
    validate_host(host)
    validate_community(community)
    root = parse_oid(root_oid)
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    if not 0.1 <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"Timeout must be between 0.1 and {MAX_TIMEOUT:g} seconds")
    if not 0 <= retries <= MAX_RETRIES:
        raise ValueError(f"Retries must be between 0 and {MAX_RETRIES}")
    if not 1 <= max_rows <= MAX_ROWS:
        raise ValueError(f"Maximum rows must be between 1 and {MAX_ROWS}")

    rows = []
    current = root
    request_id = 1
    try:
        with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, port))
            deadline = time.monotonic() + MAX_WALK_SECONDS
            while len(rows) < max_rows:
                request = encode_getnext_request(community, current, request_id)
                for attempt in range(retries + 1):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SNMPError(
                            f"SNMP walk exceeded its {MAX_WALK_SECONDS:g}-second deadline"
                        )
                    try:
                        sock.settimeout(min(timeout, remaining))
                        sock.send(request)
                        response = sock.recv(65535)
                        binding = decode_response(response, community, request_id)
                        break
                    except socket.timeout:
                        if attempt == retries:
                            raise SNMPError(
                                f"SNMP request timed out after {retries + 1} attempt(s)"
                            ) from None
                    except OSError as error:
                        raise SNMPError(f"SNMP transport error: {error}") from error

                oid = binding["oid_arcs"]
                if binding["type"] == "EndOfMibView":
                    return {"host": host, "rows": rows, "truncated": False}
                if binding["type"] in ("NoSuchObject", "NoSuchInstance"):
                    raise SNMPError(f"Agent returned {binding['type']} for {'.'.join(map(str, oid))}")
                if oid <= current:
                    raise SNMPError("Agent returned a non-increasing OID; stopping walk")
                if oid[:len(root)] != root:
                    return {"host": host, "rows": rows, "truncated": False}
                rows.append({
                    "oid": ".".join(map(str, oid)),
                    "type": binding["type"],
                    "value": binding["value"],
                    "value_truncated": binding["value_truncated"],
                })
                current = oid
                request_id += 1
    except SNMPError as error:
        error.rows = rows
        raise
    except OSError as error:
        transport_error = SNMPError(f"SNMP transport error: {error}")
        transport_error.rows = rows
        raise transport_error from error
    return {"host": host, "rows": rows, "truncated": True}


def _bounded_int(value, minimum, maximum, label):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{label} must be an integer") from None
    if not minimum <= number <= maximum:
        raise argparse.ArgumentTypeError(f"{label} must be between {minimum} and {maximum}")
    return number


def _timeout_value(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout must be a number") from None
    if not 0.1 <= number <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"timeout must be between 0.1 and {MAX_TIMEOUT:g} seconds")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only, bounded SNMPv2c inventory walk (authorized IPv4 targets only)."
    )
    parser.add_argument("hosts", nargs="+", help="IPv4 addresses or hostnames you are authorized to query")
    parser.add_argument("--community", required=True, help="One authorized SNMPv2c read community; never guessed")
    parser.add_argument("--port", type=lambda v: _bounded_int(v, 1, 65535, "port"), default=161)
    parser.add_argument("--root", default=DEFAULT_ROOT_OID, help=f"Subtree root OID (default: {DEFAULT_ROOT_OID})")
    parser.add_argument("--max-rows", type=lambda v: _bounded_int(v, 1, MAX_ROWS, "max-rows"), default=200)
    parser.add_argument("--timeout", type=_timeout_value, default=2.0, help="Per-request timeout in seconds (0.1-30)")
    parser.add_argument("--retries", type=lambda v: _bounded_int(v, 0, MAX_RETRIES, "retries"), default=1)
    parser.add_argument("--out", help="Write the bounded JSON report to this file instead of stdout")
    args = parser.parse_args(argv)

    try:
        if len(args.hosts) > MAX_HOSTS:
            raise ValueError(f"At most {MAX_HOSTS} hosts may be queried per invocation")
        for host in args.hosts:
            validate_host(host)
        validate_community(args.community)
        parse_oid(args.root)
    except ValueError as error:
        parser.error(str(error))

    results = []
    for host in args.hosts:
        try:
            results.append(walk_host(
                host, args.port, args.community, args.root, args.timeout, args.retries, args.max_rows,
            ))
        except (SNMPError, ValueError) as error:
            rows = getattr(error, "rows", [])
            results.append({
                "host": host,
                "error": str(error),
                "rows": rows,
                "truncated": False,
                "partial": bool(rows),
            })

    report = {
        "protocol": "SNMPv2c",
        "read_only": True,
        "root_oid": ".".join(map(str, parse_oid(args.root))),
        "hosts": results,
    }
    try:
        if args.out:
            with open(args.out, "w", encoding="utf-8") as output:
                json.dump(report, output, indent=2, ensure_ascii=False)
                output.write("\n")
        else:
            json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
            sys.stdout.write("\n")
    except OSError as error:
        print(f"Output error: {error}", file=sys.stderr)
        return 2
    return 1 if any("error" in result for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
