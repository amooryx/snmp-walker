#!/usr/bin/env python3
"""
SNMP Walker — SNMP v1/v2c Community String Brute-Forcer & MIB Walker
Tests for default/weak community strings and dumps SNMP MIB data.
Author: Omar Khalid (amooryx) | github.com/amooryx/snmp-walker
AUTHORIZED USE ONLY.
"""

import argparse
import json
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor

COMMON_COMMUNITIES = [
    "public", "private", "community", "manager", "admin",
    "monitor", "snmp", "cisco", "default", "1234", "secret",
    "read", "write", "guest", "network", "backup",
]

# ─── Minimal SNMP v2c GET-NEXT (pure stdlib) ──────────────────────────────────
def encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.strip(".").split(".")]
    first = parts[0] * 40 + parts[1]
    encoded = bytes([first])
    for v in parts[2:]:
        if v < 128:
            encoded += bytes([v])
        else:
            b = []
            while v:
                b.append(v & 0x7F)
                v >>= 7
            b.reverse()
            for i, byte in enumerate(b):
                encoded += bytes([byte | (0x80 if i < len(b) - 1 else 0)])
    return encoded

def snmp_get_request(community: str, oid: str = "1.3.6.1.2.1.1.1.0") -> bytes:
    comm_bytes = community.encode()
    oid_bytes  = encode_oid(oid)
    oid_tlv    = b"\x06" + bytes([len(oid_bytes)]) + oid_bytes
    null_tlv   = b"\x05\x00"
    varbind    = b"\x30" + bytes([len(oid_tlv) + len(null_tlv)]) + oid_tlv + null_tlv
    varbindlist = b"\x30" + bytes([len(varbind)]) + varbind
    req_id     = b"\x02\x04\x00\x00\x00\x01"
    err_status = b"\x02\x01\x00"
    err_index  = b"\x02\x01\x00"
    pdu_data   = req_id + err_status + err_index + varbindlist
    pdu        = b"\xa0" + bytes([len(pdu_data)]) + pdu_data
    community_tlv = b"\x04" + bytes([len(comm_bytes)]) + comm_bytes
    version_tlv   = b"\x02\x01\x01"  # v2c
    msg_data       = version_tlv + community_tlv + pdu
    return b"\x30" + bytes([len(msg_data)]) + msg_data

def snmp_probe(host: str, port: int, community: str, timeout: float = 3) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt  = snmp_get_request(community)
        sock.sendto(pkt, (host, port))
        data = sock.recv(1024)
        sock.close()
        if data and len(data) > 10:
            return {"host": host, "community": community, "bytes_received": len(data)}
    except socket.timeout:
        pass
    except Exception:
        pass
    return None

def brute_communities(host: str, port: int, communities: list[str], threads: int,
                      timeout: float) -> list[dict]:
    hits = []
    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {exe.submit(snmp_probe, host, port, c, timeout): c for c in communities}
        for fut in futures:
            r = fut.result()
            if r:
                hits.append(r)
                print(f"  [!!!] Valid community: '{r['community']}' on {host}:{port}")
    return hits

def main():
    parser = argparse.ArgumentParser(
        description="SNMP Walker — SNMP Community Brute Force & MIB Walk (Authorized use only)",
    )
    parser.add_argument("hosts",       nargs="+", help="Target hosts")
    parser.add_argument("--port",      type=int, default=161)
    parser.add_argument("--wordlist",  help="Community strings file (one per line)")
    parser.add_argument("--threads",   type=int, default=20)
    parser.add_argument("--timeout",   type=float, default=3)
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    communities = COMMON_COMMUNITIES
    if args.wordlist:
        with open(args.wordlist) as f:
            communities = [l.strip() for l in f if l.strip()]

    print(f"[*] SNMP community brute: {len(args.hosts)} hosts × {len(communities)} strings")
    all_hits = []
    for host in args.hosts:
        hits = brute_communities(host, args.port, communities, args.threads, args.timeout)
        all_hits.extend(hits)

    print(f"\n[*] {len(all_hits)} valid community strings found")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(all_hits, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
