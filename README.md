<div align="center">
  <img src="./banner.svg" alt="snmp-walker" width="800">
</div>

# snmp-walker

A small, read-only SNMP inventory walker for systems you are authorized to
query. It uses only Python's standard library and SNMPv2c GET-NEXT requests.
It does not guess community strings, try credential lists, send SNMP SET
requests, or modify target devices.

## Requirements

- Python 3.8 or newer (tested with Python 3.11).
- No third-party Python dependencies.
- SNMPv2c enabled on the target with a community string you were explicitly
  given. SNMPv2c community strings are transmitted without encryption; use an
  appropriately isolated management network and a read-only community.

## Usage

```bash
python snmp_walker.py --community '<authorized-read-community>' 192.0.2.10
```

The default subtree is MIB-II (`1.3.6.1.2.1`). Choose a narrower subtree and
save the JSON report when appropriate:

```bash
python snmp_walker.py --community '<authorized-read-community>' \
  --root 1.3.6.1.2.1.1 --max-rows 100 --timeout 2 --retries 1 \
  --out inventory.json 192.0.2.10
```

The report identifies the protocol, requested subtree, each host's rows, and
whether the row limit stopped a walk. Each row contains the numeric OID, BER
value type, decoded value, and a flag if an OCTET STRING or other textual value
was truncated. Transport, malformed-response, SNMP-agent, and output-file
errors are reported; any host failure makes the command exit nonzero.

## Safety and limits

- Only a caller-supplied community string is used. There is no default
  community, wordlist, discovery scan, parallel probing, write operation, or
  SNMPv1/v3 support.
- Targets must be IPv4 addresses or hostnames. DNS resolution follows the
  machine's resolver configuration. IPv6 is not supported.
- The per-request timeout defaults to 2 seconds and is limited to 0.1–30
  seconds. Retries default to 1 and are limited to 0–5 (timeouts only).
- Each host's SNMP walk also has a 5-minute total deadline. Hostname resolution
  uses the operating system resolver and occurs before that SNMP deadline.
- The walk defaults to at most 200 rows per host; `--max-rows` is capped at
  500. Each returned text/binary value is bounded to 256 bytes before JSON
  rendering, and response datagrams are read with a 65,535-byte ceiling.
- At most 32 hosts may be queried per invocation. Walks stop when the agent
  returns an OID outside the selected subtree or when the row limit is
  reached. A limit-reached result is marked `truncated: true`. Rows already
  collected are retained if a later request fails.
- The tool reports numeric OIDs without MIB name resolution. SNMPv2c
  authorization and privacy limitations still apply; only use it against
  systems for which you have explicit permission.

## Offline tests

Run the tests without network access or third-party packages:

```bash
python -m unittest discover -s tests -v
```

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
