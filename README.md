# IBM MQ Info Tool

`mqinfo.py` is a small Python 3 probe for identifying IBM MQ listeners on a target host.

It connects to the target, checks the standard IBM MQ listener ports by default, sends an IBM MQ-style probe when no passive banner is returned, and parses the response into readable metadata.

## Features

- Checks the default IBM MQ TCP ports `1414` through `1419`
- Accepts `-p` / `--port` to probe a single port
- Accepts `--socks` to connect through a SOCKS5 proxy
- Accepts `-d` / `--debug` to print raw response data and extracted strings
- Parses common IBM MQ response fields such as channel, queue manager, version, and build marker
- Shows built-in help with the tool banner when run without arguments

## Requirements

- Python 3
- Network access to the target host and target port(s)

No third-party Python packages are required.

## Usage

Show help:

```bash
python3 mqinfo.py
python3 mqinfo.py --help
```

Probe the default IBM MQ ports:

```bash
python3 mqinfo.py 192.0.2.10
```

Probe a single port:

```bash
python3 mqinfo.py 192.0.2.10 -p 1414
```

Probe through a SOCKS5 proxy:

```bash
python3 mqinfo.py 192.0.2.10 --socks 127.0.0.1:1080
python3 mqinfo.py 192.0.2.10 -p 1414 --socks socks5://127.0.0.1:1080
```

Enable verbose debug output:

```bash
python3 mqinfo.py 192.0.2.10 -d
python3 mqinfo.py 192.0.2.10 -p 1414 -d
```

## Output

Normal mode prints parsed fields only.

Typical parsed fields:

- `header`: MQ transport header marker, usually `TSH`
- `declared_length`: Response length declared in the MQ packet
- `channel`: Listener channel name returned by the target
- `queue_manager`: Queue manager identifier parsed from the response
- `ccsid`: MQ character set identifier from the reply
- `heartbeat_interval`: Negotiated MQ heartbeat interval
- `product_id`: MQ product/version identifier prefix
- `build_marker`: Raw IBM MQ build/version marker, shown as an anonymized placeholder in examples
- `version`: Parsed MQ version
- `build_id`: Build token extracted from the build marker
- `queue_manager_id`: MQ queue manager identifier from the reply

Example:

```text
IBM MQ Info Tool v0.2.2

[+] Probing 192.0.2.10:1414
    open
    parsed:
      - header: TSH
      - declared_length: 236
      - channel: <channel-name>
      - queue_manager: <queue-manager>
      - build_marker: MQMV<version><queue-manager>.<build-id>
      - version: <mq-version>
      - build_id: <build-id>
```

Debug mode additionally prints:

- whether the response was passive or triggered by the MQ probe
- raw response hex
- extracted ASCII strings
- extracted EBCDIC strings
- a simple IBM MQ detection hint

## Notes

- IBM MQ usually does not send a banner immediately after connection, so the script sends an active MQ-style probe when needed.
- The probe logic is modeled after Nmap service-detection behavior for `ibm-mqseries`.
- A positive response indicates an IBM MQ-compatible listener, but it does not imply that authenticated client access is allowed.

## Limitations

- This tool is intended for identification and metadata extraction, not full IBM MQ administration.
- It does not perform authenticated MQ operations.
- Some MQ listeners may return responses that are only partially parsed.
