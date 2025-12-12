# PhantomSweep

Fast, async, plugin-based network scanner inspired by Nmap and Masscan. Supports host discovery, TCP/UDP scanning, service/OS detection, scripting, and multiple report formats.

## Key Features

-   Host discovery: ICMP ping, ARP scan (LAN), TCP SYN/ACK ping (firewall-friendly)
-   Port scanning: async TCP Connect, raw TCP SYN (stealth), UDP with ICMP-aware confirmation
-   Detection: service detection (AI model or banner/probe DB), OS fingerprinting (AI model or TTL/window heuristics)
-   Outputs: JSON, XML (Nmap-style), text, CSV; console-first by default
-   Extensible: plugin loader for scanners, analyzers, reporters, and scripts (e.g., HTTP header checker)
-   Performance controls: rate templates (stealthy/balanced/fast/insane), threading, timeouts, basic evasion flags

## Requirements

-   Python 3.9+
-   Linux/macOS recommended; raw socket features need root
-   Optional ML artifacts: place trained models under `phantom_sweep/models/` (see notes below)

### Install

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Default: ICMP ping + TCP connect on top 1000 ports
python phantom.py 192.168.1.1

# CIDR or range input
python phantom.py 192.168.1.0/24
python phantom.py 192.168.1.1-192.168.1.100

# Stealth TCP SYN scan (root) with fast rate
sudo python phantom.py 192.168.1.0/24 --ping-tech tcp --scan-tech stealth --rate fast

# UDP scan on a few ports
sudo python phantom.py 192.168.1.1 --scan-tech udp --port 53,123,161

# Export results
python phantom.py 192.168.1.1 --output json,xml --output-file results
```

## CLI Overview

-   Targets: `HOST [HOST ...]` or `--host-list file`, `--exclude-host ...`; domains are resolved
-   Ports: `--port top_1000|top_100|all|comma|range`, `--port-list file`, `--exclude-port ...` (default value: `top_1000`)
-   Discovery: `--ping-tech icmp|tcp|arp|none`
-   Scanning: `--scan-tech connect|stealth|udp|none`
-   Detection: `--service-detection-mode ai|normal|none`, `--os-fingerprinting-mode ai|normal|none`
-   Scripts: `--script http_headers|all`
-   Performance: `--rate stealthy|balanced|fast|insane`, `--thread N` (default 50), `--timeout SEC` (default 1.0), `--evasion-mode randomize|fragment|decoy|spoof|ai|none`
-   Output: `--output json|xml|text|csv|none`, `--output-file NAME`, `--all-ports` (show closed/filtered too)
-   Helpers: `--verbose`, `--debug`, `--example`, `--version`, `--help`

## What Each Mode Does

-   Host discovery
    -   `icmp` (root): async raw ICMP echo
    -   `arp` (root, LAN only): raw ARP blasts
    -   `tcp` (root): TCP SYN ping across common ports with scapy sniffer
-   Port scanning
    -   `connect`: asyncio TCP connect, no root, service-friendly
    -   `stealth`: raw TCP SYN, Masscan-style batches, root required
    -   `udp`: async UDP with ICMP feedback and service-specific probes (root improves ICMP capture)
-   Detection
    -   Service: `normal` uses probe DB, `ai` uses ML model + banner grab fallback
    -   OS: `normal` uses TTL/window/banner hints; `ai` collects fingerprints then predicts via RandomForest model
-   Reporting
    -   `text`, `json`, `xml` (Nmap-like), `csv`; multiple formats allowed via comma list
-   Scripting
    -   `http_headers`: grabs and scores common HTTP security headers on detected web ports

## Model and Data Notes

-   Place trained files under `phantom_sweep/models/` (see `models/model_info.json` for expected names). Missing models automatically fall back to port/banner heuristics.
-   Service probe DB is auto-searched (e.g., `module/analyzer/service/service_probes.db`); if not found, fallback mapping is used.

## Examples

```bash
# Quiet fast scan with JSON + XML output
python phantom.py 192.168.1.1 --rate fast --output json,xml --output-file scan

# Skip discovery (assume up) and scan all ports via TCP connect
python phantom.py --ping-tech none --scan-tech connect --port all 10.0.0.5

# AI service and OS detection (needs models)
sudo python phantom.py 192.168.1.10 --scan-tech stealth \
  --service-detection-mode ai --os-fingerprinting-mode ai --output json

# Run all scripts against discovered hosts
python phantom.py 192.168.1.0/24 --script all --output text
```

## Output Files

-   `--output json`: machine-readable; embeds scan config metadata
-   `--output xml`: Nmap-style XML; useful for existing parsers
-   `--output text`: human-readable summary; respects `--all-ports`
-   `--output csv`: spreadsheet-friendly rows per host/port
-   Use `--output none` (default) to print to console only

## Project Layout

```
phantom_sweep/
├─ phantom_cli.py          # CLI entrypoint
├─ core/                   # context, result, parsers, port lists
├─ module/
│  ├─ scanner/             # host discovery (icmp/arp/tcp), port scans (connect/stealth/udp)
│  ├─ analyzer/            # service (ai/normal) and os (ai/normal)
│  ├─ reporter/            # json, xml, text, csv exporters
│  └─ scripting/           # http_headers demo script
├─ models/                 # optional ML artifacts
└─ utils/                  # warning suppression, helpers
```

## Running as Root

-   Required for raw ICMP, ARP, TCP SYN ping/scan, and best-accuracy UDP (ICMP sniffing)
-   Without root, stick to `--scan-tech connect` and `--ping-tech none|icmp` (if permitted by OS)

## Troubleshooting

-   Permission errors: rerun with `sudo` for raw socket modes
-   No hosts up: try `--ping-tech none` if ICMP/TCP ping is filtered
-   Slow scans: increase `--thread`, raise `--rate`, or reduce port set
-   Service/OS detection empty: ensure models/DB exist; otherwise fallback heuristics apply

## Legal

Use only on systems you own or have explicit permission to test. You are responsible for complying with applicable laws and policies.

## Credits

Built by Group 10 (NT140). Inspired by Nmap and Masscan.
