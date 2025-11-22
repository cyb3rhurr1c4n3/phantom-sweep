# PhantomSweep

A fast, lightweight, scalable and smart network security scanner inspired by Nmap & Masscan.

## Features

- **Host Discovery**: ICMP Echo, TCP SYN/ACK ping, ARP scan
- **Port Scanning**: TCP SYN (stealth), TCP Connect, UDP scan
- **High Performance**: Async raw socket architecture (Masscan-style) with sender/receiver threads
- **Flexible Port Specification**: Support for top_100, top_1000, all ports, ranges, and custom lists
- **Rate Limiting**: Configurable scan speeds (stealthy, balanced, fast, insane)
- **Extensible Architecture**: Plugin-based system for easy extension

## Installation

### Requirements

- Python 3.9+
- Root privileges (for raw socket operations like TCP SYN and UDP scans)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `scapy` - Packet manipulation and network scanning
- `colorama` - Colored terminal output
- `pyfiglet` - ASCII banner

## Usage

### Basic Usage

```bash
# Scan a single host with default settings (ICMP ping + TCP Connect scan on top 100 ports)
python phantom.py 192.168.1.1

# Scan multiple hosts
python phantom.py 192.168.1.1 192.168.1.2 192.168.1.3

# Scan a CIDR network
python phantom.py 192.168.1.0/24

# Scan an IP range
python phantom.py 192.168.1.1-100
```

### Host Discovery Options

```bash
# ICMP ping (default, no root required on most systems)
python phantom.py --ping-tech icmp 192.168.1.1

# TCP SYN/ACK ping (requires root)
sudo python phantom.py --ping-tech tcp 192.168.1.1

# ARP scan (local network only, requires root)
sudo python phantom.py --ping-tech arp 192.168.1.0/24

# Skip host discovery, assume all hosts are up
python phantom.py --ping-tech none 192.168.1.1
```

### Port Scanning Options

```bash
# TCP Connect scan (default, no root required)
python phantom.py --scan-tech connect 192.168.1.1

# TCP SYN scan (stealth scan, requires root, faster)
sudo python phantom.py --scan-tech stealth 192.168.1.1

# UDP scan (requires root)
sudo python phantom.py --scan-tech udp 192.168.1.1
```

### Port Specification

```bash
# Scan top 100 most common ports (default)
python phantom.py 192.168.1.1 --port top_100

# Scan top 1000 most common ports
python phantom.py 192.168.1.1 --port top_1000

# Scan all 65535 ports
python phantom.py 192.168.1.1 --port all

# Scan specific ports
python phantom.py 192.168.1.1 --port 80,443,8080

# Scan port range
python phantom.py 192.168.1.1 --port 1-1000

# Combined format
python phantom.py 192.168.1.1 --port 80,443,1000-2000

# Read ports from file (one port per line)
python phantom.py 192.168.1.1 --port-list ports.txt

# Exclude ports
python phantom.py 192.168.1.1 --port top_1000 --exclude-port 22,23
```

### Performance Tuning

```bash
# Stealthy scan (slow, AI-adaptive timing to evade IDS/IPS)
python phantom.py --rate stealthy 192.168.1.1

# Balanced scan (default, Nmap T3-like)
python phantom.py --rate balanced 192.168.1.1

# Fast scan (Nmap T4-like)
python phantom.py --rate fast 192.168.1.1

# Insane speed (Masscan-like)
python phantom.py --rate insane 192.168.1.1

# Custom thread count
python phantom.py --thread 50 192.168.1.1

# Custom timeout (seconds)
python phantom.py --timeout 2.0 192.168.1.1
```

### Output Options

```bash
# Verbose output (show detailed progress)
python phantom.py --verbose 192.168.1.1

# Debug mode (show detailed errors and stack traces)
python phantom.py --debug 192.168.1.1

# Save output to file
python phantom.py 192.168.1.1 --output json --output-file results.json
python phantom.py 192.168.1.1 --output xml --output-file results.xml
python phantom.py 192.168.1.1 --output text --output-file results.txt
python phantom.py 192.168.1.1 --output csv --output-file results.csv

# Multiple output formats
python phantom.py 192.168.1.1 --output json,xml --output-file results
```

### Advanced Examples

```bash
# Complete scan: TCP SYN ping + TCP SYN scan on top 1000 ports, fast rate
sudo python phantom.py --ping-tech tcp --scan-tech stealth --port top_1000 --rate fast 192.168.1.0/24

# Scan specific ports on multiple hosts with verbose output
python phantom.py --port 22,80,443,3306,8080 --verbose 192.168.1.1 192.168.1.2 192.168.1.3

# UDP scan on common UDP ports
sudo python phantom.py --scan-tech udp --port 53,123,161,500,4500 192.168.1.1

# Skip discovery and scan all ports (useful for firewalled hosts)
python phantom.py --ping-tech none --port all --scan-tech connect 192.168.1.1
```

## Architecture

PhantomSweep uses a modular, plugin-based architecture:

```
phantom_sweep/
├── core/              # Core data structures (ScanContext, ScanResult)
├── module/
│   ├── _base/         # Base classes for plugins
│   ├── scanner/       # Scanner plugins (host discovery, port scanning)
│   ├── analyzer/      # Analyzer plugins (service detection, OS fingerprinting)
│   ├── reporter/      # Reporter plugins (output formats)
│   └── scripting/     # Scripting plugins (exploits, custom scripts)
└── phantom_cli.py     # CLI interface
```

### Scanner Architecture

Each scanner uses an async sender/receiver architecture:

- **Sender Thread**: Rapidly sends probe packets without waiting for responses
- **Receiver Thread**: Independently listens for responses and processes results
- **Rate Limiting**: Configurable packet-per-second limits based on scan speed

This architecture allows for high-speed scanning similar to Masscan while maintaining accuracy.

## Command Line Options

### General Options
- `--version`: Show version number
- `--help`: Show help message
- `--example`: Show detailed examples
- `--verbose`: Increase verbosity
- `--debug`: Enable debug mode

### Target Specification
- `HOST [HOST ...]`: Target host(s) (required, unless using --host-list)
- `--host-list FILENAME`: Read targets from file
- `--exclude-host IP [IP ...]`: Exclude IP(s) from scan

### Port Specification
- `--port PORT`: Port specification (default: top_100)
- `--port-list FILENAME`: Read ports from file
- `--exclude-port PORT [PORT ...]`: Exclude port(s) from scan

### Scan Pipeline
- `--ping-tech {icmp,tcp,arp,none}`: Host discovery technique (default: icmp)
- `--scan-tech {connect,stealth,udp}`: Port scanning technique (default: connect)
- `--service-detection-mode {ai,normal,off}`: Service detection mode (default: ai)
- `--os-fingerprinting-mode {ai,normal,off}`: OS fingerprinting mode (default: ai)
- `--script SCRIPT [SCRIPT ...]`: Run extension scripts

### Performance and Evasion
- `--rate {stealthy,balanced,fast,insane}`: Scan rate/timing template (default: balanced)
- `--thread NUM`: Number of concurrent threads (default: 10)
- `--timeout SECONDS`: Timeout per probe in seconds (default: 1.0)
- `--evasion-mode TECHNIQUE [TECHNIQUE ...]`: Evasion techniques

### Output Format
- `--output FORMAT`: Output format (none, text, json, xml, csv, or comma-separated)
- `--output-file FILENAME`: Save output to file

## Root Requirements

Some scan types require root privileges:

- **TCP SYN scan** (`--scan-tech stealth`): Requires root for raw sockets
- **UDP scan** (`--scan-tech udp`): Requires root for raw sockets
- **TCP ping** (`--ping-tech tcp`): Requires root for raw sockets
- **ARP scan** (`--ping-tech arp`): Requires root for layer 2 access

If root is not available, PhantomSweep will automatically fall back to TCP Connect scan (no root required).

## Examples

### Example 1: Quick Scan
```bash
python phantom.py 192.168.1.1
```
Scans 192.168.1.1 with ICMP ping and TCP Connect scan on top 100 ports.

### Example 2: Stealth Scan
```bash
sudo python phantom.py --ping-tech tcp --scan-tech stealth --port top_1000 --rate fast 192.168.1.0/24
```
Fast stealth scan of entire /24 network using TCP SYN ping and TCP SYN port scan.

### Example 3: Comprehensive Scan
```bash
sudo python phantom.py \
  --ping-tech icmp \
  --scan-tech stealth \
  --port all \
  --rate balanced \
  --verbose \
  --output json,xml \
  --output-file scan_results \
  192.168.1.1
```
Comprehensive scan with all ports, multiple output formats, and verbose logging.

## Troubleshooting

### "Permission denied" errors
- Use `sudo` for scans requiring root (TCP SYN, UDP, ARP)
- Or use `--scan-tech connect` which doesn't require root

### Hosts showing as "down" but ports are open
- Host may be blocking ping but accepting connections
- Use `--ping-tech none` to skip host discovery

### Slow scanning
- Increase `--thread` count
- Use `--rate fast` or `--rate insane`
- Reduce `--port` range or use `top_100` instead of `all`

### No results found
- Check network connectivity
- Verify target is reachable
- Try `--ping-tech none` to skip discovery
- Use `--verbose` or `--debug` for more information

## Legal Disclaimer

Usage of PhantomSweep for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to comply with all applicable laws. Developers assume no liability for misuse or damage caused by this tool.

## License

[Add your license here]

## Authors

Group 10

## Acknowledgments

Inspired by Nmap and Masscan.
