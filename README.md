# PhantomSweep

A fast, lightweight, scalable and smart network security scanner inspired by Nmap & Masscan.

## Features

-   **Host Discovery**: ICMP Echo, TCP SYN/ACK ping, ARP scan
-   **Port Scanning**: TCP SYN (stealth), TCP Connect, UDP scan
-   **Service Detection**: AI-powered and banner-based service/version detection
-   **OS Fingerprinting**: AI-powered and TTL-based OS detection
-   **High Performance**: Async raw socket architecture (Masscan-style) with sender/receiver threads
-   **Flexible Port Specification**: Support for top_100, top_1000, all ports, ranges, and custom lists
-   **Rate Limiting**: Configurable scan speeds (stealthy, balanced, fast, insane)
-   **Multiple Output Formats**: JSON, XML, Text, and CSV output
-   **Extensible Architecture**: Plugin-based system for easy extension
-   **AI-powered Evasion**: Adaptive evasion techniques to evade IDS/IPS systems

## Installation

### Requirements

-   Python 3.9+
-   Root privileges (required for advanced scanning techniques: TCP SYN, UDP scan, ARP scan, TCP ping)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:

-   `scapy` - Packet manipulation and network scanning
-   `colorama` - Colored terminal output
-   `pyfiglet` - ASCII banner
-   `numpy` - Numerical computing (used in AI models)
-   `scikit-learn` - Machine learning library (for OS and service detection)
-   `joblib` - Serialization library (for model persistence)
-   `requests` - HTTP library (for service detection)
-   `beautifulsoup4` - HTML/XML parsing (for banner analysis)
-   `paramiko` - SSH library (for advanced scripting)

## Usage

### Scan Pipeline

```bash
# Scan a single host with default settings (ICMP ping + TCP Connect scan on top 1000 ports)
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
# Scan top 1000 most common ports (default)
python phantom.py 192.168.1.1 --port top_1000

# Scan top 100 most common ports
python phantom.py 192.168.1.1 --port top_100

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

# Custom thread count (default: 50)
python phantom.py --thread 100 192.168.1.1

# Custom timeout (default: 1.0 seconds)
python phantom.py --timeout 2.0 192.168.1.1

# Combined: fast scan with custom threads
python phantom.py --rate fast --thread 100 --timeout 0.5 192.168.1.1
```

### Service Detection and OS Fingerprinting

```bash
# Enable AI-powered service detection
python phantom.py --service-detection-mode ai 192.168.1.1

# Enable normal (banner-based) service detection
python phantom.py --service-detection-mode normal 192.168.1.1

# Disable service detection (default)
python phantom.py --service-detection-mode off 192.168.1.1

# Enable AI-powered OS fingerprinting
python phantom.py --os-fingerprinting-mode ai 192.168.1.1

# Enable normal (TTL-based) OS fingerprinting
python phantom.py --os-fingerprinting-mode normal 192.168.1.1

# Disable OS fingerprinting (default)
python phantom.py --os-fingerprinting-mode off 192.168.1.1

# Combined: AI detection for both service and OS
python phantom.py --service-detection-mode ai --os-fingerprinting-mode ai 192.168.1.1
```

### Output Options

```bash
# Verbose output (show detailed progress)
python phantom.py --verbose 192.168.1.1

# Debug mode (show detailed errors and stack traces)
python phantom.py --debug 192.168.1.1

# Save output to JSON file
python phantom.py --output json --output-file results.json 192.168.1.1

# Save output to XML file
python phantom.py --output xml --output-file results.xml 192.168.1.1

# Save output to text file
python phantom.py --output text --output-file results.txt 192.168.1.1

# Multiple output formats
python phantom.py --output json,xml --output-file results 192.168.1.1

# Only print to console (no file output)
python phantom.py --output none 192.168.1.1
```

### Advanced Examples

```bash
# Complete scan: TCP SYN ping + TCP SYN scan on top 1000 ports, fast rate
sudo python phantom.py --ping-tech tcp --scan-tech stealth --port top_1000 --rate fast 192.168.1.0/24

# Scan specific ports on multiple hosts with verbose output
python phantom.py --port 22,80,443,3306,8080 --verbose 192.168.1.1 192.168.1.2 192.168.1.3

# UDP scan on common UDP ports with root privileges
sudo python phantom.py --scan-tech udp --port 53,123,161,500,4500 192.168.1.1

# Skip discovery and scan all ports (useful for firewalled hosts)
python phantom.py --ping-tech none --port all --scan-tech connect 192.168.1.1

# AI-powered comprehensive scan with multiple output formats
sudo python phantom.py \
  --ping-tech tcp \
  --scan-tech stealth \
  --port top_1000 \
  --service-detection-mode ai \
  --os-fingerprinting-mode ai \
  --rate fast \
  --verbose \
  --output json,xml \
  --output-file scan_results \
  192.168.1.0/24
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

-   **Sender Thread**: Rapidly sends probe packets without waiting for responses
-   **Receiver Thread**: Independently listens for responses and processes results
-   **Rate Limiting**: Configurable packet-per-second limits based on scan speed

This architecture allows for high-speed scanning similar to Masscan while maintaining accuracy.

## Command Line Options

### General Options

-   `--version`: Show version number and exit
-   `--help`: Show help message and exit
-   `--example`: Show detailed command examples
-   `--verbose`: Increase verbosity level
-   `--debug`: Enable debug mode with detailed error messages

### Target Specification

-   `HOST [HOST ...]`: Target host(s) to scan (can be IP, IP range, CIDR, or domain name)
-   `--host-list FILENAME`: Read targets from file (one per line)
-   `--exclude-host IP [IP ...]`: Exclude specific IP(s) from scan

### Port Specification (Default: top_1000)

-   `--port PORT`: Port specification (top_100, top_1000, all, specific, range, or combined)
-   `--port-list FILENAME`: Read ports from file (one port per line)
-   `--exclude-port PORT [PORT ...]`: Exclude specific port(s) from scan

### Scan Pipeline Configuration

-   `--ping-tech {icmp,tcp,arp,none}`: Host discovery technique (default: icmp)
-   `--scan-tech {connect,stealth,udp}`: Port scanning technique (default: connect)
-   `--service-detection-mode {ai,normal,off}`: Service detection mode (default: off)
-   `--os-fingerprinting-mode {ai,normal,off}`: OS fingerprinting mode (default: off)
-   `--script SCRIPT [SCRIPT ...]`: Run extension scripts

### Performance and Evasion (Default rate: balanced)

-   `--rate {stealthy,balanced,fast,insane}`: Scan rate/timing template
-   `--thread NUM`: Number of concurrent threads (default: 50)
-   `--timeout SECONDS`: Timeout per probe in seconds (default: 1.0)
-   `--evasion-mode TECHNIQUE [TECHNIQUE ...]`: Evasion techniques (randomize, fragment, decoy, spoof, ai, none)

### Output Format (Default: none)

-   `--output FORMAT`: Output format (none, text, json, xml, or comma-separated)
-   `--output-file FILENAME`: Save output to file

## Root Requirements

Some scan types require root privileges due to raw socket operations:

-   **TCP SYN scan** (`--scan-tech stealth`): Requires root for raw socket access
-   **UDP scan** (`--scan-tech udp`): Requires root for raw socket access
-   **TCP ping** (`--ping-tech tcp`): Requires root for raw socket access
-   **ARP scan** (`--ping-tech arp`): Requires root for layer 2 access

If root is not available, PhantomSweep will automatically fall back to TCP Connect scan (no root required).

Run commands with `sudo` when using these techniques:

```bash
sudo python phantom.py --scan-tech stealth 192.168.1.1
```

## Examples

### Example 1: Quick Scan

```bash
python phantom.py 192.168.1.1
```

Scans 192.168.1.1 with ICMP ping and TCP Connect scan on top 1000 ports (default settings).

### Example 2: Stealth Scan

```bash
sudo python phantom.py --ping-tech tcp --scan-tech stealth --port top_1000 --rate fast 192.168.1.0/24
```

Fast stealth scan of entire /24 network using TCP SYN ping and TCP SYN port scan.

### Example 3: Service and OS Detection

```bash
sudo python phantom.py \
  --ping-tech tcp \
  --scan-tech stealth \
  --port top_1000 \
  --service-detection-mode ai \
  --os-fingerprinting-mode ai \
  192.168.1.1
```

Scans target with AI-powered service and OS detection.

### Example 4: Comprehensive Scan with Multiple Outputs

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

-   Use `sudo` for scans requiring root (TCP SYN, UDP, ARP, TCP ping)
-   Alternative: Use `--scan-tech connect` which doesn't require root

### Hosts showing as "down" but ports are open

-   Host may be blocking ping packets but accepting connections
-   Solution: Use `--ping-tech none` to skip host discovery and scan all targets

### Slow scanning

-   Increase `--thread` count (default: 50, try 100-200 for faster machines)
-   Use `--rate fast` or `--rate insane` instead of balanced/stealthy
-   Reduce port range or use `--port top_100` instead of `--port all`

### No results found

-   Check network connectivity to target
-   Verify target is reachable using ping or other tools
-   Try `--ping-tech none` to skip discovery and force scanning
-   Use `--verbose` or `--debug` for detailed error information

### High CPU/Memory usage

-   Reduce `--thread` count (increase CPU usage per thread, reduce concurrency)
-   Use larger `--timeout` value to reduce retries
-   Scan fewer ports using `--port top_100` instead of `--port all`

### Service detection not working

-   Ensure `--service-detection-mode` is set to `ai` or `normal` (default: off)
-   For AI mode, ensure scikit-learn and numpy are installed: `pip install scikit-learn numpy`
-   Check if target services are actually responding to probes

## Project Structure

PhantomSweep uses a modular, plugin-based architecture:

```
phantom_sweep/
├── core/              # Core data structures and parsers
│   ├── constants.py   # Configuration and port lists
│   ├── parsers.py     # Target and port parsing
│   ├── scan_context.py # Scan configuration container
│   └── scan_result.py  # Result data structure
├── module/
│   ├── _base/         # Base classes for plugins
│   │   ├── scanner_base.py
│   │   ├── analyzer_base.py
│   │   ├── reporter_base.py
│   │   └── scripting_base.py
│   ├── scanner/       # Scanner plugins
│   │   ├── host_discovery/  # ICMP, TCP, ARP ping
│   │   └── port_scanning/   # TCP Connect, SYN, UDP scans
│   ├── analyzer/      # Analysis plugins
│   │   ├── service/   # Service detection (AI & normal)
│   │   └── os/        # OS fingerprinting (AI & normal)
│   ├── reporter/      # Output format plugins
│   │   ├── json_reporter.py
│   │   ├── xml_reporter.py
│   │   └── text_reporter.py
│   └── scripting/     # Custom script plugins
├── utils/             # Utility functions
└── phantom_cli.py     # CLI interface
```

## Performance Characteristics

-   **Sender/Receiver Architecture**: Decoupled packet transmission and response handling for optimal throughput
-   **AI-Powered Optimization**: Adaptive timing and evasion for intelligent scanning
-   **Masscan-Style Scanning**: Raw socket-based high-speed scanning when available
-   **Scalability**: Configurable threading to handle networks from single hosts to large subnets

## Legal Disclaimer

Usage of PhantomSweep for attacking targets without prior mutual consent is **illegal**. It is the end user's responsibility to comply with all applicable laws and regulations. Developers assume no liability for misuse, unauthorized access, or damage caused by this tool.

This tool is intended for:

-   Authorized penetration testing and security assessments
-   Network administration and monitoring on networks you own or have permission to test
-   Security research and educational purposes
-   Legitimate cybersecurity operations

## License

[Add your license here]

## Contributing

Group 10 - NT140 Project

## Acknowledgments

Inspired by Nmap and Masscan - leading open-source network scanning tools.
