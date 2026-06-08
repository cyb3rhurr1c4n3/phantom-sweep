<div align="center">

# 👻 PhantomSweep

### _A Fast, Lightweight, Scalable & Intelligent Network Security Scanner_

[![Python Version](https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/) [![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](https://claude.ai/chat/LICENSE) [![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-lightgrey?style=for-the-badge)](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff) [![Status](https://img.shields.io/badge/status-v1.0-brightgreen?style=for-the-badge)](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff)

**[Overview](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff#-overview)** • **[Features](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff#-features)** • **[Installation](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff#-installation)** • **[Usage](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff#-usage)** • **[Architecture](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff#-architecture)** • **[Roadmap](https://claude.ai/chat/44b2cf66-527e-4f9b-9774-3351324defff#-roadmap)**

</div>

---

## 📋 Overview

**PhantomSweep** is a Python-based network security scanner built for authorized penetration testing and security research. It combines asynchronous raw socket scanning with a plugin-based architecture and ML-powered OS fingerprinting.

The project was built as an exercise in understanding low-level network scanning mechanics - from raw packet crafting to service detection - while exploring how machine learning can augment traditional fingerprinting techniques.

> **Legal Notice**: PhantomSweep is intended for use on networks and systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 📽️ Demo

### 1. Scan with default options

[![1 - Scan with default options](https://img.youtube.com/vi/MlOuMnwanFk/0.jpg)](https://youtu.be/MlOuMnwanFk)

### 2. Fast Host Discovery with ICMP

[![2 - Fast Host Discovery with ICMP](https://img.youtube.com/vi/FfvUZ23XMDk/0.jpg)](https://youtu.be/FfvUZ23XMDk)

### 3. Fast Host Discovery with ARP

[![3 - Fast Host Discovery with ARP](https://img.youtube.com/vi/A0-Q_FAZ6YU/0.jpg)](https://youtu.be/A0-Q_FAZ6YU)

### 4. Scan with top 100 ports

[![4 - Scan with top 100 ports](https://img.youtube.com/vi/KD0ZVbn_OiI/0.jpg)](https://youtu.be/KD0ZVbn_OiI)

### 5. AI-powered OS Fingerprinting feature

[![5 - AI-powered OS Fingerprinting feature](https://img.youtube.com/vi/9t9Vw3xWcO8/0.jpg)](https://youtu.be/9t9Vw3xWcO8)

### 6. Scanning with Custom Extension Scripts

[![6 - Scanning with Custom Extension Scripts](https://img.youtube.com/vi/xUTByvm7PZY/0.jpg)](https://youtu.be/xUTByvm7PZY)

---

## ✨ Features

### Host Discovery

| Technique    | Scope             | Notes                         |
| ------------ | ----------------- | ----------------------------- |
| ARP Scan     | LAN only          | Fastest, no IP stack overhead |
| ICMP Ping    | WAN-friendly      | Standard echo request/reply   |
| TCP SYN Ping | Firewall-friendly | Useful when ICMP is filtered  |

### Port Scanning

| Technique         | Stealth | Speed      | Reliability |
| ----------------- | ------- | ---------- | ----------- |
| TCP Connect       | ❌      | ⭐⭐⭐⭐   | ⭐⭐⭐⭐⭐  |
| TCP SYN (Stealth) | ✅      | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐    |
| UDP Scan          | ❌      | ⭐⭐⭐     | ⭐⭐⭐      |

### Analysis

- **Service & Version Detection** - Banner grabbing with probe matching
- **AI OS Fingerprinting** - Scikit-learn classifier trained on Nmap OS database features
- **Extension Scripts** - HTTP security headers checker; scriptable framework for custom checks

### Output Formats

- `JSON`
- `CSV`
- `XML` (Nmap-compatible)
- `Plain Text`

### Evasion & Performance

- Packet fragmentation, decoy generation, randomized scan order
- Configurable timing profiles: `stealthy` / `balanced` / `fast` / `insane`
- Adjustable thread count and per-probe timeout

---

## 📦 Installation

**Requirements**: Python 3.10+, Linux or WSL2, root/sudo privileges (required for raw sockets)

```bash
git clone https://github.com/cyb3rhurr1c4n3/phantom-sweep.git
cd phantom-sweep
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo python phantom.py --help
```

<details> <summary><b>Dependencies</b></summary>

| Library          | Purpose                                   |
| ---------------- | ----------------------------------------- |
| `scapy`          | Packet crafting and raw socket operations |
| `scikit-learn`   | ML model for OS fingerprinting            |
| `numpy`          | Feature vector processing                 |
| `joblib`         | Model serialization and parallel jobs     |
| `requests`       | HTTP probing for extension scripts        |
| `beautifulsoup4` | HTML parsing in scripts                   |
| `paramiko`       | SSH banner grabbing                       |
| `colorama`       | Terminal color output                     |
| `pyfiglet`       | Banner rendering                          |

</details>

---

## 📖 Usage

```
sudo python phantom.py [TARGET] [OPTIONS]
```

### Common Examples

```bash
# Default scan (ICMP discovery + TCP Connect, top 1000 ports)
sudo python phantom.py scanme.nmap.org

# Host discovery only
sudo python phantom.py 192.168.1.0/24 --ping-tech icmp --scan-tech none

# Stealth SYN scan on specific ports
sudo python phantom.py 10.0.0.1 --scan-tech stealth --port 22,80,443,8080

# Service detection + AI OS fingerprinting
sudo python phantom.py scanme.nmap.org --service-detection-mode normal --os-fingerprinting-mode ai

# Run extension script
sudo python phantom.py scanme.nmap.org --script http_headers

# Export results
sudo python phantom.py scanme.nmap.org --output json --output-file results
```

### Key Options

| Option                     | Values                                           | Default    | Description               |
| -------------------------- | ------------------------------------------------ | ---------- | ------------------------- |
| `--ping-tech`              | `arp`, `icmp`, `tcp`, `none`                     | `icmp`     | Host discovery technique  |
| `--scan-tech`              | `connect`, `stealth`, `udp`, `none`              | `connect`  | Port scan method          |
| `--port`                   | `top_100`, `top_1000`, `all`, `80,443`, `1-1000` | `top_1000` | Port specification        |
| `--service-detection-mode` | `normal`, `none`                                 | `none`     | Service/version detection |
| `--os-fingerprinting-mode` | `ai`, `normal`, `none`                           | `none`     | OS fingerprinting         |
| `--rate`                   | `stealthy`, `balanced`, `fast`, `insane`         | `balanced` | Timing profile            |
| `--thread`                 | integer                                          | `10`       | Concurrent workers        |
| `--evasion-mode`           | `randomize`, `fragment`, `decoy`                 | `none`     | Evasion techniques        |
| `--output`                 | `json`, `csv`, `xml`, `text`                     | `none`     | Export format             |

<details> <summary><b>Full option reference</b></summary>

```
usage: phantom [--version] [--help] [--example]
               [--host-list FILENAME] [--exclude-host HOST [HOST ...]]
               [--port PORT] [--port-list FILENAME] [--exclude-port PORT [PORT ...]]
               [--ping-tech {arp,icmp,tcp,tcp-ping-scapy,none}]
               [--scan-tech {connect,stealth,udp,none}]
               [--service-detection-mode {normal,none}]
               [--os-fingerprinting-mode {ai,normal,none}]
               [--script SCRIPT [SCRIPT ...]]
               [--rate {stealthy,balanced,fast,insane}]
               [--thread NUM] [--timeout SECONDS]
               [--evasion-mode TECHNIQUE [TECHNIQUE ...]]
               [--output {csv,json,text,xml,none}] [--output-file FILENAME]
               [--verbose] [--debug] [--all-ports]
               [HOST ...]
```

</details>

### Sample JSON Output

```json
{
	"hosts": {
		"45.33.32.156": {
			"host": "45.33.32.156",
			"state": "up",
			"os": null,
			"os_version": "unknown",
			"tcp_ports": {
				"22": {
					"port": 22,
					"state": "open",
					"service": "ssh",
					"version": null,
					"banner": null
				},
				"80": {
					"port": 80,
					"state": "open",
					"service": "http",
					"version": null,
					"banner": null
				},
				"9929": {
					"port": 9929,
					"state": "open",
					"service": null,
					"version": null,
					"banner": null
				}
			},
			"udp_ports": {},
			"scripts": {}
		}
	},
	"statistics": {
		"total_hosts": 1,
		"up_hosts": 1,
		"total_ports_scanned": 1000,
		"open_ports": 4
	},
	"metadata": {
		"scan_start_time": "2025-12-24T12:08:55.171810",
		"scan_end_time": "2025-12-24T12:08:56.615795",
		"scan_duration": 1.443985
	}
}
```

---

## 🏗️ Architecture

```
phantom-sweep/
├── core/
│   ├── context.py          # Scan state management
│   ├── constants.py        # Global constants
│   ├── parsers.py          # Input parsing (targets, ports)
│   └── result.py           # Result data structures
├── model/                  # ML models and supporting assets
├── module/
│   ├── manager.py          # Plugin loader & scan pipeline
│   ├── _base/              # Abstract base classes
│   ├── scanner/
│   │   ├── discovery/      # ARP, ICMP, TCP SYN ping
│   │   └── port/           # TCP Connect, TCP SYN, UDP
│   ├── analyzer/
│   │   ├── os_detection/   # AI and TTL/window-based fingerprinting
│   │   └── service/        # Banner grabbing, probe matching
│   ├── reporter/           # CSV, JSON, XML, Text exporters
│   └── scripting/          # Extension scripts (http_headers, ...)
└── phantom_cli.py          # CLI entry point
```

**Design principles:**

- **Sender/Receiver separation** - prevents timeout blocking during high-rate scans
- **Generator-based processing** - constant memory footprint regardless of target range size
- **Plugin architecture** - scanners, analyzers, reporters, and scripts are dynamically loaded; new modules require no changes to core

---

## 📊 Performance

Tested against `scanme.nmap.org` on a standard home connection (100 Mbps, i5-13500H):

| Config                                   | PhantomSweep | Nmap equivalent |
| ---------------------------------------- | ------------ | --------------- |
| Top 1000 ports, ICMP + Connect, balanced | ~1.5s        | T3: ~3–5s       |
| Top 1000 ports, ICMP + Connect, fast     | ~0.8s        | T4: ~1–2s       |
| Top 1000 ports, SYN stealth, insane      | ~0.5s        | T5: ~0.5–1s     |

> Results vary significantly by network conditions and target responsiveness. These figures reflect single-host scans and should not be extrapolated to large subnet scanning without independent testing.

---

## 🗺️ Roadmap

### v1.1

- [ ] AI-powered adaptive evasion (RL-based timing selection)
- [ ] SSL/TLS validation script
- [ ] Benchmark suite for reproducible performance testing

### v1.2

- [ ] IPv6 support
- [ ] Custom vulnerability check scripts
- [ ] Nmap NSE-compatible script interface

### Long-term

- [ ] Web UI for scan management and result visualization
- [ ] gRPC API for integration with other tooling

---

## ⚖️ License & Disclaimer

Released under the **MIT License**. See [LICENSE](LICENSE) for details.

**Disclaimer**: This tool is intended solely for authorized security testing and educational purposes. The authors assume no liability for misuse or for any damages resulting from use of this software. Users are solely responsible for complying with applicable laws.

---

<div align="center">

**PhantomSweep** - Built by [Cyber_Threat Group](https://github.com/cyb3rhurr1c4n3) · UIT, Vietnam · 2025

</div>
