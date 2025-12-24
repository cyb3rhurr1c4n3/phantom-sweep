<div align="center">

# 👻 PhantomSweep

### _A Fast, Lightweight, Scalable & Intelligent Network Security Scanner_

[![Python Version](https://img.shields.io/badge/python-3.13.9+-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/cyb3rhurr1c4n3/phantom-sweep)

**[Features](#-các-tính-năng)** •
**[Installation](#-yêu-cầu--cài-đặt)** •
**[Usage](#-hướng-dẫn-sử-dụng)** •
**[Architecture](#-kiến-trúc-hệ-thống)** •
**[Team](#-thành-viên-dự-án)**

</div>

---

## 📋 Tổng Quan

> **PhantomSweep** là một công cụ quét mạng (network security scanner) được thiết kế cho mục đích **giáo dục** và **kiểm thử bảo mật hợp pháp** (authorized penetration testing). Dự án kết hợp hiệu suất cao của Masscan, tính linh hoạt của Nmap và sức mạnh của **Trí tuệ Nhân tạo (AI)**, mang đến một giải pháp quét mạng thế hệ mới.

### ✨ Đặc điểm Chính

<table>
<tr>
<td width="50%">

#### ⚡ Siêu Tốc

-   AsyncIO + Raw Sockets
-   Architecture Sender-Receiver riêng biệt

</td>
<td width="50%">

#### 💾 Siêu Nhẹ

-   Tối ưu bộ nhớ với Generators
-   Minimal dependencies

</td>
</tr>
<tr>
<td width="50%">

#### 🔌 Dễ Mở Rộng

-   Plugin-based architecture
-   Dynamic module loading

</td>
<td width="50%">

#### 🤖 Thông Minh

-   AI-powered OS fingerprinting
-   Evasion with AI

</td>
</tr>
</table>

---

## 🎯 Mục Tiêu Dự Án

Xây dựng một công cụ **quét mạng chuyên nghiệp** kết hợp:

```
┌─────────────────────────────────────────────────────────────────┐
│  1️⃣  Hiệu suất cao      → Tiệm cận Masscan                     │
│  2️⃣  Tính linh hoạt     → Cấu hình như Nmap                     │
│  3️⃣  Kiến trúc mở rộng  → Plugin system                        │
│  4️⃣  Khả năng AI        → Tích hợp các tính năng AI             │
└─────────────────────────────────────────────────────────────────┘
```

### 👥 Đối Tượng Người Dùng

<div align="center">

|         👨‍💼         |        🔒        |          🛡️           |           👨‍🎓           |
| :----------------: | :--------------: | :-------------------: | :--------------------: |
| **Network Admins** |  **Pentesters**  |    **Red Teamers**    | **Security Students**  |
|   Quản trị mạng    | Kiểm thử bảo mật | Đội tấn công mô phỏng | Sinh viên an ninh mạng |

</div>

---

## 🏗️ 4 Trụ Cột Công Nghệ

### 1️⃣ **Fast** — _Siêu Tốc_ ⚡

<details open>
<summary><b>Các Kỹ Thuật Tối Ưu</b></summary>

-   🔥 **AsyncIO + Raw Sockets**: Loại bỏ overhead hệ điều hành
-   🔄 **Sender-Receiver Architecture**: Hai luồng riêng biệt, tránh block timeout
-   📦 **Pre-computed Packet Templates**: Giảm chi phí tạo gói tin
-   ⚙️ **Batch Processing**: Xử lý hàng loạt hiệu quả
-   ⏱️ **Smart Timeout**: Tối ưu thời gian chờ dựa trên phản hồi

</details>

> 📊 **Kết quả**: Ngang hàng và nhỉnh hơn T5 Nmap trong nhiều kịch bản mà còn chính xác hơn

### 2️⃣ **Lightweight** — _Siêu Nhẹ_ 💾

<details open>
<summary><b>Chiến Lược Tối Ưu Bộ Nhớ</b></summary>

-   🔄 **Generator-based Processing**: Xử lý triệu IP mà không tràn RAM
-   📚 **Minimal Dependencies**: Chỉ dùng thư viện cần thiết
-   🎯 **Core-focused**: Tập trung vào tính năng chính
-   🗂️ **Optimized Data Structures**: Sử dụng cấu trúc dữ liệu hiệu quả

</details>

> 📊 **Kết quả**: Kích thước khiêm tốn dù đã tích hợp AI

### 3️⃣ **Scalable** — _Dễ Mở Rộng_ 🔌

<details open>
<summary><b>Kiến Trúc Module</b></summary>

-   🧩 **Plugin Architecture**: Thêm scanner, analyzer, reporter, script mà không sửa core
-   🔄 **Dynamic Module Loading**: Tự động phát hiện và tải module
-   🎨 **Module Base Classes**: Interface rõ ràng để implement modules
-   🔒 **Separation of Concerns**: Mỗi module độc lập, dễ test

</details>

> 📊 **Kết quả**: Cộng đồng dễ dàng đóng góp plugins mới

### 4️⃣ **Smart** — _Thông Minh_ 🤖

<details open>
<summary><b>Tính Năng AI/ML</b></summary>

-   🧠 **AI OS Fingerprinting**: Nhận dạng hệ điều hành bằng ML models
-   🎯 **AI Evasion Techniques**: Lựa chọn chiến thuật Evasion tự động bằng RL

</details>

> 📊 **Kết quả**: Nhận diện OS với độ chính xác cao, lẫn tránh IDS/IPS tốt

---

## ✨ Các Tính Năng

### 🔍 Host Discovery — _Trinh Sát Host_

| Kỹ Thuật         | Tốc Độ     | Độ Chính Xác | Phạm Vi           |
| ---------------- | ---------- | ------------ | ----------------- |
| **ARP Scan**     | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐   | LAN only          |
| **ICMP Ping**    | ⭐⭐⭐⭐   | ⭐⭐⭐⭐     | WAN-friendly      |
| **TCP SYN Ping** | ⭐⭐⭐     | ⭐⭐⭐⭐     | Firewall-friendly |

### 🔌 Port Scanning — _Quét Cổng_

| Kỹ Thuật              | Stealth | Tốc Độ     | Độ Tin Cậy |
| --------------------- | ------- | ---------- | ---------- |
| **TCP Connect**       | ❌      | ⭐⭐⭐⭐   | ⭐⭐⭐⭐⭐ |
| **TCP SYN (Stealth)** | ✅      | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐   |
| **UDP Scan**          | ❌      | ⭐⭐⭐     | ⭐⭐⭐     |

### 🔬 Service & Version Detection — _Phát Hiện Dịch Vụ_

-   ✅ **Normal Mode**: Banner grabbing, service probe matching
-   📊 **Precision**: Tỷ lệ phát hiện chính xác ~ Nmap

### 🖥️ OS Fingerprinting — _Nhận Dạng Hệ Điều Hành_

-   🤖 **AI Mode**: Deep learning models trên Nmap OS database
-   📈 **Coverage**: Nhận dạng OS với độ chính xác cao ~ Nmap

### 🥷 Evasion Techniques — _Kỹ Thuật Né Tránh_

<table>
<tr><td>📦 Packet fragmentation</td><td>🎭 Idle zombies scan</td></tr>
<tr><td>🎯 Decoy generation</td><td>⏱️ Custom timing profiles</td></tr>
<tr><td colspan="2" align="center">🔀 User-agent spoofing</td></tr>
</table>

### 📄 Output Formats — _Định Dạng Xuất_

|   Format    | Description                | Use Case                      |
| :---------: | -------------------------- | ----------------------------- |
| **CSV** 📊  | Comma-separated values     | Import vào Excel/Spreadsheets |
| **JSON** 🔧 | JavaScript Object Notation | Parse programmatically        |
| **XML** 📝  | Extensible Markup Language | Tương thích Nmap parsers      |
| **Text** 📄 | Plain text                 | Human-readable reports        |

### 🔧 Extension Scripts — _Scripts Mở Rộng_

-   ✅ HTTP Security Headers checker
-   ⏳ SSL/TLS validation _(not implemented yet)_
-   ⏳ Custom vulnerability checks _(not implemented yet)_

---

## 📦 Yêu Cầu & Cài Đặt

### ⚙️ Yêu Cầu Hệ Thống

<table>
<tr>
<td><b>🐍 Python</b></td>
<td>3.10 trở lên (recommend 3.13+)</td>
</tr>
<tr>
<td><b>💻 OS</b></td>
<td>Linux (Windows cần WSL2)</td>
</tr>
<tr>
<td><b>🔐 Quyền</b></td>
<td>Root/sudo (để sử dụng raw sockets, khuyến khích trong mọi trường hợp)</td>
</tr>
</table>

### 🚀 Cài Đặt

**Bước 1: Clone Repository**

```bash
# Clone từ GitHub
git clone https://github.com/cyb3rhurr1c4n3/phantom-sweep.git
cd phantom-sweep
```

**Bước 2: Tạo Virtual Environment**

```bash
# Tạo và kích hoạt virtual environment
python3 -m venv .venv
source .venv/bin/activate
```

**Bước 3: Cài Dependencies**

```bash
# Cài đặt các thư viện cần thiết
pip install -r requirements.txt
```

**Bước 4: Verify Installation**

```bash
# Kiểm tra cài đặt thành công
sudo python phantom.py --help
```

### 📚 Dependencies

<details>
<summary><b>Danh Sách Thư Viện</b></summary>

| Library          | Purpose                 | Version |
| ---------------- | ----------------------- | :-----: |
| `colorama`       | Colored terminal output | Latest  |
| `pyfiglet`       | ASCII art banners       | Latest  |
| `scapy`          | Packet manipulation     | Latest  |
| `paramiko`       | SSH operations          | Latest  |
| `requests`       | HTTP requests           | Latest  |
| `beautifulsoup4` | HTML parsing            | Latest  |
| `joblib`         | Parallel processing     | Latest  |
| `numpy`          | Numerical computing     | Latest  |
| `scikit-learn`   | Machine learning models | Latest  |

</details>

---

## 📖 Hướng Dẫn Sử Dụng

--> Note cho team: bổ sung video demo vào đây

### 💻 Cú Pháp Cơ Bản

```bash
┌─────────────────────────────────────────────┐
│  sudo python phantom.py [TARGET] [OPTIONS]  │
└─────────────────────────────────────────────┘
```

### 🎯 Ví Dụ Thông Dụng và Demo

#### **Example 1** — Super Fast Discovery & Scanning (ICMP + TCP Connect) - Default

```bash
sudo python phantom.py scanme.nmap.org
```

https://github.com/user-attachments/assets/2398e2c1-0fe3-4b56-b36e-a16edad448ba

#### **Example 2** — Fast Host Discovery (ICMP)

```bash
sudo python phantom.py scanme.nmap.org --ping-tech icmp --scan-tech none
```

https://github.com/user-attachments/assets/66e971e4-6476-4a05-9153-8769d47ef727

#### **Example 3** — Fast Host Discovery (ARP)

```bash
sudo python phantom.py scanme.nmap.org --ping-tech arp --scan-tech none
```

#### **Example 4** — Quét 100 Port Phổ Biến Nhất

```bash
sudo python phantom.py scanme.nmap.org --port top_100  
```

https://github.com/user-attachments/assets/59be7b48-7e0c-4bab-b0f3-4ff6f9942bb7

#### **Example 5** — Service & Version Detection

```bash
sudo python phantom.py scanme.nmap.org --service-detection-mode normal
```

https://github.com/user-attachments/assets/3f4810c6-a1e9-44bd-92ad-394ba4edd107

#### **Example 6** — AI OS Fingerprinting

```bash
sudo python phantom.py scanme.nmap.org --os-fingerprinting-mode ai
```

https://github.com/user-attachments/assets/1034ef43-259e-4017-ab64-97f24944afbf

#### **Example 7** — Custom Extension Scripts

```bash
sudo python phantom.py scanme.nmap.org --script http_headers
```

https://github.com/user-attachments/assets/bfbad2f6-3f2e-4d5d-8101-9d2be1b8a368

#### **Example 8** — Xuất Kết Quả Ra File

```bash
sudo python phantom.py scanme.nmap.org --output json --output-file json_result
sudo python phantom.py scanme.nmap.org --output csv --output-file csv_result
```

Đầu ra JSON ví dụ:

```json
{
  "hosts": {
    "45.33.32.156": {
      "host": "45.33.32.156",
      "state": "up",
      "os": null,
      "os_version": "unknown",
      "os_accuracy": null,
      "tcp_ports": {
        "26": {
          "port": 26,
          "state": "closed",
          "service": null,
          "version": null,
          "banner": null
        },
        "99": {
          "port": 99,
          "state": "closed",
          "service": null,
          "version": null,
          "banner": null
        },
        "8002": {
          "port": 8002,
          "state": "closed",
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
    "scan_duration": 1.443985,
    "scan_config": {
      "targets": {
        "hosts": [
          "45.33.32.156"
        ],
        "host_count": 1,
        "exclude_hosts": []
      },
      "ports": {
        "port_spec": "top_1000",
        "port_list_file": null,
        "exclude_ports": null
      },
      "pipeline": {
        "ping_tech": "icmp",
        "scan_tech": "connect",
        "service_detection_mode": "none",
        "os_fingerprinting_mode": "none",
        "scripts": []
      },
      "performance": {
        "rate": "balanced",
        "thread": 50,
        "timeout": 1.0,
        "evasion_mode": []
      }
    }
  }
}
```

Đầu ra CSV ví dụ:

```
45.33.32.156,up,,unknown,,80,TCP,open,,,
,,,,,22,TCP,open,,,
,,,,,31337,TCP,open,,,
,,,,,9929,TCP,open,,,
```

#### **Example 9** — AI Evasion Techniques

--> Note cho team: Bổ sung

#### **Example 10** — Tùy Chỉnh Performance

```bash
sudo python phantom.py scanme.nmap.org --rate insane --thread 100 --timeout 10
```

### ⚙️ Các Tùy Chọn Chính

<details>
<summary><b>📋 Full Command Options (Click to expand)</b></summary>

```
usage: phantom [--version] [--help] [--example] [--host-list FILENAME] [--exclude-host HOST [HOST ...]] [--port PORT]
               [--port-list FILENAME] [--exclude-port PORT [PORT ...]] [--ping-tech {arp,icmp,tcp,tcp-ping-scapy,none}]
               [--scan-tech {connect,stealth,udp,none}] [--service-detection-mode {ai,normal,none}]
               [--os-fingerprinting-mode {ai,normal,none}] [--script SCRIPT [SCRIPT ...]] [--rate {stealthy,balanced,fast,insane}]
               [--thread NUM] [--timeout SECONDS] [--evasion-mode TECHNIQUE [TECHNIQUE ...]] [--output {csv,json,text,xml,none}]
               [--output-file FILENAME] [--verbose] [--debug] [--all-ports]
               [HOST ...]

PhantomSweep - A fast, lightweight, scalable and smart network security scanner

:#################### GENERAL ####################:
  Some general options

  --version             Show program's version number and exit
  --help                Show this help message and exit
  --example             Show detailed examples

:#################### HOST SPECIFICATION ####################:
  Specify hosts to scan. At least one host source is required.

  HOST                  Target host(s) to scan. Can be:
                                    - Single IP: 192.168.1.1
                                    - Multiple IPs: 192.168.1.1 192.168.1.2
                                    - IP range: 192.168.1.1-100 or 192.168.1.1-192.168.1.100
                                    - CIDR block: 192.168.1.0/24
                                    - Domain name: scanme.nmap.org
  --host-list FILENAME  Read targets from file (one per line). Required if HOST is not specified.
  --exclude-host HOST [HOST ...]
                        Exclude HOST(s) from scan. Same format as --host.

:#################### PORT SPECIFICATION ####################:
  Specify which ports to scan.

  --port PORT           Port(s) to scan (default: top_100). Can be:
                                    - top_100: Scan 100 most common ports
                                    - top_1000: Scan 1000 most common ports
                                    - all: Scan all 65535 ports
                                    - Specific: 80,443,8080
                                    - Range: 1-1000
                                    - Combined: 80,443,1000-2000
  --port-list FILENAME  Read port from file (one per line).
  --exclude-port PORT [PORT ...]
                        Exclude port(s) from scan. Same format as --port.

:#################### SCAN PINELINE ####################:
  Configure which technique to use, which step is enable or disable, bla bla

  --ping-tech {arp,icmp,tcp,tcp-ping-scapy,none}
                        Host discovery technique (default: icmp):
                                    - arp: ARP Scan (Ultra-fast, local network only)
                                    - icmp: ICMP Echo Request (Ping) Discovery
                                    - tcp-ping-scapy: TCP SYN Ping (Scapy-based, easier, slower)
                                    - tcp: TCP SYN Ping Discovery (fast, firewall-friendly) - FIXED
                                    - none: Skip discovery (assume all hosts are up)
  --scan-tech {connect,stealth,udp,none}
                        Port scanning technique (default: connect):
                                    - connect: TCP Connect Scan (async, fast, service-compatible)
                                    - stealth: TCP SYN Scan (stealth scan, ultra-fast)
                                    - udp: UDP Scan (async, ICMP-aware, service probes)
                                    - none: Skip port scanning
  --service-detection-mode {ai,normal,none}
                        Service detection mode (default: none):
                                    - ai: AI-powered service and version detection
                                    - normal: Banner-based detection
                                    - none: Disable service detection
  --os-fingerprinting-mode {ai,normal,none}
                        OS fingerprinting mode (default: none):
                                    - ai: AI-powered OS detection
                                    - normal: TTL/Window size-based detection
                                    - none: Disable OS fingerprinting
  --script SCRIPT [SCRIPT ...]
                        Run one or more extension scripts:
                                    - http_headers: Check HTTP headers for web services
                                    - all: Run all available scripts

:#################### PERFORMANCE AND EVASION ####################:
  Control scan speed and evasion techniques.

  --rate {stealthy,balanced,fast,insane}
                        Scan rate/timing template (default: balanced):
                                    - stealthy: Slow, AI-adaptive timing (evade IDS/IPS)
                                    - balanced: Balanced speed and accuracy (Nmap T3-like)
                                    - fast: Fast scan (Nmap T4-like)
                                    - insane: Maximum speed (Masscan-like)
  --thread NUM          Number of concurrent thread/workers (default: 10). Higher = faster but more resource usage.
  --timeout SECONDS     Timeout in seconds for each probe (default: 5.0). AI may auto-adjust if --rate stealthy.
  --evasion-mode TECHNIQUE [TECHNIQUE ...]
                        Evasion techniques (can combine multiple):
                                    - randomize: Randomize host and port order
                                    - fragment: Fragment packets
                                    - decoy: Use decoy IPs
                                    - spoof: Spoof source IP
                                    - ai: AI-powered adaptive evasion
                                    - none: No evasion (default)


:#################### OUTPUT FORMAT ####################:
  Specify how your output should be format.

  --output {csv,json,text,xml,none}
                        Export to file format (default: none):
                                    - csv: CSV format (spreadsheet-compatible)
                                    - json: JSON format (machine-readable)
                                    - text: Human-readable text format
                                    - xml: Nmap-compatible XML format
                                    - none: only print to screen
  --output-file FILENAME
                        Save output to file. If not specified, results are printed to console.

:#################### MISCELLANEOUS ####################:
  --verbose             Increase verbosity level (show detailed progress and information)
  --debug               Enable debug mode (show detailed error messages and stack traces)
  --all-ports           Show all port states (closed, filtered, open) in results
```

</details>

### 📚 Quick References

```bash
# Xem tất cả options
sudo python phantom.py --help

# Xem ví dụ sử dụng
sudo python phantom.py --example
```

---

## 🏗️ Kiến Trúc Hệ Thống

### 📂 System Architecture

```plaintext
📦 PhantomSweep/
├── Core Engine (core/)
│  ├── Scan Context      - Quản lý trạng thái quét
│  ├── Constants         - Hằng số toàn cục
│  ├── Parsers           - Parse dữ liệu đầu vào
│  └── Scan Result       - Cấu trúc dữ liệu kết quả
│
|── AI Model (model/)    - Các model AI và tài nguyên hỗ trợ
|
├── Module System (module/)
│  ├── Manager           - Plugin loader và quản lý scanpipeline
│  ├── Base (_base/)     - Các base class hỗ trợ tính chất Scalable
│  ├── Scanner           - Các kỹ thuật quét
│  │  ├── Host Discovery
│  │  │  ├── ARP Scan
│  │  │  ├── ICMP Ping
│  │  │  └── TCP SYN Ping
│  │  └── Port Scanning
│  │     ├── TCP Connect
│  │     ├── TCP SYN
│  │     └── UDP Scan
│  ├── Analyzer          - Phân tích kết quả
│  │  ├── OS Detection   (AI)
│  │  └── Service Detect (Normal)
│  ├── Reporter          - Xuất báo cáo
│  │  ├── CSV, JSON, XML, Text
│  └── Scripting         - Custom scripts
│      └── HTTP Headers Check
│
└── CLI Interface (phantom_cli.py)
```

---

## 👥 Thành Viên Dự Án

<div align="center">

### 🎓 Cyber_Threat Group - UIT

_Dự án được thực hiện bởi 4 thành viên sinh viên_  
_Trường Đại học Công nghệ Thông tin, ĐHQG TP.HCM_

</div>

### 📊 Phân Công Công Việc

| Thành Viên            | Đóng góp (%) | Đóng Góp Chính |
| --------------------- | ------------ | -------------- |
| Hà Sơn Bin            |              |                |
| Võ Quốc Bảo           |              |                |
| Nguyễn Đoàn Gia Khánh |              |                |
| Lê Quốc Khôi          |              |                |

---

## 📈 Tính Năng Hoàn Thành

### ✅ Phase 1: Core Features

-   [x] CLI Framework & Help System
-   [x] ARP Scan
-   [x] ICMP Ping Discovery
-   [x] TCP SYN Ping
-   [x] TCP Connect Scan
-   [x] UDP Scan
-   [x] Basic Service Detection
-   [x] Output Formats (JSON, CSV, XML, Text)

### ✅ Phase 2: Advanced Features

-   [x] AI OS Fingerprinting
-   [x] Service Detection (Normal & AI modes)
-   [x] Evasion Timing Templates
-   [x] Custom Scripting Framework
-   [x] HTTP Headers Check Script
-   [x] Plugin Architecture & Dynamic Loading

### ✅ Phase 3: Optimization & Polish

-   [x] Performance Tuning
-   [x] Memory Optimization (Generators)
-   [x] Comprehensive Error Handling
-   [x] Full Documentation
-   [x] Code Comments & Docstrings

---

## 🤝 Đóng Góp

> 💡 Chúng tôi hoan nghênh mọi đóng góp từ cộng đồng!

### 📝 Cách Đóng Góp

1. Fork dự án
2. Tạo Feature Branch: `git checkout -b feature/AmazingFeature`
3. Commit thay đổi: `git commit -m 'Add AmazingFeature'`
4. Push lên branch: `git push origin feature/AmazingFeature`
5. Mở Pull Request

---

## 📜 Giấy Phép & Tuyên Bố Miễn Trừ

### ⚖️ Giấy Phép

Dự án này được phát hành dưới giấy phép **MIT License**.

```
MIT License

Copyright (c) 2024 Cyber_Threat Group - UIT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

### ⚠️ Tuyên Bố Miễn Trừ

**CẢNH BÁO**: PhantomSweep là công cụ được thiết kế cho mục đích **giáo dục** và **kiểm thử bảo mật được ủy quyền** (authorized penetration testing).

**Trách nhiệm pháp lý**:

1. **Chỉ sử dụng trên các hệ thống được ủy quyền**: Bất kỳ hoạt động quét mạng trái phép vào hệ thống không được phép là bất hợp pháp theo pháp luật.

2. **Không chịu trách nhiệm**: Tác giả và những người đóng góp không chịu trách nhiệm cho:

    - Bất kỳ hành vi sử dụng sai trái nào
    - Thiệt hại do công cụ gây ra
    - Vi phạm pháp luật của người dùng

3. **Tuân thủ pháp luật**: Người dùng phải tuân thủ các luật pháp địa phương về:

    - Kiểm thử bảo mật
    - Bảo vệ dữ liệu cá nhân
    - Quyền riêng tư

4. **Sử dụng có trách nhiệm**:
    - Luôn lấy sự cho phép bằng văn bản trước khi quét
    - Giữ bí mật thông tin phát hiện được
    - Báo cáo lỗ hổng một cách có trách nhiệm (responsible disclosure)

---

## 🎓 Thông Tin Đồ Án

<div align="center">

| 📌 Thông Tin   | 📝 Chi Tiết                         |
| -------------- | ----------------------------------- |
| **Môn Học**    | NT140 - An toàn mạng                |
| **Trường**     | Đại học Công nghệ Thông tin (UIT)   |
| **Đại học**    | Đại học Quốc gia TP.HCM             |
| **Năm Học**    | 2024                                |
| **Nhóm**       | Cyber_Threat Group (4 thành viên)   |
| **Giảng viên** | Trần Tuấn Dũng (thầy Dũng đẹp trai) |

</div>

---

## 📞 Liên Hệ & Hỗ Trợ

<div align="center">

|      Channel       | Link                                                                               |
| :----------------: | ---------------------------------------------------------------------------------- |
|   🐛 **Issues**    | [Báo cáo bugs](https://github.com/cyb3rhurr1c4n3/phantom-sweep/issues)             |
| 💬 **Discussions** | [Thảo luận tính năng](https://github.com/cyb3rhurr1c4n3/phantom-sweep/discussions) |
|    📧 **Email**    | 23520146@gm.uit.edu.vn (Võ Quốc Bảo - Leader)                                      |

</div>

---

<div align="center">

### 💙 Made with Love

**Developed with ❤️ by Cyber_Threat Group - UIT**

_Last Updated: December 2024_

⭐ _If you find this project useful, please consider giving it a star!_ ⭐

</div>
