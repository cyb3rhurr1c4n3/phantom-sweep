# 👻 PhantomSweep

**A Fast, Lightweight, Scalable & Intelligent Network Security Scanner**

![Python Version](https://img.shields.io/badge/python-3.13.9+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

---

## 📋 Tổng Quan

**PhantomSweep** là một công cụ quét mạng (network security scanner) được thiết kế cho mục đích **giáo dục** và **kiểm thử bảo mật hợp pháp** (authorized penetration testing). Dự án kết hợp hiệu suất cao của Masscan, tính linh hoạt của Nmap và sức mạnh của **Trí tuệ Nhân tạo (AI)**, mang đến một giải pháp quét mạng thế hệ mới.

### Đặc điểm Chính

-   ⚡ **Siêu tốc**: AsyncIO + Raw Sockets, architecture Sender-Receiver riêng biệt
-   💾 **Siêu nhẹ**: Tối ưu bộ nhớ với Generators, minimal dependencies
-   🔌 **Dễ mở rộng**: Plugin-based architecture, dynamic module loading
-   🤖 **Thông minh**: AI-powered OS fingerprinting, Evasion with AI

---

## 🎯 Mục Tiêu Dự Án

Xây dựng một công cụ **quét mạng chuyên nghiệp** kết hợp:

1. **Hiệu suất cao** - Tốc độ ngang ngửa Masscan trong nhiều kịch bản
2. **Tính linh hoạt** - Cấu hình linh hoạt như Nmap
3. **Kiến trúc mở rộng** - Dễ dàng thêm tính năng mới qua plugin system
4. **Khả năng AI** - Phát hiện OS, dịch vụ và kỹ thuật evasion thông minh

**Đối tượng người dùng**:

-   👨‍💼 Quản trị viên mạng
-   🔒 Penetration Testers
-   🛡️ Red Teamers
-   👨‍🎓 CyberSec Student
-   ...

---

## 🏗️ 4 Trụ Cột Công Nghệ

### 1️⃣ **Fast (Siêu Tốc)**

-   **AsyncIO + Raw Sockets**: Loại bỏ overhead hệ điều hành
-   **Sender-Receiver Architecture**: Hai luồng riên biệt, tránh block timeout
-   **Pre-computed Packet Templates**: Giảm chi phí tạo gói tin
-   **Batch Processing**: Xử lý hàng loạt hiệu quả
-   **Smart Timeout**: Tối ưu thời gian chờ dựa trên phản hồi

**📊 Kết quả**: Ngang hàng và nhỉnh hơn T5 Nmap trong nhiều kịch bản mà còn chính xác hơn

### 2️⃣ **Lightweight (Siêu Nhẹ)**

-   **Generator-based Processing**: Xử lý triệu IP mà không tràn RAM
-   **Minimal Dependencies**: Chỉ dùng thư viện cần thiết
-   **Core-focused**: Tập trung vào tính năng chính
-   **Optimized Data Structures**: Sử dụng cấu trúc dữ liệu hiệu quả

**📊 Kết quả**: Kích thước khiêm tốn dù đã tích hợp AI

### 3️⃣ **Scalable (Dễ Mở Rộng)**

-   **Plugin Architecture**: Thêm scanner, analyzer, reporter, script mà không sửa core
-   **Dynamic Module Loading**: Tự động phát hiện và tải module
-   **Module Base Classes**: Interface rõ ràng để implement modules
-   **Separation of Concerns**: Mỗi module độc lập, dễ test

**📊 Kết quả**: Cộng đồng dễ dàng đóng góp plugins mới

### 4️⃣ **Smart (Thông Minh)**

-   **AI OS Fingerprinting**: Nhận dạng hệ điều hành bằng ML models
-   **AI Evasion Techniques**: Lựa chọn chiến thuật Evasion tự động bằng RL

**📊 Kết quả**: Nhận diện OS với độ chính xác cao, lẫn tránh IDS/IPS tốt

---

## ✨ Các Tính Năng

### Host Discovery (Trinh Sát Host)

| Kỹ Thuật         | Tốc Độ     | Độ Chính Xác | Phạm Vi           |
| ---------------- | ---------- | ------------ | ----------------- |
| **ARP Scan**     | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐   | LAN only          |
| **ICMP Ping**    | ⭐⭐⭐⭐   | ⭐⭐⭐⭐     | WAN-friendly      |
| **TCP SYN Ping** | ⭐⭐⭐     | ⭐⭐⭐⭐     | Firewall-friendly |

### Port Scanning (Quét Cổng)

| Kỹ Thuật              | Stealth | Tốc Độ     | Độ Tin Cậy |
| --------------------- | ------- | ---------- | ---------- |
| **TCP Connect**       | ❌      | ⭐⭐⭐⭐   | ⭐⭐⭐⭐⭐ |
| **TCP SYN (Stealth)** | ✅      | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐   |
| **UDP Scan**          | ❌      | ⭐⭐⭐     | ⭐⭐⭐     |

### Service & Version Detection

-   **Normal Mode**: Banner grabbing, service probe matching
-   **Precision**: Tỷ lệ phát hiện chính xác ~ Nmap

### OS Fingerprinting

-   **AI Mode**: Deep learning models trên Nmap OS database
-   **Coverage**: Nhận dạng OS với độ chính xác cao ~ Nmap

### Evasion Techniques

-   Packet fragmentation
-   Idle zombies scan
-   Decoy generation
-   Custom timing profiles
-   User-agent spoofing

### Output Formats

-   **CSV**: Dễ import vào Excel/Spreadsheets
-   **JSON**: Parse programmatically
-   **XML**: Tương thích Nmap parsers
-   **Text**: Human-readable reports

### Extension Scripts

-   HTTP Security Headers checker
-   SSL/TLS validation (not implemented yet)
-   Custom vulnerability checks (not implemented yet)

---

## 📦 Yêu Cầu & Cài Đặt

### Yêu Cầu Hệ Thống

-   **Python**: 3.10 trở lên (recommend 3.13+)
-   **OS**: Linux (Windows cần WSL2)
-   **Quyền**: Root/sudo (để sử dụng raw sockets, khuyến khích trong mọi trường hợp)

### Cài Đặt

**Clone từ GitHub**

```bash
git clone https://github.com/cyb3rhurr1c4n3/phantom-sweep.git

cd phantom-sweep

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

sudo python phantom.py --help
```

**Dependencies**

```
colorama          # Colored terminal output
pyfiglet          # ASCII art banners
scapy             # Packet manipulation
paramiko          # SSH operations
requests          # HTTP requests
beautifulsoup4    # HTML parsing
joblib            # Parallel processing
numpy             # Numerical computing
scikit-learn      # Machine learning models
```

---

## 📖 Hướng Dẫn Sử Dụng

### Cú Pháp Cơ Bản

```bash
sudo python phantom.py [TARGET] [OPTIONS]
```

### Ví Dụ Thông Dụng và Demo

**1. Super Fast Port Scanning (ICMP + TCP Connect) - Default**

```bash
sudo python phantom.py 192.168.0.0/24
```

![](resources/0_default_scan.mp4)

**2. Fast Host Discovery (ICMP)**

```bash
sudo python phantom.py 192.168.0.0/24 --scan-tech none
```

**3. Fast Host Discovery (ARP)**

```bash
sudo python phantom.py 192.168.0.0/24 --ping-tech arp --scan-tech none
```

**4. Quét 100 port phổ biến nhất**

```bash
sudo python phantom.py 192.168.0.0/24 --port top_100
```

**5. Quét với Service & Version Detection**

```bash
sudo python phantom.py 192.168.0.0/24 --service-detection-mode normal
```

**6. Quét với AI OS Fingerprinting**

```bash
sudo python phantom.py 192.168.0.0/24 --os-fingerprinting-mode ai
```

**7. Quét với Script bổ sung**

```bash
sudo python phantom.py 192.168.0.0/24 --script http_headers
```

**8. Xuất kết quả ra file**

```bash
sudo python phantom.py 192.168.0.0/24 --output json --output-file json_result
sudo python phantom.py 192.168.0.0/24 --output csv --output-file csv_result
```

**9. Quét với AI Evasion**

--> Bổ sung

**10. Quét tùy chỉnh performence**

```bash
sudo python phantom.py 192.168.0.0/24 --rate insane --thread 100 --timeout 10
```

### Các Tùy Chọn Chính

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

Xem tất cả options:

```bash
sudo python phantom.py --help
```

Xem ví dụ:

```bash
sudo python phantom.py --example
```

---

## 📊 So Sánh Hiệu Năng (chưa có)

## 🏗️ Kiến Trúc Hệ Thống

```
PhantomSweep/
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

**Cyber_Threat Group - UIT**

Dự án được thực hiện bởi 4 thành viên sinh viên Trường Đại học Công nghệ Thông tin, ĐHQG TP.HCM

### Phân Công

| Thành Viên            | Đóng góp (%) | Đóng Góp Chính |
| --------------------- | ------------ | -------------- |
| Hà Sơn Bin            |              |                |
| Võ Quốc Bảo           |              |                |
| Nguyễn Đoàn Gia Khánh |              |                |
| Lê Quốc Khôi          |              |                |

---

## 📈 Tính Năng Hoàn Thành

### Phase 1: Core Features ✅

-   [x] CLI Framework & Help System
-   [x] ARP Scan
-   [x] ICMP Ping Discovery
-   [x] TCP SYN Ping
-   [x] TCP Connect Scan
-   [x] UDP Scan
-   [x] Basic Service Detection
-   [x] Output Formats (JSON, CSV, XML, Text)

### Phase 2: Advanced Features ✅

-   [x] AI OS Fingerprinting
-   [x] Service Detection (Normal & AI modes)
-   [x] Evasion Timing Templates
-   [x] Custom Scripting Framework
-   [x] HTTP Headers Check Script
-   [x] Plugin Architecture & Dynamic Loading

### Phase 3: Optimization & Polish ✅

-   [x] Performance Tuning
-   [x] Memory Optimization (Generators)
-   [x] Comprehensive Error Handling
-   [x] Full Documentation
-   [x] Code Comments & Docstrings

---

## 🤝 Đóng Góp

Chúng tôi hoan nghênh mọi đóng góp từ cộng đồng!

### Cách Đóng Góp

1. Fork dự án
2. Tạo Feature Branch: `git checkout -b feature/AmazingFeature`
3. Commit thay đổi: `git commit -m 'Add AmazingFeature'`
4. Push lên branch: `git push origin feature/AmazingFeature`
5. Mở Pull Request

---

## 📚 Tài Liệu & Tham Khảo

### Tài Liệu Dự Án

-   [Proposal](./docs/proposal.md) - Đề xuất ban đầu
-   [Architecture Details](./docs/README.md) - Chi tiết kiến trúc
-   [Completed Tasks](./docs/final_tasks.md) - Task hoàn thành
-   [Demo Guide](./docs/what_to_demo.md) - Hướng dẫn presentation

### Công cụ Tham Khảo

-   [Nmap](https://nmap.org/) - Network mapping & port scanning
-   [Masscan](https://github.com/robertdavis60/masscan) - Fast network scanner

---

## 📜 Giấy Phép & Tuyên Bố Miễn Trừ

### Giấy Phép

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

| Thông Tin      | Chi Tiết                            |
| -------------- | ----------------------------------- |
| **Môn Học**    | NT140 - An toàn mạng                |
| **Trường**     | Đại học Công nghệ Thông tin (UIT)   |
| **Đại học**    | Đại học Quốc gia TP.HCM             |
| **Năm Học**    | 2024                                |
| **Nhóm**       | Cyber_Threat Group (4 thành viên)   |
| **Giảng viên** | Trần Tuấn Dũng (thầy Dũng đẹp trai) |

---

## 📞 Liên Hệ & Hỗ trợ

-   **GitHub Issues**: Báo cáo bugs
-   **GitHub Discussions**: Thảo luận tính năng
-   **Email**: 23520146@gm.uit.edu.vn (Võ Quốc Bảo - Leader)

---

**Developed with ❤️ by Cyber_Threat Group - UIT**

_Last Updated: December 2024_
