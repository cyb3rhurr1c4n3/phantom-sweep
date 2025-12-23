# NT140 - Proposal

## Tên dự án

PhantomSweep - A fast, lightweight and scalable network security scanner

## Mục tiêu

Xây dựng một công cụ quét mạng (network reconnaissance tool) **cực nhanh, nhẹ, dễ mở rộng và thông minh (AI)**, lấy cảm hứng từ Nmap/Masscan. Qua đó giúp quản trị viên mạng, pentester và red teamer **khám phá hệ thống mục tiêu**: phát hiện host, cổng mở, dịch vụ, phiên bản, và hệ điều hành. Đồng thời, tạo ra cơ chế dynamic plugin loading, đảm bảo công cụ vừa mang tính **học thuật** (phục vụ đồ án) vừa có giá trị **thực tiễn** (có thể đưa lên GitHub/CV như một open-source project có giá trị cao, cộng đồng có thể tham gia một cách dễ dàng).

## Yêu cầu

## phantom --help

```text
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

## Mô tả cụ thể

### Các tính năng

-   **Host discovery**: ICMP Echo, TCP SYN/ACK ping, ARP scan.
-   **Port scanning**: TCP SYN, TCP Connect, UDP scan.
-   **Service & version detection**: Normal mode.
-   **OS fingerprinting**: AI mode.
-   **Xuất kết quả đầu ra**: Text , JSON, Nmap-XML, CSV
-   **Plugin & Module & Dynamic Loading Architecture**: Có 5 yếu tố có thể mở rộng (hoặc bổ sung) là: các kỹ thuật Host Discovery (1), các kỹ thuật Port Scanning (2), các định dạng xuất kết quả đầu ra (3), các custom script (4), độ thông minh của các tính năng AI (5).
-   **Custom Script Running**: các script để chạy trên target (ví dụ http_headers_check,...)
-   **Tùy chọn evasive**: Evasion with AI

### Tham vọng

Chúng tôi định nói PhantomSweep nổi bật thông qua 3 yếu tố chính:

-   Super Fast & Lightweight: PhantomSweep sẽ tập trung vào những yếu tố cốt lõi nhất và bỏ những phần thừa, đồng thời tận dụng các kỹ thuật, phương pháp, kiến trúc quét tối ưu nhất để tăng tốc độ quét lên tối đa. Mặt này sẽ thể hiện qua hai tính năng là Host Discovery và Port Scanning
-   Scalable: Kiến trúc Plugin & Module & Dynamic Loading sẽ giúp PhantomSweep dễ dàng mở rộng thêm tính năng. Mặt này sẽ thể hiện ở sự dễ mở rộng của các yếu tố sau: các kỹ thuật Host Discovery (1), các kỹ thuật Port Scanning (2), các định dạng xuất kết quả đầu ra (3), các custom script (4), độ thông minh của các tính năng AI (5).
-   Smart: dùng AI để nâng cao hiệu quả của Service & Version Detection, OS Fingerprinting, đồng thời dùng AI để tự evasion một cách tối ưu, chống bị phát hiện. Mặt này sẽ thể hiện qua 3 tính năng: Service & Version Detection, OS Fingerprinting và Evasion with AI.
