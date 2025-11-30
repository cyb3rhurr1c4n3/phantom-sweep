# NT140 - Proposal

## Tên dự án

PhantomSweep - A fast, lightweight and scalable network security scanner

## Mục tiêu

Xây dựng một công cụ quét mạng (network reconnaissance tool) **cực nhanh, nhẹ, dễ mở rộng và thông minh (AI)**, lấy cảm hứng từ Nmap/Masscan. Qua đó giúp quản trị viên mạng, pentester và red teamer **khám phá hệ thống mục tiêu**: phát hiện host, cổng mở, dịch vụ, phiên bản, và hệ điều hành. Đồng thời, tạo ra cơ chế dynamic plugin loading, đảm bảo công cụ vừa mang tính **học thuật** (phục vụ đồ án) vừa có giá trị **thực tiễn** (có thể đưa lên GitHub/CV như một open-source project có giá trị cao, cộng đồng có thể tham gia một cách dễ dàng).

## Yêu cầu

## phantom --help

```text
:#################### GENERAL ####################:
  Some general options

  --version             Show program's version number and exit
  --help                Show this help message and exit
  --example             Show detailed examples

:#################### TARGET SPECIFICATION ####################:
  Specify targets to scan. At least one target source is required.

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

  --ping-tech {arp,icmp,tcp,none}
                        Host discovery technique (default: icmp):
                                    - arp: ARP Discovery (LAN only)
                                    - icmp: ICMP Echo Request (Ping) Discovery
                                    - icmp: ICMP Echo Request (Ping) Discovery - Scapy Fallback
                                    - tcp: TCP SYN Ping to common ports (80, 443, 22, etc.)
                                    - none: Skip discovery
  --scan-tech {ai_os_fingerprinter,connect,stealth,udp,none}
                        Port scanning technique (default: connect):
                                    - ai_os_fingerprinter: AI-powered OS detection using Random Forest
                                    - connect: TCP Connect Scan (ultra-fast)
                                    - stealth: TCP SYN Scan (stealth scan, ultra-fast)
                                    - udp: UDP Port Scan (ICMP-based)
                                    - none: Skip port scanning
  --service-detection-mode {ai,normal,off}
                        Service detection mode (default: off):
                                    - ai: AI-powered service and version detection
                                    - normal: Banner-based detection
                                    - off: Disable service detection
  --os-fingerprinting-mode {ai,normal,off}
                        OS fingerprinting mode (default: off):
                                    - ai: AI-powered OS detection
                                    - normal: TTL/Window size-based detection
                                    - off: Disable OS fingerprinting
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

:#################### OUTPUT FORMAT ####################:
  Specify how your output should be format.

  --output {json,text,xml,none}
                        Export to file format (default: none):
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

-   **Host discovery**:
    -   Tối thiểu: ICMP Echo, TCP SYN/ACK ping, ARP scan. --> chưa hoàn thành và chưa tối ưu tốc độ
-   **Port scanning**:
    -   Tối thiểu: TCP SYN, TCP Connect, UDP scan. --> chưa hoàn thành và chưa tối ưu tốc độ
-   **Service & version detection**:
    -   Tối thiểu: normal mode (thu thập banner, phân tích dịch vụ phổ biến) --> đã hoàn thành
    -   Nâng cao: ai mode (dùng AI để thực hiện tính năng này) --> chưa hoàn thành
-   **OS fingerprinting**:
    -   Tối thiểu: normal mode (dựa trên TTL, Window Size, TCP/IP stack behavior) --> chưa hoàn thành
    -   Nâng cao: ai mode (dùng AI để thực hiện tính năng này) --> đã hoàn thành
-   **Xuất kết quả đầu ra**:
    -   Tối thiểu: Text , JSON cho máy móc xử lý --> Đã hoàn thành
    -   Nâng cao: Nmap-XML, CSV --> Đã hoàn thành
-   **Plugin & Module & Dynamic Loading Architecture** (nâng cao): Tạo cơ chế cho phép viết thêm các plugin. Có 5 yếu tố có thể mở rộng (hoặc bổ sung) là: các kỹ thuật Host Discovery (1), các kỹ thuật Port Scanning (2), các định dạng xuất kết quả đầu ra (3), các custom script (4), độ thông minh của các tính năng AI (5). --> Đã hoàn thành
-   **Custom Script Running** (nâng cao): viết các script để chạy trên target (ví dụ http_headers_check,...) --> Đã hoàn thành
-   **Tùy chọn evasive** (nâng cao):
    -   normal: randomize, fragment, decoy, spoof --> Chưa hoàn thành
    -   ai: Evasion with AI --> Gần hoàn thành

### Tham vọng

Chúng tôi định nói PhantomSweep nổi bật thông qua 3 yếu tố chính:

-   Super Fast & Lightweight: PhantomSweep sẽ tập trung vào những yếu tố cốt lõi nhất và bỏ những phần thừa, đồng thời tận dụng các kỹ thuật, phương pháp, kiến trúc quét tối ưu nhất để tăng tốc độ quét lên tối đa. Mặt này sẽ thể hiện qua hai tính năng là Host Discovery và Port Scanning
-   Scalable: Kiến trúc Plugin & Module & Dynamic Loading sẽ giúp PhantomSweep dễ dàng mở rộng thêm tính năng. Mặt này sẽ thể hiện ở sự dễ mở rộng của các yếu tố sau: các kỹ thuật Host Discovery (1), các kỹ thuật Port Scanning (2), các định dạng xuất kết quả đầu ra (3), các custom script (4), độ thông minh của các tính năng AI (5).
-   Smart: dùng AI để nâng cao hiệu quả của Service & Version Detection, OS Fingerprinting, đồng thời dùng AI để tự evasion một cách tối ưu, chống bị phát hiện. Mặt này sẽ thể hiện qua 3 tính năng: Service & Version Detection, OS Fingerprinting và Evasion with AI.
