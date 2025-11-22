netprobe/
├── .gitignore              # Bỏ qua các tệp không cần thiết
├── CONTRIBUTING.md         # Hướng dẫn đóng góp
├── README.md               # Tổng quan dự án và hướng dẫn
├── requirements.txt        # Thư viện Python cần thiết
├── setup.py               # Cài đặt package
├── config.yaml            # Cấu hình toàn cục
├── LICENSE                # Giấy phép sử dụng
│
├── netprobe.py            # Entry point chính của CLI
│
├── netprobe_core/         # Gói chứa logic cốt lõi
│   ├── __init__.py
│   ├── engine.py          # Lõi điều phối quét
│   ├── interfaces.py      # Interface cho plugin
│   ├── target_parser.py   # Phân tích target
│   ├── output_formatter.py # Định dạng đầu ra
│   ├── plugin_manager.py  # Quản lý plugin
│   ├── timing_manager.py  # Quản lý timing và performance
│   ├── result_aggregator.py # Tổng hợp kết quả
│   └── utils.py           # Các hàm tiện ích
│
├── plugins/               # Plugin system
│   ├── __init__.py
│   │
│   ├── discovery/         # Host Discovery plugins
│   │   ├── __init__.py
│   │   ├── ping_scan.py   # -sn ping scan
│   │   ├── tcp_ack_ping.py # -PA TCP ACK ping
│   │   ├── udp_ping.py    # -PU UDP ping
│   │   └── arp_ping.py    # ARP ping discovery
│   │
│   ├── scan_types/        # Các loại scan chính
│   │   ├── __init__.py
│   │   ├── tcp_syn.py     # -sS TCP SYN scan (default)
│   │   ├── tcp_connect.py # -sT TCP connect scan
│   │   ├── udp_scan.py    # -sU UDP scan
│   │   ├── tcp_fin.py     # -sF TCP FIN scan
│   │   ├── tcp_xmas.py    # -sX TCP Xmas scan
│   │   ├── tcp_null.py    # -sN TCP Null scan
│   │   └── idle_scan.py   # -sI Idle scan
│   │
│   ├── port_scanning/     # Port scanning modules
│   │   ├── __init__.py
│   │   ├── port_range.py  # Quét theo range
│   │   ├── fast_scan.py   # -F Fast scan (top 100)
│   │   ├── all_ports.py   # -p- All ports scan
│   │   └── custom_ports.py # Custom port lists
│   │
│   ├── service_detection/ # Service & Version Detection
│   │   ├── __init__.py
│   │   ├── version_detect.py # -sV Service version
│   │   ├── banner_grab.py    # Banner grabbing
│   │   ├── service_probe.py  # Service probing
│   │   └── protocol_detect.py # Protocol detection
│   │
│   ├── os_detection/      # OS Detection
│   │   ├── __init__.py
│   │   ├── tcp_fingerprint.py # TCP fingerprinting
│   │   ├── icmp_fingerprint.py # ICMP fingerprinting
│   │   ├── os_guess.py        # --osscan-guess
│   │   └── passive_os.py      # Passive OS detection
│   │
│   ├── evasion/          # Firewall Evasion Techniques
│   │   ├── __init__.py
│   │   ├── fragmentation.py  # -f Packet fragmentation
│   │   ├── decoy_scan.py     # -D Decoy scan
│   │   ├── spoof_source.py   # -S Source IP spoofing
│   │   ├── mac_spoof.py      # --spoof-mac MAC spoofing
│   │   ├── timing_control.py # Timing control
│   │   ├── mtu_discovery.py  # --mtu MTU manipulation
│   │   ├── proxy_chain.py    # --proxies Proxy chains
│   │   └── random_data.py    # --data-length Random data
│   │
│   └── scripts/          # NSE-like scripting engine
│       ├── __init__.py
│       ├── script_engine.py  # Script execution engine
│       │
│       ├── discovery/    # Discovery scripts
│       │   ├── dns_brute.py      # DNS brute force
│       │   ├── dns_zone_transfer.py # DNS zone transfer
│       │   └── snmp_walk.py      # SNMP enumeration
│       │
│       ├── vulnerability/ # Vulnerability scripts
│       │   ├── vuln_scanner.py   # Generic vuln scanner
│       │   ├── http_vulns.py     # HTTP vulnerabilities
│       │   ├── ssl_vulns.py      # SSL/TLS vulnerabilities
│       │   └── vulners_api.py    # Vulners.com integration
│       │
│       ├── brute_force/  # Brute force scripts
│       │   ├── ssh_brute.py      # SSH brute force
│       │   ├── ftp_brute.py      # FTP brute force
│       │   ├── mysql_brute.py    # MySQL brute force
│       │   ├── snmp_brute.py     # SNMP brute force
│       │   └── smtp_brute.py     # SMTP user enum
│       │
│       ├── enumeration/  # Service enumeration
│       │   ├── http_enum.py      # HTTP enumeration
│       │   ├── smb_enum.py       # SMB enumeration
│       │   ├── mysql_enum.py     # MySQL enumeration
│       │   ├── dns_enum.py       # DNS enumeration
│       │   └── ftp_enum.py       # FTP enumeration
│       │
│       └── misc/         # Miscellaneous scripts
│           ├── http_title.py     # HTTP title grabber
│           ├── ssl_cert.py       # SSL certificate info
│           ├── ssh_hostkey.py    # SSH host key
│           ├── http_robots.py    # robots.txt checker
│           ├── http_config_backup.py # Config backup finder
│           └── firewalk.py       # Firewalk technique
│
├── database/             # Database và signature files
│   ├── __init__.py
│   ├── os_signatures.db  # OS fingerprint database
│   ├── service_probes.db # Service detection probes
│   ├── vulnerability.db  # Vulnerability signatures
│   └── wordlists/        # Wordlists cho brute force
│       ├── usernames.txt
│       ├── passwords.txt
│       ├── directories.txt
│       └── subdomains.txt
│
├── output/               # Output handlers
│   ├── __init__.py
│   ├── formatters/       # Output formatters
│   │   ├── __init__.py
│   │   ├── normal_output.py  # -oN Normal output
│   │   ├── xml_output.py     # -oX XML output
│   │   ├── grepable_output.py # -oG Grepable output
│   │   ├── json_output.py    # JSON output
│   │   └── html_report.py    # HTML report generator
│   │
│   └── exporters/        # Export to external tools
│       ├── __init__.py
│       ├── metasploit.py     # Export to Metasploit
│       ├── nessus.py         # Export to Nessus
│       └── elastic_search.py # Export to ElasticSearch
│
├── network/              # Network utilities
│   ├── __init__.py
│   ├── packet_forge.py   # Packet crafting utilities
│   ├── raw_socket.py     # Raw socket operations
│   ├── network_utils.py  # Network utility functions
│   ├── protocol_parsers.py # Protocol parsers
│   └── rate_limiter.py   # Rate limiting mechanism
│
├── config/               # Configuration management
│   ├── __init__.py
│   ├── settings.py       # Settings management
│   ├── profiles/         # Scan profiles
│   │   ├── default.yaml
│   │   ├── stealth.yaml
│   │   ├── aggressive.yaml
│   │   └── comprehensive.yaml
│   └── templates/        # Report templates
│       ├── html_template.html
│       └── pdf_template.html
│
├── cli/                  # Command Line Interface
│   ├── __init__.py
│   ├── argument_parser.py # CLI argument parsing
│   ├── interactive_mode.py # Interactive mode
│   ├── progress_display.py # Progress bars và status
│   └── help_system.py    # Help và documentation
│
│
├── api/                  # REST API (optional)
│   ├── __init__.py
│   ├── rest_server.py    # REST API server
│   ├── endpoints.py      # API endpoints
│   └── authentication.py # API authentication
│
├── tests/                # Test suite
│   ├── __init__.py
│   ├── unit/             # Unit tests
│   │   ├── test_engine.py
│   │   ├── test_target_parser.py
│   │   ├── test_plugins.py
│   │   └── test_output.py
│   ├── integration/      # Integration tests
│   │   ├── test_scan_flows.py
│   │   └── test_plugin_integration.py
│   ├── performance/      # Performance tests
│   │   └── test_performance.py
│   └── fixtures/         # Test data
│       ├── sample_targets.txt
│       └── expected_outputs.json
│
├── docs/                 # Documentation
│   ├── README.md
│   ├── installation.md   # Hướng dẫn cài đặt
│   ├── user_guide.md     # Hướng dẫn sử dụng
│   ├── api_reference.md  # Tài liệu API
│   ├── plugin_development.md # Hướng dẫn phát triển plugin
│   ├── architecture.md   # Kiến trúc hệ thống
│   ├── performance_tuning.md # Tối ưu hiệu suất
│   └── examples/         # Ví dụ sử dụng
│       ├── basic_scan.md
│       ├── advanced_evasion.md
│       └── custom_scripts.md
│
├── scripts/              # Utility scripts
│   ├── install.sh        # Installation script
│   ├── update_db.py      # Update signature databases
│   ├── benchmark.py      # Performance benchmarking
│   └── generate_docs.py  # Documentation generation
│
└── examples/             # Example configurations và usage
    ├── scan_configs/     # Example scan configurations
    │   ├── web_app_scan.yaml
    │   ├── network_discovery.yaml
    │   └── vulnerability_scan.yaml
    ├── custom_scripts/   # Example custom scripts
    │   └── custom_http_check.py
    └── reports/          # Sample reports
        ├── sample_report.html
        ├── sample_report.xml
        └── sample_report.json