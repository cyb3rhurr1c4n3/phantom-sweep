# Ý tưởng về cách hoạt động của CLI
Với mỗi option được chỉ ra (có ngoại lệ), chương trình sẽ tìm trong thư mục tương ứng để tìm file plugin tương ứng. Điều này sẽ giúp chương trình rất dễ mở rộng. Sau này nếu bổ sung thêm tính năng hay kỹ thuật quét mới, ta chỉ cần thêm file mới vào thư mục tương ứng, không cần sửa CLI.

# 👻 Cấu trúc CLI Hoàn thiện cho PhantomSweep
## I - Cấu trúc Lệnh
Cú pháp chung sẽ là các tùy chọn dài, rõ ràng, với các giá trị mặc định thông minh.
```bash
phantom [TÙY CHỌN] --host <MỤC TIÊU>
```
- Hầu hết các tùy chọn đều có giá trị mặc định.
- Chỉ có **`--host`** (hoặc **`--input-file`**) là bắt buộc.
## II - Danh sách Tùy chọn (Options)
### 🎯 Chỉ định Mục tiêu (Target Specification)

| **Tùy chọn**                                                                                                                                                                                                                                                           | **Ví dụ**                           | **Mô tả**                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | -------------------------------------------------------- |
| - Quét một IP cụ thể: `--host 192.168.1.2`<br>- Quét nhiều IP cụ thể: `--host 192.168.1.2 192.168.1.3 192.168.1.4`<br>- Quét một dãy IP: `--host 192.168.1.1-192.168.1.100`<br>- Quét một CIDR: `--host 192.168.1.0/24`<br>- Quét một domain: `--host scanme.nmap.org` | `--host 192.168.1.1 192.168.1.2-10` | (Bắt buộc) Chỉ định IP, Dải IP, hoặc CIDR, Domain name   |
| - Quét danh sách IP từ file: **`--input-file <file>`**                                                                                                                                                                                                                 | `--input-file targets.txt`          | (Bắt buộc nếu không có --host) Đọc mục tiêu từ một file. |
| **`--exclude-ip <target(s)>`**                                                                                                                                                                                                                                         | `--exclude 192.168.1.5`             | Loại trừ IP hoặc Dải IP khỏi quá trình quét.             |

### 🔎 Chỉ định Cổng (Port Specification)

| **Tùy chọn**         | **Ví dụ**              | **Mô tả**                                   |
| -------------------- | ---------------------- | ------------------------------------------- |
| **`--port <ports>`** | `--port 80,443,8080`   | Chỉ định cổng (cách nhau bằng dấu phẩy).    |
|                      | `--port 1-1000`        | Chỉ định một dải cổng.                      |
|                      | `--port top_100`       | **(Mặc định)** Quét 100 cổng phổ biến nhất. |
|                      | `--port all`           | Quét tất cả 65,535 cổng.                    |
| `--exclude-port`     | `--exclude-port 22,23` | Loại trừ cổng khỏi scan                     |

### 📡 Quy trình Quét (Scan Pipeline)

| **Tùy chọn**                   | **Lựa chọn**                            | **Mô tả**                                                                                                         |
| ------------------------------ | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **`--ping_tech`**              | `icmp` (Mặc định), `tcp`, `arp`, `none` | Chọn kỹ thuật khám phá host (Host Discovery). `none` = Bỏ qua, coi tất cả host đều sống. `tcp` = TCP SYN/ACK Ping |
| **`--scan_tech`**              | `connect` (Mặc định), `stealth`, `udp`  | Chọn kỹ thuật quét cổng. `stealth` = TCP SYN Scan. `connect` = TCP Connect Scan.                                  |
| **`--service_detection_mode`** | `ai` (Mặc định), `normal`, `off`        | Chọn chế độ nhận diện dịch vụ. `normal` = Dựa trên banner tĩnh (nếu có).                                          |
| **`--os_fingerprinting_mode`** | `ai` (Mặc định), `normal`, `off`        | Chọn chế độ nhận diện HĐH. `normal` = Dựa trên TTL/Window Size tĩnh.                                              |

### ⚡ Hiệu suất và Evasion (Tích hợp AI)

| **Tùy chọn**         | **Lựa chọn**                              | **Mô tả**                                                                                                               |
| -------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **`--rate`**         | `stealthy`                                | **(AI Evasion)** Tốc độ chậm, tự động kích hoạt **AI Adaptive Timing** (thêm Jitter, Rate-limit động) để tránh IDS/IPS. |
|                      | `balanced` (Mặc định)                     | Tốc độ cân bằng, tối ưu cho độ chính xác (Kiểu Nmap T3).                                                                |
|                      | `fast`                                    | Tốc độ nhanh (Kiểu Nmap T4).                                                                                            |
|                      | `insane`                                  | Tốc độ tối đa, chấp nhận mất gói (Kiểu Masscan).                                                                        |
| **`--threads`**      | `<number>` (Mặc định: 10)                 | Số luồng/tác vụ đồng thời.                                                                                              |
| **`--timeout`**      | `<seconds>` (Mặc định: 1.0)               | Thời gian chờ phản hồi (AI có thể tự điều chỉnh nếu `--rate stealthy`).                                                 |
| `--evasion <method>` | `randomize`, `fragment`, `decoy`, `spoof` | Evasion techniques (có thể kết hợp)                                                                                     |

### 🧩 Mở rộng và Đầu ra (Extension & Output)

| **Tùy chọn**                          | **Ví dụ**                      | **Mô tả**                                                         |
| ------------------------------------- | ------------------------------ | ----------------------------------------------------------------- |
| **`--script <script1> <script2>...`** | `--script ftp_anon http_risky` | Chạy một hoặc nhiều script                                        |
| **`--output <format>`**               | `--output json`                | Chọn định dạng (text, json, csv, xml). **(Mặc định: text)**.      |
| **`--output-file <filename>`**        | `--output-file results.json`   | Tên file để lưu kết quả. Nếu không có, kết quả sẽ in ra màn hình. |

### 🚀 Gói Combo (Combo Packs) (sẽ bổ sung)

## III. Help system (sẽ bổ sung)
## IV. Plugin discovery mechanism

Cấu trúc thư mục đề xuất:

```
plugins/
├── ping_tech/
│   ├── icmp_plugin.py
│   ├── tcp_plugin.py
│   ├── arp_plugin.py
│   └── none_plugin.py
├── scan_tech/
│   ├── connect_plugin.py
│   ├── stealth_plugin.py
│   └── udp_plugin.py
├── analyze/
│   ├── service_detection_plugin.py
│   └── os_fingerprinting_plugin.py
├── scripts/
│   ├── ftp_anon_plugin.py
│   ├── http_risky_methods_plugin.py
│   └── ssl_check_plugin.py
└── output/
    ├── json_plugin.py
    ├── text_plugin.py
    ├── xml_plugin.py
    └── csv_plugin.py
```

Mỗi plugin cần metadata:

```python
class StealthPlugin(BasePlugin):
    def metadata(self):
        return {
            "name": "stealth",
            "display_name": "TCP SYN Stealth Scan",
            "description": "Fast SYN scan without completing TCP handshake",
            "category": "scan_tech",
            "requires_root": True,  # Cần quyền root
            "aliases": ["syn", "syn_scan"]
        }
```

## IV. Một số ví dụ thực tế

```bash
# Note: cái nào không chỉ ra sẽ sử dụng option mặc định. Nếu không có option mặc định sẽ không thực hiện.


# 1. Quét mặc định (sử dụng các option mặc định như top_100 ports, icmp ping, AI mode, balanced rate,...)
python phantom.py --host 192.168.1.1


# 2. Quét mạng custom
python phantom.py --host 192.168.1.0/24 -port 80,443 --output json --output_file results.json

# 3. Stealth scan với AI evasion
python phantom.py --host 192.168.1.0/24 --scan_tech stealth --rate stealthy --evasion randomize

# 4. Full scan với tất cả scripts
python phantom.py --host 192.168.1.1 --port all --script all --output json,xml,html

# 6. Sử dụng combo
python phantom.py --host scanme.nmap.org --combo 1
python phantom.py --host 192.168.1.0/24 --combo full_ai

# 7. List và xem thông tin plugins
python phantom.py --list-plugins
python phantom.py --plugin-info stealth
python phantom.py --list-scripts
python phantom.py --script-info ftp_anon

# 8. Tạo và lưu combo
python phantom.py --host 192.168.1.1 --scan_tech stealth --rate fast --combo-save my_stealth

# 9. Quét với script arguments
python phantom.py --host 192.168.1.1 --script ftp_anon --script-args user=anonymous

# 10. Quét UDP cụ thể
python phantom.py --host 192.168.1.1 --scan_tech udp --port 53,161

# 11. Quét với exclusion
python phantom.py --host 192.168.1.0/24 --exclude_ip 192.168.1.1,192.168.1.100 --port top_1000

```



