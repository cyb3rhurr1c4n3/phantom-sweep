# 👻 Cấu trúc CLI cho PhantomSweep
## Cấu trúc lệnh
```

phantom [TÙY CHỌN] <MỤC TIÊU> 

```
- Mục tiêu sẽ là argument bắt buộc, các tùy chọn còn lại không bắt buộc.
- Tạm thời chưa cần phiên bản thu gọn cho các tùy chọn (ví dụ -p cho --port), sau này sẽ tự phát triển sau.
- Một số tùy chọn sẽ có giá trị mặc định, tức sẽ được tự động gọi với giá trị mặc định nếu user không chỉ ra.
- Một số tùy chọn sẽ không có giá trị mặc định, tức sẽ chỉ được gọi khi user chỉ ra.
- Thiết kế các tùy chọn mặc định một cách thông minh, tối ưu để ứng dụng sẽ mặc định cho ra hiệu suất tốt nhất mà không cần người dùng tune.
## Các tùy chọn chi tiết
### General
#### Mô tả
- Những option chung chung cho ứng dụng
#### Chi tiết
```
#################### GENERAL ####################:
  Some general options

  --version             Show program's version number and exit
  --help                Show this help message and exit
  --example             Show detailed examples
```

### Miscellaneous
#### Mô tả
- Những option hữu ích
#### Chi tiết
```
#################### MISCELLANEOUS ####################:
  --verbose             Increase verbosity level (show detailed progress and information)
```

### 🎯 Chỉ định Mục tiêu (Target Specification)
#### Mô tả
- Đây là phần bắt buộc phải có của mỗi lần nhập lệnh
- Đảm nhiệm bởi core/parsers.py, được gọi khi xây dựng ScanContext
- Nếu không có 
#### Chi tiết
- Quét một IP cụ thể: `192.168.1.2`
- Quét nhiều IP cụ thể: `192.168.1.2 192.168.1.3 192.168.1.4`
- Quét một dãy IP: `192.168.1.1-192.168.1.100`
- Quét một CIDR: `192.168.1.0/24`
- Quét một domain: `scanme.nmap.org`
- Quét kết hợp: `192.168.1.1 192.168.1.2-192.168.1.10` (kết hợp nhiều kiểu lại với nhau)
- Quét danh sách IP từ file: `--host-list targets.txt` (bắt buộc phải có nếu không chỉ ra IP cụ thể như các cách đã nêu)
- Loại trừ IP hoặc Dải IP khỏi quá trình quét: `--exclude-host 192.168.1.5 192.168.1.10-20` (có thể xử lý tất cả các dạng specification như trên)
### 🔎 Chỉ định Cổng (Port Specification)
#### Mô tả
- Đây là phần có giá trị mặc định, sẽ dùng port list top 100 port phổ biến nhất nếu người dùng không tự chỉ quét port khác
- Đảm nhiệm bởi core/parsers.py, được gọi khi xây dựng ScanContext
#### Chi tiết
- Chỉ định một port: `--port 80`
- Chỉ định nhiều port: `--port 80,443,8080` (cách nhau bằng dấu phẩy)
- Chỉ định một dải port: `--port 1-1000`
- Chỉ định quét 100 port phổ biến nhất: `--port top_100` --> Default value
- Chỉ định quét 1000 port phổ biến nhất: `--port top_1000`
- Chỉ định quét toàn bộ 65535 port: `--port all`
- Chỉ định quét danh sách port từ file: `--port-list ports.txt` (mỗi port một dòng)
- Loại trừ cổng hoặc danh sách cổng: `--exclude-port 21 22,23 top_100` (có thể xử lý tất cả các dạng specification như trên)
### 📡 Quy trình Quét (Scan Pipeline)
#### Mô tả
- Đây là xương sống của ứng dụng.
- Có 4 bước chính trong pineline: Host Discovery, Port Scanning, Service & Version Detection, OS Fingerprinting, Run Custom Script.
- Chế độ mặc định của pineline là Host Discovery (icmp) và Port Scanning (tcp connect) và ba bước kia mặc định sẽ off, chỉ được bật khi người dùng chỉ ra.
- Có các option sau:
1. Only Host Discovery: chỉ kiểm tra host nào up, nào down, không cần làm gì thêm.
2. Host Discovery + Port Scanning: kiểm tra port nào mở, nào đóng
3. No Host Discovery + Port Scanning: xem như host đã up và kiểm tra port
4. Kết quả Port Scanning + combo tùy ý từ {Service & Version Detection, OS Fingerprinting, Script}: bật tắt tùy ý 3 tính năng sau, nhưng muốn chúng được thực hiện thì bắt buộc phải có kết quả từ Port Scanning (kết quả từ port scanning có thể có được từ host discovery + port scanning (2) hoặc no host discovery + port scanning (3))
--> Ràng buộc như vậy vì ta ba tính năng Service & Version Detection, OS Fingerprinting, Script bắt buộc có Port Scanning, còn Port Scanning có thể có hoặc không có Host Discovery.
- Ý tưởng hoạt động:
	- Với các tính năng Host Discovery, Port Scanning và Script, khi được gọi (ví dụ --ping-tech icmp --scan-tech steath --script abc_xyz), manager.py sẽ tìm trong thư mục module/scanner/ và tìm 3 file: icmp_plugin.py, steath_plugin.py và abc_xyz_plugin.py để gọi đến các plugin tương ứng và chạy chúng. Nếu chúng không tồn tại hay chạy lỗi thì sẽ báo lỗi. Như vậy sẽ rất dễ mở rộng, sau này người khác chỉ cần thêm plugin mới với tên new-plugin-name_plugin.py và đảm bảo các phương thức trừu tượng của plugin base được triển khai đúng cách là đã có thể tích hợp với ứng dụng và không cần sửa đổi CLI. 
	- Với tính năng Service and Version Detection, sẽ có 3 mode {normal, ai, off} (mặc định là off). Khi người dùng chọn --service-detection-mode normal (hoặc ai), manager.py sẽ tìm trong module/analyzer để tìm file tương ứng và thực thi. Nếu option là off thì sẽ bỏ qua.
	- Với tính năng OS Fingerprinting, sẽ có 3 mode {normal, ai, off} (mặc định là off). Khi người dùng chọn --os-fingerprinting-mode normal (hoặc ai), manager.py sẽ tìm trong module/analyzer để tìm file tương ứng và thực thi. Nếu option là off thì sẽ bỏ qua.
- Nếu tính năng cần sudo nhưng người dùng không chỉ ra thì sẽ cảnh báo
#### Chi tiết
##### Host Discovery
`--ping-tech` <kỹ thuật quét>
	`icmp` (Mặc định): quét bằng kỹ thuật ICMP Ping 
	`tcp`: quét bằng kỹ thuật TCP SYN/ACK Ping
	`arp`: quét bằng kỹ thuật ARP Scan
	`none`: Consider Alive 
--> Người dùng có thể tự bổ sung thêm

##### Port Scanning
`--scan-tech` <kỹ thuật quét>
	`connect` (Mặc định): quét bằng kỹ thuật TCP Connect
	`stealth`: quét bằng kỹ thuật TCP Syn
	`udp`: quét bằng kỹ thuật UDP Scan
--> Người dùng có thể tự bổ sung thêm

##### Service & Version Detection
`--service-detection-mode` <chế độ>
	`ai`: dùng ai
	`normal`: không dùng ai
	`off` (Mặc định): tắt tính năng
##### OS Fingerprinting
`--os-fingerprinting-mode` <chế độ>
	`ai`: dùng ai
	`normal`: không dùng ai
	`off` (Mặc định): tắt tính năng
##### Script
`--script` <tên script>
	`<tên script>`: chạy script cụ thể
	`all`: chạy tất cả các script

### ⚡ Hiệu suất và Evasion (Tích hợp AI)
#### Mô tả
- Tinh chỉnh hiệu suất quét và tính năng Evasion
- Có thể tích hợp tối ưu bằng AI nhưng chưa biết cách
#### Chi tiết
```
#################### PERFORMANCE AND EVASION ####################
  Control scan speed and evasion techniques.
  --rate {stealthy,balanced,fast,insane}
                        Scan rate/timing template (default: balanced):
                                    - stealthy: Slow, AI-adaptive timing (evade IDS/IPS)
                                    - balanced: Balanced speed and accuracy (Nmap T3-like)
                                    - fast: Fast scan (Nmap T4-like)
                                    - insane: Maximum speed (Masscan-like)
  --thread NUM          Number of concurrent thread/workers (default: 10). Higher = faster but more resource usage.
  --timeout SECONDS     Timeout in seconds for each probe (default: 5.0 seconds). AI may auto-adjust if --rate stealthy.
  --evasion-mode TECHNIQUE [TECHNIQUE ...]
                        Evasion techniques (can combine multiple):
                                    - none: Not use (default)
                                    - randomize: Randomize host and port order
                                    - fragment: Fragment packets
                                    - decoy: Use decoy IPs
                                    - spoof: Spoof source IP
```

### 🧩 Định dạng đầu ra (Output Format)
#### Mô tả
- Định dạng xuất kết quả, mặc định sẽ chỉ xuất ra màn hình.
- Nếu user chọn `--output json,xml --output-file my_scan`, chương trình sẽ tạo ra `my_scan.json` và `my_scan.xml`
#### Chi tiết
```
	#################### OUTPUT FORMAT ####################:
  Specify how your output should be format.

  --output OUTPUT_FORMAT
                        Export to file format (default: none):
                                    - none: only print to screen
                                    - text: Human-readable text format
                                    - json: JSON format (machine-readable)
                                    - xml: XML format (Nmap-compatible)
                                    - csv: CSV format
                                    - Multiple: json,xml (comma-separated)
                                    
                                    
  --output-file FILENAME
                        Save output to file. If not specified, results are printed to console.
```
## Một số ví dụ thực tế
```
# 1. Quét mặc định (sử dụng các option mặc định: "--port top_100 --ping-tech icmp --scan-tech connect --service-detection-mode off --os-fingerprinting-mode off --rate balanced --thread 10 --timeout 5.0 --output none")

python phantom.py 192.168.1.1

# 2. Quét mạng custom

python phantom.py 192.168.1.0/24 --port 80,443 --output json --output-file results.json

# 3. Stealth scan với AI evasion

python phantom.py 192.168.1.0/24 --ping-tech none --scan-tech stealth --rate stealthy --evasion randomize

# 4. Full scan với tất cả scripts và xuất ra nhiều định dạng

python phantom.py 192.168.1.1 --port all --script all --output json,xml,html

# 5. Quét UDP cụ thể

python phantom.py 192.168.1.1 --scan-tech udp --port 53,161

# 6. Quét với exclusion

python phantom.py 192.168.1.0/24 --exclude-host 192.168.1.1,192.168.1.100 --port top_1000 --exclude-port 80,443

```