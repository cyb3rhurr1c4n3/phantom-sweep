# 🗺️ Tổng Hợp Các Lệnh Nmap Thường Dùng

Cấu trúc lệnh chung của Nmap:
```
nmap [Tùy chọn Quét(s)] [Tùy chọn khác] {Chỉ định Mục tiêu}
```

## I - Chỉ định Mục tiêu

| Mô tả | Cú pháp Lệnh | Ví dụ |
| :--- | :--- | :--- |
| Quét một **IP** | `nmap <target>` | `nmap 192.168.1.1` |
| Quét nhiều **IP cụ thể** | `nmap <target1> <target2>...` | `nmap 192.168.1.1 192.168.1.2` |
| Quét một **dải IP** | `nmap <range>` | `nmap 192.168.1.1-254` |
| Quét **tên miền** | `nmap <domain>` | `nmap scanme.nmap.org` |
| Quét theo **CIDR** | `nmap <CIDR>` | `nmap 192.168.1.0/24` |
| Quét từ một **tệp** | `nmap -iL <file>` | `nmap -iL targets.txt` |
| Quét các máy chủ **ngẫu nhiên** | `nmap -iR <count>` | `nmap -iR 100` |
| **Loại trừ** host | `nmap --exclude <target>` | `nmap --exclude 192.168.1.1` |

## II - Tùy chọn quét

### 1. Các Kiểu Quét Chính (Scan Types)

| Tên kiểu quét | Tùy chọn | Mô tả |
| :--- | :--- | :--- |
| **TCP SYN Scan** | `-sS` | Quét tàng hình (Stealth), mặc định, không hoàn thành bắt tay 3 bước. |
| **TCP Connect Scan** | `-sT` | Quét kết nối đầy đủ (non-stealth), dùng khi không có quyền root. |
| **UDP Scan** | `-sU` | Quét các cổng sử dụng giao thức UDP. |
| **FIN/Xmas/Null Scan** | `-sF / -sX / -sN` | Các kiểu quét tàng hình khác (Stealth Scans). |

### 2. Khám phá Máy chủ (Host Discovery) & Quét Cổng (Port Scanning)

| Tính năng | Tùy chọn | Ví dụ |
| :--- | :--- | :--- |
| **Ping Scan** | `-sn` | Chỉ kiểm tra host có hoạt động không, không quét cổng. |
| Chỉ **liệt kê** mục tiêu | `-sL` | Liệt kê mục tiêu mà không gửi bất kỳ gói tin nào. |
| **TCP ACK Scan** (Discovery) | `-PA<ports>` | Dùng gói ACK để khám phá/xác định quy tắc tường lửa. |
| Quét **một cổng** | `-p <port>` | `nmap -p 80 192.168.1.1` |
| Quét một **dải cổng** | `-p <range>` | `nmap -p 21-100 192.168.1.1` |
| Quét **tất cả** các cổng | `-p-` | Quét tất cả 65535 cổng TCP. |
| **Quét nhanh** (Top 100) | `-F` | Chỉ quét 100 cổng phổ biến nhất. |

### 3. Phát hiện Dịch vụ, Phiên bản, và HĐH

| Tính năng | Tùy chọn | Mô tả/Ví dụ |
| :--- | :--- | :--- |
| **Phát hiện phiên bản** dịch vụ | `-sV` | Thu thập banner và xác định chi tiết dịch vụ/phiên bản. |
| Chế độ nhẹ (`-sV`) | `--version-light` | Quét nhanh hơn, ít chuyên sâu. |
| Chế độ mạnh (`-sV`) | `--version-all` | Quét chuyên sâu nhất. |
| **Phát hiện HĐH** | `-O` | Cố gắng xác định hệ điều hành của mục tiêu. |
| **Đoán HĐH** (mạnh) | `--osscan-guess` | Cho phép Nmap đoán HĐH nếu không chắc chắn. |


## Các tùy chọn khác:

---

### 5. Tùy chọn Đầu ra (Output) & Hiệu suất (Timing)

| Tính năng | Tùy chọn | Ví dụ |
| :--- | :--- | :--- |
| Đầu ra **Thông thường** | `-oN <file>` | `nmap -oN normal.txt 192.168.1.1` |
| Đầu ra **XML** | `-oX <file>` | `nmap -oX xml.txt 192.168.1.1` |
| Chỉ hiển thị **cổng mở** | `--open` | Lọc kết quả chỉ hiển thị các cổng có trạng thái `open`. |
| Cấu hình **tốc độ** (0-5) | `-T<0-5>` | `-T4` (Aggressive) là phổ biến, `-T0` (Paranoid) là chậm nhất. |
| **Giới hạn tốc độ** | `--max-rate <rate>` | Giới hạn tốc độ gửi gói tin (ví dụ: 100 gói/giây). |

### 6. Kỹ thuật Vượt Tường lửa (Firewall Evasion)

| Kỹ thuật | Tùy chọn | Mô tả |
| :--- | :--- | :--- |
| Phân mảnh gói tin | `-f` / `--mtu <size>` | Chia gói tin thành các mảnh nhỏ hơn để vượt qua tường lửa/IDS. |
| Thứ tự host ngẫu nhiên | `--randomize-hosts` | Trộn lẫn thứ tự quét host để tránh bị phát hiện. |
| **Mồi nhử** (Decoy) | `-D RND:10,ME` | Thêm các địa chỉ IP giả mạo vào gói tin để che dấu IP thật. |
| Giả mạo IP nguồn | `-S <IP>` | Thay đổi IP nguồn (cần kiểm tra cấu hình mạng). |
| Giả mạo địa chỉ MAC | `--spoof-mac 00:11:22:33:44:55` | Thay đổi địa chỉ MAC nguồn. |
| Giả mạo cổng nguồn | `--source-port 53` | Thiết lập cổng nguồn phổ biến (ví dụ: DNS 53, HTTP 80). |
| TTL tùy chỉnh | `--ttl 128` | Thiết lập giá trị Time-to-Live. |
| Thêm dữ liệu ngẫu nhiên | `--data-length 50` | Thêm dữ liệu rác để làm cho gói tin có vẻ "hợp lệ" hơn. |

### 7. Nmap Scripting Engine (NSE)

NSE cho phép bạn mở rộng khả năng quét và kiểm tra lỗ hổng.

| Mục đích | Ví dụ Lệnh | Script (Tập lệnh) |
| :--- | :--- | :--- |
| **Kiểm tra Lỗ hổng Chung** | `nmap --script=vuln [target]` | `vuln`, `http-vuln-*`, `mysql-empty-password` |
| **Brute Force/Tấn công từ điển** | `nmap -p 22 --script=ssh-brute...` | `ssh-brute`, `snmp-brute`, `mysql-brute` |
| **Thông tin HTTP/TLS/SSL** | `nmap -p 80 --script=http-title...` | `http-title`, `ssl-cert`, `http-robots.txt`, `http-enum` |
| **Liệt kê SMB/FTP/DNS** | `nmap --script=smb-enum-shares...` | `smb-enum-shares`, `ftp-anon`, `dns-zone-transfer`, `smb-os-discovery` |

Các tập lệnh NSE được gọi bằng cách sử dụng tùy chọn **`--script=`**.