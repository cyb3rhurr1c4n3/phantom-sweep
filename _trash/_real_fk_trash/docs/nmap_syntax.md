# Cấu trúc chung lệnh Nmap: 
nmap [Scan Type(s)] [Options] {target specification}

# Các thành phần
## Target Specification
Các cách để chọn mục tiêu cho cuộc trinh thám
```
- Quét một IP: nmap <target> nmap 192.168.1.1
- Quét các IP cụ thể: nmap <target1> <target2>		nmap 192.168.1.1 192.168.1.2

Quét một dải IP			nmap <range> nmap 192.168.1.1-254

Quét tên miền			nmap <domain> nmap scanme.nmap.org

Quét theo CIDR			nmap <CIDR> 	nmap 192.168.1.0/24

Quét từ một tệp			nmap -iL <file> nmap -iL targets.txt

Quét các máy chủ ngẫu nhiên	nmap -iR <count> nmap -iR 100

Loại trừ máy chủ			nmap --exclude <target>			nmap --exclude 192.168.1.1
```

2. Các Kiểu Quét (Scan Types)

TCP SYN Scan (mặc định)		nmap -sS <target> nmap -sS 192.168.1.1

TCP Connect Scan			nmap -sT <target>				nmap -sT 192.168.1.1

UDP Scan				nmap -sU <target>				nmap -sU 192.168.1.1

Stealth Scans			nmap -sF					-sX

3. Khám phá Máy chủ (Host Discovery)
Ping Scan				nmap -sn <target>				nmap -sn 192.168.1.1
Chỉ liệt kê mục tiêu		nmap -sL <target>				nmap -sL 192.168.1.1-3
TCP ACK Scan			nmap -PA<ports> <target>		nmap -PA22,80 192.168.1.1

4. Quét Cổng (Port Scanning)
Quét một cổng			nmap -p <port> <target>			nmap -p 80 192.168.1.1
Quét một dải cổng			nmap -p <range> <target>		nmap -p 21-100 192.168.1.1
Quét tất cả các cổng		nmap -p- <target>				nmap -p- 192.168.1.1
Quét nhanh (top 100 cổng)	nmap -F <target>				nmap -F 192.168.1.1

5. Phát hiện Dịch vụ & Phiên bản (Service & Version Detection)
Phát hiện phiên bản dịch vụ	nmap -sV <target>				nmap -sV 192.168.1.1
Chế độ nhẹ				nmap -sV --version-light <target>	nmap -sV --version-light 192.168.1.1
Chế độ mạnh				nmap -sV --version-all <target>	nmap -sV --version-all 192.168.1.1

6. Phát hiện Hệ điều hành (OS Detection)
Phát hiện HĐH			nmap -O <target>				nmap -O 192.168.1.1
Đoán HĐH (mạnh)			nmap -O --osscan-guess <target>	nmap -O --osscan-guess 192.168.1.1

7. Tùy chọn Đầu ra (Output Options)
Đầu ra thông thường		nmap -oN <file> <target>		nmap -oN normal.txt 192.168.1.1
Đầu ra XML				nmap -oX <file> <target>		nmap -oX xml.txt 192.168.1.1
Chỉ hiển thị cổng mở		nmap --open <target>			nmap --open 192.168.1.1

8. Thời gian & Hiệu suất (Timing & Performance)
Cấu hình tốc độ (0-5)		nmap -T<0-5> <target>			nmap -T4 192.168.1.1
Giới hạn tốc độ			nmap --max-rate <rate> <target>	nmap --max-rate 100 192.168.1.1

9. Kỹ thuật Vượt Tường lửa (Firewall Evasion Techniques)
Điều chỉnh thời gian		nmap -T2 -Pn 192.168.1.1
Phân mảnh gói tin			nmap -f 192.168.1.1
Kích thước MTU tùy chỉnh	nmap --mtu 16 192.168.1.1
Thứ tự máy chủ ngẫu nhiên	nmap --randomize-hosts -iL targets.txt
Mồi nhử				nmap -D RND:10,ME 192.168.1.1
Giả mạo IP nguồn			nmap -S 1.2.3.4 192.168.1.1
Giả mạo địa chỉ MAC		nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1
Giả mạo cổng nguồn		nmap --source-port 53 192.168.1.1
TTL tùy chỉnh			nmap --ttl 128 192.168.1.1
Chuỗi proxy				nmap --proxies proxylist.txt 192.168.1.1
Giao thức không phổ biến	nmap -PE 192.168.1.1
Dữ liệu ngẫu nhiên		nmap --data-length 50 192.168.1.1
Liệt kê DNS				nmap -sL 192.168.1.1/24
Kết hợp các kỹ thuật		nmap -f -T2 -D RND:5 --spoof-mac 0 --source-port 443 192.168.1.1

10. Nmap Scripting Engine (NSE)
dns-brute				nmap -p 80 --script=dns-brute [target]
snmp-brute				nmap --script=snmp-brute [target]
http-vuln-*				nmap --script=http-vuln-* [target]
http-title				nmap -p 80,443 --script=http-title [target-ip-or-domain]
ssl-cert				nmap -p 443 --script=ssl-cert [target-ip-or-domain]
vuln					nmap -p 80,443 --script=vuln [target-ip-or-domain]
http-robots.txt			nmap -p 80,443 --script=http-robots.txt [target-ip-or-domain]
ssh-hostkey				nmap -p 22 --script=ssh-hostkey [target-ip-or-domain]
http-enum				nmap --script=http-enum testhtml5.vulnweb.com
ssh-brute				nmap -p 22 --script=ssh-brute --script-args userdb=users.txt,passdb=passwords.txt [target]
smb-enum-shares			nmap --script=smb-enum-shares --script-args smbuser=guest,smbpass=guest [target]
mysql-brute				nmap -p 3306 --script=mysql-brute --script-args userdb=users.txt,passdb=passwords.txt [target]
http-grep				nmap -p 80 --script=http-grep --script-args http-grep.url=<subpage> [target]
http-config-backup		nmap -p 80 --script=http-config-backup [target]
smb-enum-users			nmap --script=smb-enum-users [target]
http-wordpress-enum		nmap -p 80 --script=http-wordpress-enum [target]
firewalk				nmap --script=firewalk [target]
mysql-empty-password		nmap -p 3306 --script=mysql-empty-password [target]
mysql-users				nmap -p 3306 --script=mysql-users --script-args mysqluser=root,mysqlpass= [target]
smb-os-discovery			nmap -p 443 --script=smb-os-discovery [target]
dns-zone-transfer			nmap --script=dns-zone-transfer.nse --script-args dns-zone-transfer.domain=[domain] [target]
ftp-anon				nmap --script=ftp-anon [target]
smtp-enum-users			nmap --script=smtp-enum-users --script-args smtp.domain=[domain] [target]
vulners				nmap --script=vulners --script-args mincvss=[value] [target]








	