#### 1. **Target Specification**

```bash

✅ Quét một IP: netprobe 192.168.1.1

✅ Quét nhiều IP: netprobe 192.168.1.1 192.168.1.2  

✅ Quét dải IP: netprobe 192.168.1.1-10

✅ Quét CIDR: netprobe 192.168.1.0/24

✅ Quét domain: netprobe google.com

✅ Từ file: netprobe -iL targets.txt

✅ Loại trừ: netprobe 192.168.1.0/24 --exclude 192.168.1.1

```



#### 2. **Basic Scanning**

```bash

✅ TCP Connect Scan: netprobe -sT 192.168.1.1 (DEFAULT)

✅ Ping Scan: netprobe -sn 192.168.1.0/24

⚠️ TCP SYN Scan: netprobe -sS 192.168.1.1 (CẦN ROOT)

```



#### 3. **Port Scanning**

```bash

✅ Quét cổng cụ thể: netprobe -p 80,443 target

✅ Quét dải cổng: netprobe -p 1-1000 target  

✅ Quét nhanh: netprobe -F target (top 100 ports)

✅ Quét tất cả: netprobe -p- target (1-65535)

✅ Custom port list: netprobe -p 21,22,23,25,53,80,110,443 target

```



#### 4. **Service Detection**

```bash

✅ Banner grabbing: netprobe -sV target

✅ Service identification cơ bản (HTTP, SSH, FTP, SMTP...)

Version detection nâng cao

```



#### 5. **Host Discovery**

```bash

✅ TCP ACK Ping: netprobe -PA22,80 target

✅ List targets only: netprobe -sL target

⚠️ ICMP Ping

```



#### 6. **Performance & Timing**

```bash

✅ Timing templates: netprobe -T1 đến -T5 target

✅ Thread control: netprobe --max-threads 200 target

✅ Rate limiting: netprobe --max-rate 100 target

✅ Timeout control: netprobe --timeout 5 target

```



#### 7. **Output Formats**

```bash

✅ Normal output: netprobe -oN results.txt target

✅ XML output: netprobe -oX results.xml target  

✅ JSON output: netprobe -oJ results.json target

✅ Show only open: netprobe --open target

✅ HTML report: netprobe -oH report.html target

```

#### 9. **Basic Scripts** (3-5 scripts đơn giản)

```bash

✅ http-title: Lấy title của website

✅ ssl-cert: Thông tin SSL certificate

✅ ssh-hostkey: SSH host key

✅ dns-brute: DNS subdomain brute force (wordlist nhỏ)

✅ http-robots: Check robots.txt

```

#### 10. **Os Detection**

```bash

Phát hiện HĐH           nmap -O <target>                nmap -O 192.168.1.1


```