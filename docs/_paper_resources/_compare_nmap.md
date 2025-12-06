Kết quả và kịch bản so sánh Nmap (chỉ ở mạng 24)

# Host Discovery

## ICMP Ping --> Ngang ngửa T5 và phát hiện được nhiều hơn

phantom 10.0.21.0/24 --ping-tech icmp --scan-tech none
sudo nmap -sn -PE -n --send-ip -T5 10.0.21.0/24

## ARP Scan --> Ngang ngửa T5 và phát hiện giống nhau

phantom 10.0.21.0/24 --ping-tech arp --scan-tech none
sudo nmap -sn -PR -n -T5 10.0.21.0/24

## TCP Syn/Ack Ping (chưa ổn)

phantom 10.0.21.0/24 --ping-tech tcp --scan-tech none
sudo nmap -sn -PS443 -n -T5 10.0.21.0/24

# Port Scanning (nền ICMP)

## TCP Connect --> Ăn đức Nmap

phantom scanme.nmap.org --ping-tech none --scan-tech connect --timeout 3
sudo nmap -Pn -sT -T5 scanme.nmap.org

## TCP Stealth (chưa ổn)

phantom scanme.nmap.org --ping-tech none --scan-tech stealth --timeout 3
sudo nmap -Pn -sS -n -T5 scanme.nmap.org

## UDP Scan (chưa ổn)

phantom scanme.nmap.org --ping-tech none --scan-tech udp --timeout 3
sudo nmap -Pn -sU -n -T5 scanme.nmap.org
