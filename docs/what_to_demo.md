# Demo 1: Kiến trúc CLI

Mục tiêu: Chứng minh tính Professional và Scalable.
Hành động:
Gõ lệnh: sudo python phantom.py --help

# Demo 2: Mặt Fast của ứng dụng

--> Mở 2 cửa terminal, cho PhantomSweep và Nmap chạy cùng để xem ai hoàn thành trước

## Host Discovery with ICMP Ping --> Ngang ngửa T5 của Nmap và phát hiện được nhiều host hơn

phantom 10.0.21.0/24 --ping-tech icmp --scan-tech none
sudo nmap -sn -PE -n --send-ip -T5 10.0.21.0/24

## ARP Scan --> Ngang ngửa T5 Nmap và phát hiện được giống số lượng host

phantom 10.0.21.0/24 --ping-tech arp --scan-tech none
sudo nmap -sn -PR -n -T5 10.0.21.0/24

## ICMP Ping (discovery) + TCP Connect (port scan) --> Ăn đức Nmap

phantom scanme.nmap.org --ping-tech none --scan-tech connect --timeout 3
sudo nmap -Pn -sT -T5 scanme.nmap.org

# Demo 3: Tính năng Service & Version Detection mode NORMAL

phantom 10.0.21.0/24 --service-detection-mode normal

# Demo 4: Tính năng OS Fingerprinting mode AI

phantom 10.0.21.0/24 --os-fingerprinting-mode ai

# Demo 5: Tính năng Custom Script Running

phantom scanme.nmap.org --script http_headers

# Demo 6: Tính năng xuất kết quả ra các định dạng

--> Tự tìm lệnh

# Demo 7: Tính năng Evasion with AI

--> Để xem thầy Bin sao

# Demo 8: Khả năng scale

--> Kéo thả file host discovery technique ra chỗ khác và check CLI thì thấy mất, kéo bỏ vô lại thì thấy load được

# Demo 8: Các tính năng lặt vặt

-   Cách chỉ định host và port cực đa dạng và linh hoạt
-   In example cho tham khảo
-   Khả năng in debug, verbose, all-port
