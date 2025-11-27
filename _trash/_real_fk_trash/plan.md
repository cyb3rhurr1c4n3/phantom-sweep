code cli
code base.py (base scanner,parse_ports)
code scanner (tcp_scanner,syn_scan,ping_scan) + tích hợp nó vào cli
code reports
code manager.py tích hợp để điều phối các scanner và reports 
kiểm tra và tối ưu

chia 
triển khai base
triển khai context 
xây dựng tcp_scanner
xây dựng engine - tích hợp engine vào cli
mở rộng scanner
triển khai report
triển khai manager (run_scan điều phối engine và report)- tích hợp vào cli
