# NT140 - Proposal

## Tên dự án

PhantomSweep - A fast, lightweight and scalable network security scanner

## Mục tiêu

-   Xây dựng một công cụ quét mạng (network reconnaissance tool) **nhanh, nhẹ, dễ mở rộng** lấy cảm hứng từ Nmap/Masscan.
-   Giúp quản trị viên mạng, pentester và red teamer **khám phá hệ thống mục tiêu**: phát hiện host, cổng mở, dịch vụ, phiên bản, và hệ điều hành.
-   Tích hợp tính năng **plugin engine** để cho phép mở rộng chức năng quét bảo mật (ví dụ: check FTP anonymous login, HTTP risky methods, TLS weak protocols).
-   Xuất kết quả ở định dạng **human-readable + JSON + Nmap-XML** để dễ tích hợp vào các pipeline tự động (SIEM, CI/CD).
-   Đảm bảo công cụ vừa mang tính **học thuật** (phục vụ đồ án) vừa có giá trị **thực tiễn** (có thể đưa lên GitHub/CV như một open-source project).

## Yêu cầu

-   **Host discovery**: ICMP Echo, TCP SYN/ACK ping, ARP scan.
-   **Port scanning**: TCP SYN, TCP Connect, UDP scan.
-   **Service & version detection**: Thu thập banner, phân tích dịch vụ phổ biến.
-   **OS fingerprinting**: Dựa trên TTL, Window Size, TCP/IP stack behavior.
-   **Kết quả đầu ra**: Text dễ đọc, JSON cho máy móc xử lý, Nmap-XML/CSV (Nâng cao)
-   **Plugin engine**: Cho phép viết plugin nhỏ để mở rộng khả năng phát hiện lỗ hổng/dịch vụ.
-   **Tùy chọn evasive**: rate-limit, randomize host order, jitter,... (nâng cao)
-   **Docker testbed** đi kèm để demo và kiểm thử (nâng cao)

## Sản phẩm

-   Proposal
-   Final Report
-   Slide
-   Demo
-   Source code
