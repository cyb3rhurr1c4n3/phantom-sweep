# [NT140] Tổng quan về đồ án An toàn mạng

## I. Tên đồ án:

PhantomSweep - A fast, lightweight and scalable network security scanner

## II. Mục tiêu:

-   Xây dựng một công cụ quét mạng (network reconnaissance tool) **nhanh, nhẹ, dễ mở rộng** lấy cảm hứng từ Nmap/Masscan.
-   Giúp quản trị viên mạng, pentester và red teamer **khám phá hệ thống mục tiêu**: phát hiện host, cổng mở, dịch vụ, phiên bản, và hệ điều hành.
-   Tích hợp tính năng **plugin engine** để cho phép mở rộng chức năng quét bảo mật (ví dụ: check FTP anonymous login, HTTP risky methods, TLS weak protocols).
-   Xuất kết quả ở định dạng **human-readable + JSON + Nmap-XML** để dễ tích hợp vào các pipeline tự động (SIEM, CI/CD).
-   Đảm bảo công cụ vừa mang tính **học thuật** (phục vụ đồ án) vừa có giá trị **thực tiễn** (có thể đưa lên GitHub/CV như một open-source project).

## III. Yêu cầu tối thiểu

### A. Yêu cầu về sản phẩm

-   **Host discovery**: ICMP Echo, TCP SYN/ACK ping, ARP scan.
-   **Port scanning**: TCP SYN, TCP Connect, UDP scan.
-   **Service & version detection**: Thu thập banner, phân tích dịch vụ phổ biến.
-   **OS fingerprinting**: Dựa trên TTL, Window Size, TCP/IP stack behavior.
-   **Kết quả đầu ra**:
-   Text dễ đọc.
-   JSON cho máy móc xử lý.
-   (High-impact) Hỗ trợ thêm Nmap-XML/CSV.
-   **Plugin engine**: Cho phép viết plugin nhỏ để mở rộng khả năng phát hiện lỗ hổng/dịch vụ.
-   **Tùy chọn evasive** (rate-limit, randomize host order, jitter).
-   **Docker testbed** đi kèm để demo và kiểm thử. (nâng cao)
-   Báo cáo, slide, demo

### B. Yêu cầu về đạo đức

-   **Chỉ sử dụng trong môi trường lab** hoặc khi được **ủy quyền rõ ràng** (hợp đồng pentest, CTF, bài lab học tập).
-   Không được sử dụng PhantomSweep để **tấn công hệ thống thật** mà không có sự cho phép.
-   Trong README/SECURITY.md ghi rõ cảnh báo pháp lý và khuyến cáo sử dụng.
-   Các tính năng “nguy hiểm” (ví dụ: decoy scan, default credential check) được **gated** bằng flag `--lab-only` hoặc yêu cầu xác nhận. (AI đề xuất cái này)

## IV. Ý nghĩa của việc làm đồ án

-   **Học thuật**: Củng cố kiến thức về TCP/IP, raw sockets, packet crafting (Scapy), đa luồng/bất đồng bộ, và cơ chế fingerprinting.
-   **Kỹ năng kỹ thuật**: Lập trình Python 3 nâng cao, thiết kế kiến trúc plugin engine, sử dụng Docker để xây dựng lab, viết test & CI.
-   **Kỹ năng nghề nghiệp**: Biết cách thiết kế một công cụ **modular, extensible, production-ready** (giống như tool thực tế trong pentest & security engineering).
-   **Giá trị thực tiễn**: Có sản phẩm **open-source** hoàn chỉnh (repo GitHub, README chi tiết, video demo, CI/CD, sample output) → thêm vào CV như một dự án thực tế.

## V. Cần phải làm gì để đồ án có giá trị cao

-   Đối xử sản phẩm như một dự án thực tế chứ không chỉ là đồ án môn học
-   Tập trung vào các tính năng có giá trị cao như:
    -   plugin engine và các plugin bổ sung
    -   xuất output phù hợp để làm đầu vào cho các tool khác, quy trình khác
    -   Tạo thêm các flag để bypass các phòng thủ quét mạng cơ bản (evastion)

