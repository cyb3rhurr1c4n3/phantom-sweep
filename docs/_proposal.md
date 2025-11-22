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
-   **Tích hợp AI**: tích hợp để khiến app trở nên dynamic, tích hợp vào OS fingerprinting, service and version detection, optimize time wait, rate-limit,...
-   **Docker testbed** đi kèm để demo và kiểm thử (nâng cao)

## Sản phẩm

-   Proposal
-   Final Report
-   Slide
-   Demo
-   Source code

## Các ý phát sinh
### Có thể scale ở những mặt nào và bằng cách nào?
#### Về hiệu suất: scale từ ít lên rất nhiều IP mà vẫn giữ được tốc độ quét nhanh. How?
--> Tham khảo kiến trúc của Masscan
#### Về tính năng: 
##### Scale về kỹ thuật quét (host discovery & port scanning). How?
--> Tạo các base class chứa các thuộc tính, phương thức bắt buộc cho mỗi kỹ thuật (plugin) quét. Khi thêm kỹ thuật mới thì chỉ cần kế thừa là đảm bảo có thể tích hợp được với ứng dụng.
##### Scale về script (thêm CVE mới, kỹ thuật kiểm thử mới, nhận diện lỗ hổng mới,...). How?
--> Cũng tạo ra base class chứa các thuộc tính, phương thức bắt buộc để mỗi script tuân theo (ví dụ run(scancontext, scanresult)).
##### Scale về định dạng xuất kết quả. How?
--> Cũng tạo ra base class chứa các thuộc tính, phương thức bắt buộc để mỗi plugin xuất phải tuân theo. Làm sao để Manager chỉ cần gọi đến reporter.export() mà không cần biết nó được code thế nào.
#### Về sự thông minh: 
##### Scale về độ thông minh (tính chính xác) của các tính năng AI. How?
--> Train lại hoặc update model với độ chính xác cao hơn và tích hợp lại một cách dễ dàng do ứng dụng đã có khuôn sẵn.
##### AI ngày càng mạnh mẽ và thông minh hơn qua quá trình sử dụng. How?
--> AI có khả năng học hỏi nên càng dùng nó sẽ càng thông minh.