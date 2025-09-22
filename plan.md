
# P1-1: Thiết lập nền tảng dự án (Lead/Architect)

[ ] Khởi tạo kho chứa Git trên GitHub.

[ ] Thiết lập các nhánh (branches) chính: main và develop.

[ ] Tạo file pyproject.toml định nghĩa tên dự án, phiên bản 0.1.0.

[ ] Tạo file requirements.txt với các thư viện ban đầu (click, rich).

[ ] Tạo file .gitignore chuẩn cho dự án Python.

# P1-2 & P1-3: Thiết kế Lõi & Hệ thống Plugin (Lead/Architect)

[ ] Định nghĩa các lớp cơ sở trừu tượng (ScannerPluginBase, ReporterPluginBase) trong plugins/base.py.

[ ] Viết logic trong plugins/manager.py để tự động tìm và nạp các file plugin từ các thư mục con.

[ ] Định nghĩa lớp ScanContext trong core/context.py để chứa thông tin mục tiêu và kết quả quét.

[ ] Viết khung sườn cho core/engine.py, bao gồm hàm khởi tạo nhận cấu hình và hàm run() chính.

# P1-4: Xây dựng Giao diện CLI (CLI & UX)

[ ] Cài đặt thư viện click và cấu trúc file cli.py với command group chính.

[ ] Viết logic xử lý input mục tiêu (IP đơn, CIDR, domain).

[ ] Viết hàm xử lý tham số -p để phân tích chuỗi cổng (ví dụ: 80,443,1000-2000).

[ ] Viết hàm xử lý tham số -iL để đọc danh sách mục tiêu từ file.

[ ] Viết hàm xử lý tham số -oJ để lấy tên file output JSON.

# P1-5: Plugin Scanner #1: TCP Connect Scan (Plugin Dev - Scanners)

[ ] Tạo file scanners/tcp_connect_scan.py và lớp TCPConnectScanner kế thừa từ ScannerPluginBase.

[ ] Viết logic dùng thư viện socket để thực hiện một kết nối TCP đến một port cụ thể.

[ ] Xử lý các trường hợp: kết nối thành công (cổng mở), kết nối bị từ chối (cổng đóng), timeout (cổng bị lọc).

[ ] Định dạng kết quả trả về cho mỗi port (ví dụ: dictionary {'port': 80, 'status': 'open'}).

# P1-6 & P1-7: Plugins Reporter (Plugin Dev - Reporters)

[ ] Viết plugin reporters/console_reporter.py để in kết quả ra màn hình một cách rõ ràng.

[ ] Viết plugin reporters/json_reporter.py để chuyển đổi kết quả quét thành định dạng JSON và ghi ra file.

# P1-8: Tích hợp lần 1 (Tất cả thành viên)

[ ] Đảm bảo cli.py gọi đúng hàm trong engine.py với các tham số đã phân tích.

[ ] engine.py phải nạp và gọi được plugin TCPConnectScanner.

[ ] engine.py phải nạp và gọi được plugin ConsoleReporter hoặc JsonReporter để xuất kết quả.

[ ] Chạy thử nghiệm toàn bộ luồng với một mục tiêu và vài cổng để xác nhận mọi thứ hoạt động.


# P2-1: Tối ưu Hiệu suất bằng Đa luồng (Lead/Architect)

[ ] Nghiên cứu và chọn cách triển khai đa luồng (ví dụ: concurrent.futures.ThreadPoolExecutor).

[ ] Sửa lại hàm run() trong engine.py để đưa các tác vụ quét (mỗi host hoặc mỗi port) vào một hàng đợi.

[ ] Khởi tạo một pool các luồng để xử lý các tác vụ trong hàng đợi.

[ ] Viết logic để thu thập kết quả một cách an toàn từ tất cả các luồng.

# P2-2: Cải thiện CLI (CLI & UX)

[ ] Thêm logic xử lý tham số quét nhanh -F (sử dụng một danh sách cổng định sẵn).

[ ] Thêm logic xử lý tham số --exclude để loại bỏ mục tiêu khỏi danh sách quét.

[ ] Tích hợp thư viện rich hoặc tqdm để hiển thị một thanh tiến trình (progress bar) trong lúc quét.

# P2-3: Plugin Host Discovery (Plugin Dev - Scanners)

[ ] Tạo plugin scanners/icmp_ping.py để gửi gói tin ICMP Echo.

[ ] Tạo plugin scanners/tcp_ack_ping.py để gửi gói TCP ACK đến các cổng phổ biến (ví dụ: 80, 443).

# P2-4 & P2-5: Viết thêm Plugins (Plugin Dev - Reporters)

[ ] Viết plugin reporters/xml_reporter.py.

[ ] Viết các hàm kịch bản đơn giản http_title và ssl_cert và tích hợp vào engine để có thể gọi qua tham số --script.

# P2-6 & P2-7: Hoàn thiện & Viết Test (CLI & UX, Lead/Architect)

[ ] Dùng rich để thêm màu sắc cho output (cổng mở màu xanh, đóng màu xám, lọc màu vàng).

[ ] Viết các bài test đơn vị (unit test) cho các hàm xử lý input phức tạp (ví dụ: hàm phân tích chuỗi cổng).

[ ] Viết test tích hợp (integration test) đơn giản cho luồng quét cơ bản.


# P3-1: Plugin Scanner #2: TCP SYN Scan (Plugin Dev - Scanners)

[ ] Nghiên cứu cách dùng thư viện Scapy để tạo và gửi gói tin TCP.

[ ] Viết logic tạo gói tin SYN.

[ ] Viết logic gửi gói tin và lắng nghe gói trả lời (SYN/ACK hoặc RST).

[ ] Xử lý các trường hợp timeout.

[ ] Ghi chú rõ ràng rằng tính năng này yêu cầu quyền quản trị (root/administrator).

# P3-2: Tính năng OS Guessing (Lead/Architect)

[ ] Viết một module phân tích gói tin trả lời từ host.

[ ] Lấy ra giá trị TTL (Time-To-Live) từ gói tin ICMP hoặc TCP.

[ ] Viết logic so khớp giá trị TTL với các hệ điều hành phổ biến (ví dụ: TTL gần 64 -> Linux, gần 128 -> Windows).

# P3-3: Viết tài liệu (Tất cả thành viên)

[ ] Viết hướng dẫn cài đặt và sử dụng chi tiết trong README.md.

[ ] Viết hướng dẫn đóng góp (CONTRIBUTING.md), quy định về format code và quy trình pull request.

[ ] Viết tài liệu cho lập trình viên (docs/plugin_dev_guide.md) giải thích cách để tạo một plugin mới.

# P3-4 & P3-5: Test và Chuẩn bị Demo (Tất cả thành viên)

[ ] Mỗi thành viên kiểm tra chéo tính năng của thành viên khác.

[ ] Tạo một danh sách các lỗi tìm thấy và phân công nhau sửa.

[ ] Chuẩn bị kịch bản, slide và video để demo sản phẩm cuối cùng.