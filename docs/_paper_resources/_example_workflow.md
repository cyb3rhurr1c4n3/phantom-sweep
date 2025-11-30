Bước 1: Phân tích lệnh

-   Người dùng nhập lệnh từ màn hình
-   phantom_cli.py sẽ thực hiện phân tích và lưu trữ toàn bộ ngữ cảnh, option của lần quét vào ScanContext (core/scan_context.py)
    Bước 2: Thực thi
-   ScanContext sẽ được truyền cho Manager (module/manager.py)
-   Manager sẽ xem xét ngữ cảnh và quyết định quy trình quét như thế nào, kỹ thuật gì sẽ được dùng, bước nào sẽ chạy, bước nào sẽ bỏ qua, kết quả lưu ở định dạng gì,... (có 5 bước trong ScanPipeline và có thể bật tắt tùy ý: Host Discovery, Port Scanning, Service Detection, OS Fingerprinting, Custom Script Running).
-   Sau khi hiểu rõ, Manager sẽ gọi đến các module phù hợp và thực thi
-   Cuối cùng, Manager sẽ trả kết quả về ScanResult (core/scan_result.py)
    Bước 3: Trả kết quả ra console hoặc file theo tùy chọn
