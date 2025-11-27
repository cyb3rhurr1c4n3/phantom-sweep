1. Người dùng chạy lệnh: netprobe -sS -oJ report.json 192.168.1.0/24

2. cli.py phân tích lệnh, hiểu rằng:

    Kiểu quét: sS

    Định dạng output: oJ (JSON)

    Mục tiêu: 192.168.1.0/24

3. cli.py khởi tạo engine.py và truyền cấu hình vào.

4. engine.py yêu cầu Plugin Manager tải tất cả các plugin.

5. Plugin Manager quét các thư mục, tìm thấy tcp_syn_scan.py và json_reporter.py.

6. engine.py lấy plugin tcp_syn_scan từ manager và sử dụng một bộ điều phối luồng (thread pool) để chạy phương thức scan() của plugin này trên tất cả các IP trong dải 192.168.1.0/24.

7. Kết quả quét được thu thập và lưu trong context.py.

8. Cuối cùng, engine.py lấy plugin json_reporter và gọi phương thức report() của nó để ghi kết quả từ context ra file report.json.