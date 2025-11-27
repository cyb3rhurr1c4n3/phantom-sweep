# 👻 PhantomSweep: A Lightweight, Scalable Network Security Scanner

## Giới thiệu

**PhantomSweep** là một công cụ trinh sát mạng (network reconnaissance tool) trên giao diện dòng lệnh (CLI), lấy cảm hứng từ Nmap và Masscan. Được xây dựng với mục tiêu **nhanh chóng, nhẹ nhàng và dễ mở rộng**, PhantomSweep giúp quản trị viên mạng, pentester và red teamer nhanh chóng vẽ ra bản đồ một mạng lưới, phát hiện host đang hoạt động, xác định các cổng mở, dịch vụ đang chạy, và đoán Hệ điều hành (OS).

Đây là sản phẩm đồ án môn **An toàn mạng máy tính**, tập trung vào việc áp dụng kiến thức về TCP/IP, raw sockets và thiết kế kiến trúc phần mềm modular.

## ✨ Các Tính năng Nổi bật

| Tính năng | Mô tả | Trạng thái |
| :--- | :--- | :--- |
| **Phát hiện Host (Host Discovery)** | Hỗ trợ ICMP Echo, TCP SYN/ACK Ping, và ARP Scan (trên mạng cục bộ). | Chưa hoàn thành |
| **Quét Cổng (Port Scanning)** | Triển khai các kiểu quét hiệu quả: **TCP SYN (Stealth)**, **TCP Connect**, và **UDP Scan**. | Chưa hoàn thành |
| **Nhận dạng Dịch vụ & Phiên bản** | Thu thập banner từ các cổng mở để xác định chính xác dịch vụ (ví dụ: `Apache/2.4.41`, `OpenSSH_8.2p1`). | Chưa hoàn thành |
| **Nhận dạng HĐH (OS Fingerprinting)** | Phân tích các đặc điểm của TCP/IP stack (TTL, Window Size) để đưa ra dự đoán về HĐH mục tiêu. | Chưa hoàn thành |
| **Plugin Engine** (High-Impact) | Kiến trúc plugin cho phép mở rộng khả năng kiểm tra bảo mật (ví dụ: check FTP Anonymous Login, check HTTP risky methods). | Chưa hoàn thành |
| **Kỹ thuật Evasion** | Hỗ trợ rate-limit gói tin và random host order để tránh bị phát hiện bởi IDS/IPS cơ bản. | Chưa hoàn thành |
| **Định dạng Đầu ra** | Hỗ trợ **JSON**, **CSV**, và **Nmap-XML** (để dễ dàng tích hợp với các công cụ khác). | Chưa hoàn thành |

## 🚀 Cài đặt

### Yêu cầu
- Tạm chưa có

### Các bước cài đặt
- Tạm chưa có

## 💻 Hướng dẫn Sử dụng (CLI)
- Tạm chưa có

## 🛠️ Docker Testbed
- Tạm chưa có

## ⚠️ Cảnh báo Đạo đức & Pháp lý

### ⚖️ Chỉ sử dụng hợp pháp

**PhantomSweep** là một công cụ bảo mật được tạo ra với mục đích học tập và kiểm thử hệ thống.

  * **KHÔNG ĐƯỢC PHÉP** sử dụng công cụ này để quét hoặc tấn công bất kỳ hệ thống nào mà bạn **không được ủy quyền rõ ràng và bằng văn bản**.
  * Việc quét mạng mà không có sự đồng ý của chủ sở hữu là hành vi bất hợp pháp và có thể dẫn đến hậu quả pháp lý nghiêm trọng.

**Sử dụng có trách nhiệm và tuân thủ pháp luật.**

## 🎓 Tóm tắt Kỹ thuật và Kiến trúc

Dự án được xây dựng trên nền tảng **Python 3** với kiến trúc **Modular** và sử dụng các công nghệ cốt lõi sau:

  * **Scapy:** Được sử dụng để tạo và phân tích các gói tin mạng cấp thấp (raw sockets), đảm bảo độ chính xác và tốc độ cho các kiểu quét như TCP SYN.
  * **Asyncio/Multi-threading:** Áp dụng kiến trúc bất đồng bộ hoặc đa luồng để xử lý đồng thời hàng nghìn kết nối mạng, tối ưu hóa hiệu năng quét.
  * **Plugin Engine:** Thiết kế theo mô hình Command Pattern, cho phép người dùng dễ dàng viết và tích hợp các module kiểm tra bảo mật mới mà không cần chỉnh sửa Core Engine.

## 🤝 Đóng góp

Mọi đóng góp (pull requests, báo cáo lỗi) đều được hoan nghênh. Vui lòng tham khảo `CONTRIBUTING.md` để biết chi tiết.

## 📄 Giấy phép

Dự án này được cấp phép theo Giấy phép **MIT**. Xem file `LICENSE` để biết thêm chi tiết.

-----

**(C) 2024 [Nhóm 10] - Đồ án Môn An toàn mạng máy tính.**