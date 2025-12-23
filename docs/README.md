# 👻 PhantomSweep

### A Fast, Lightweight, Scalable & Smart Network Security Scanner

![Python Version](https://img.shields.io/badge/python-3.13.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange)

> **PhantomSweep** là công cụ quét mạng thế hệ mới, được thiết kế để kết hợp tốc độ của Masscan, tính linh hoạt của Nmap và sức mạnh của Trí tuệ Nhân tạo. Dự án tập trung vào khả năng trinh sát mạng với tốc độ cao, khả năng mở rộng đa dạng qua Plugin & Module Architecture và các tính năng tích hợp AI mạnh mẽ như OS Fingerprinting with AI, Evasion with AI.

---

## Demo

_[Chèn Video Youtube (or other things) demo tính năng tại đây]_

> _Xem video demo chi tiết tại: [Link]_

--> AE chèn demo vô đây

## Tại sao chọn PhantomSweep?

PhantomSweep được xây dựng dựa trên 4 trụ cột công nghệ:

### 1. Fast (Siêu tốc)

-   Sử dụng kỹ thuật lập trình bất đồng bộ **(Asyncio)** kết hợp với **Raw Sockets** để loại bỏ các tầng overhead của hệ điều hành.
-   Sử dụng 2 luồng riêt biệt **(Sender và Receiver)** giúp tránh thời gian chờ như Nmap.
-   Cơ chế **Pre-computed Packet Templates** giúp giảm thiểu chi phí CPU khi tạo gói tin.

> _Kết hợp với nhiều cơ chế tối ưu khác như **Batch Processing, Raw BPF, Smart Timeout,...** để vừa quét cực nhanh, vừa chính xác._

### 2. Lightweight (Siêu nhẹ)

-   Tối ưu hóa bộ nhớ: Sử dụng **Generators** thay vì Lists để xử lý hàng triệu IP mà không tràn RAM.
-   Chỉ tập trung vào các tính năng cốt lõi và quan trọng.
-   Hạn chế tối đa phụ thuộc thư viện.

> _Qua đó giúp PhantomSweep vừa đa dạng tính năng, vừa giữ được kích thước khiêm tốn (ngay cả khi tích hợp AI)._

### 3. Scalable (Dễ mở rộng)

-   **Kiến trúc Plugin-based:** Dễ dàng thêm kỹ thuật quét mới (Scan Tech), định dạng báo cáo mới (Output), hoặc script kiểm tra lỗ hổng mới,... mà **không cần sửa Core**.
-   Cơ chế **Dynamic Loading**: Tự động phát hiện và nạp plugin từ thư mục cấu hình.

> _Hỗ trợ sự phát triển của PhantomSweep trong tương lai._

### 4. Smart (Thông minh)

-   **AI OS Fingerprinting:**

-   **AI Evasion:**

---

## Các tính năng của PhantomSweep

## Cài đặt

## Hướng dẫn sử dụng

## Kiến trúc hệ thống

## So sánh hiệu năng

## Đóng góp (Contributing)

Chúng tôi hoan nghênh mọi đóng góp từ cộng đồng\!

1.  Fork dự án.
2.  Tạo Feature Branch (`git checkout -b feature/AmazingFeature`).
3.  Commit thay đổi (`git commit -m 'Add some AmazingFeature'`).
4.  Push lên Branch (`git push origin feature/AmazingFeature`).
5.  Mở Pull Request.

---

## 📜 Giấy phép & Tuyên bố miễn trừ

Dự án này được phát hành dưới giấy phép **MIT License**.

**⚠️ CẢNH BÁO:** PhantomSweep là công cụ được thiết kế cho mục đích **giáo dục** và **kiểm thử bảo mật hợp pháp**. Tác giả không chịu trách nhiệm cho bất kỳ hành vi sử dụng sai trái nào vào các hệ thống không được ủy quyền.

---

**Developed with ❤️ by Cyber_Threat Group - UIT**
