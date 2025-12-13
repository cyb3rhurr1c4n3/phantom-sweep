# 👻 PhantomSweep

### A Fast, Lightweight, Scalable & Smart Network Security Scanner

![Python Version](https://img.shields.io/badge/python-3.13.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange)

> **PhantomSweep** là công cụ quét mạng thế hệ mới, được thiết kế để kết hợp tốc độ của Masscan, tính linh hoạt của Nmap và sức mạnh của Trí tuệ Nhân tạo (AI). Dự án tập trung vào khả năng trinh sát mạng với tốc độ cao, khả năng mở rộng tính năng qua Plugin & Module Architecture, và sự thông minh với các tính năng như OS Fingerprinting with AI, Evasion with AI.

---

## Demo

```Hoàn thành phần này
*[Chèn Link GIF hoặc Video Youtube Demo tính năng AI Evasion và Tốc độ quét tại đây]*
> *Xem video demo chi tiết tại: [Link Youtube]*
```

## Tại sao chọn PhantomSweep?

PhantomSweep được xây dựng dựa trên 4 trụ cột công nghệ:

### 1. Fast (Siêu tốc)

-   Sử dụng kiến trúc **Asyncio** kết hợp với **Raw Sockets** để loại bỏ các tầng overhead của hệ điều hành.
-   Hỗ trợ quét **Stateless** (tương tự Masscan) cho tốc độ lên đến hàng nghìn gói tin/giây.
-   Cơ chế **Pre-computed Packet Templates** giúp giảm thiểu chi phí CPU khi tạo gói tin.
    --> Kết hợp với các cơ chế khác để vừa quét cực nhanh, vừa chính xác.

### 2. Lightweight (Siêu nhẹ)

-   Tối ưu hóa bộ nhớ: Sử dụng **Generators** thay vì Lists để xử lý hàng triệu IP mà không tràn RAM.
-   Chỉ tập trung vào các tính năng cốt lõi và quan trọng.
-   Hạn chế tối đa phụ thuộc thư viện.
    --> Qua đó giúp PhantomSweep vừa đa dạng tính năng, vừa giữ được kích thước khiêm tốn (ngay cả khi tích hợp AI).

### 3. Scalable (Dễ mở rộng)

-   **Kiến trúc Plugin-based:** Dễ dàng thêm kỹ thuật quét mới (Scan Tech), định dạng báo cáo mới (Output), hoặc script kiểm tra lỗ hổng mới,... mà **không cần sửa Core**.
-   Cơ chế **Dynamic Loading**: Tự động phát hiện và nạp plugin từ thư mục cấu hình.
    --> Hỗ trợ sự phát triển của PhantomSweep trong tương lai.

### 🧠 4. Smart (Thông minh)

-   **AI OS Fingerprinting:**

-   **AI Evasion (Reinforcement Learning):**

--> Hoàn thiện phần này

---

# Những gì cần phải có trong README

-

## Các tính năng

-   Nói về ScanPipeline 6 phần ứng dụng: Host Discovery --> Port Scanning --> Service & Version Detection --> OS Fingerprinting --> Custom Script Running --> Output Formatting
