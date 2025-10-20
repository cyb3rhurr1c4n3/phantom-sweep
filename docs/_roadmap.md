# NT140 - Roadmap

> **Mục tiêu chung:** Xây dựng một công cụ quét mạng mạnh mẽ, sử dụng kiến trúc **Asyncio** để đạt hiệu năng cao và tích hợp **Machine Learning** để tối ưu hóa tốc độ (**Adaptive Timing**) và nhận dạng hệ điều hành (**OS Fingerprinting**).
>
> **Thời gian:** 20/10 - 14/12

---

## 🏗️ Giai Đoạn 1: Nền Tảng & Hiệu Suất Tối Đa (20/10 - 2/11)

### 🎯 Nhiệm Vụ Kỹ Thuật (Tasks)

-   **Khởi tạo & Môi trường:**
    -   [ ] Thiết lập kho **GitHub** và cấu trúc dự án chuẩn.
    -   [ ] Cài đặt môi trường **Python 3**, thư viện **Scapy**, và **Asyncio**.
-   **Kiến trúc & Quét Cơ bản:**
    -   [ ] Xây dựng **CLI Parser** cơ bản (nhận Target, Port Range, Type Scan).
    -   [ ] Triển khai **Host Discovery** ban đầu (ARP Scan và ICMP Echo).
    -   [ ] Thiết lập kiến trúc **Bất đồng bộ (Asyncio)** cho việc quét cổng.
-   **Các kiểu Quét TCP:**
    -   [ ] Triển khai **TCP SYN Scan** (`-sS`) sử dụng Scapy (Yêu cầu quyền root).
    -   [ ] Triển khai **TCP Connect Scan** (`-sT`).
-   **Tối ưu hóa Ban đầu:**
    -   [ ] Tối ưu hóa giá trị **Timeout ban đầu** (Ví dụ: $0.5$s) để đảm bảo độ tin cậy.

### 📦 Sản Phẩm Cần Đạt (Deliverables)

-   [ ] 🛠️ **CLI** hoạt động, thực hiện **Host Discovery** cơ bản thành công.
-   [ ] ⚡️ Cả hai kiểu quét **TCP SYN** và **TCP Connect** hoạt động, có thể quét **1000 cổng** trong thời gian ngắn (mục tiêu: **dưới 30 giây**).

---

## 🔬 Giai Đoạn 2: Mở Rộng Tính Năng & Thu Thập Dữ Liệu AI (3/11 - 16/11)

### 🎯 Nhiệm Vụ Kỹ Thuật (Tasks)

-   **Quét & Khám phá:**
    -   [ ] Triển khai kiểu quét **UDP Scan** (`-sU`).
    -   [ ] Hoàn thiện **Host Discovery** (thêm TCP SYN/ACK Ping).
    -   [ ] Triển khai **Service Banner Grabbing** (đọc $1024$ bytes đầu tiên).
    -   [ ] Nhận dạng dịch vụ/phiên bản cơ bản (phân tích chuỗi banner).
-   **Định dạng Đầu ra:**
    -   [ ] Hoàn thiện định dạng đầu ra **JSON** và **CSV**.
    -   [ ] Thiết kế cấu trúc và triển khai output **Nmap-XML**.
-   **Chuẩn bị AI:**
    -   [ ] Xác định các thông số gói tin sẽ dùng cho AI (**TTL, Window Size, IHL, Latency**).
    -   [ ] **Thu thập Bộ dữ liệu thô** ($50-100$ host) cho mô hình AI.

### 📦 Sản Phẩm Cần Đạt (Deliverables)

-   [ ] 🏷️ Mọi kiểu quét (**TCP SYN/Connect, UDP**) hoạt động. Banner dịch vụ được hiển thị.
-   [ ] 📊 Kết quả được xuất ra **3 định dạng** chuẩn (JSON/CSV/XML). **Bộ dữ liệu AI** sẵn sàng.

---

## 🧠 Giai Đoạn 3: Tích Hợp AI & Mở Rộng Mô-đun (17/11 - 30/11)

### 🎯 Nhiệm Vụ Kỹ Thuật (Tasks)

-   **Mô-đun & Né tránh:**
    -   [ ] Thiết kế và xây dựng **Plugin Engine** (cơ chế tải và chạy script ngoài).
    -   [ ] Viết **02 Plugin mẫu** (ví dụ: Check FTP Anonymous Login, HTTP Method Discovery).
    -   [ ] Triển khai các tính năng **Evasive** (Rate-limit cố định, Random Host Order).
-   **AI Tính năng:**
    -   [ ] **AI 1 (Adaptive Timing):** Triển khai logic tự động điều chỉnh **`timeout`** và **`max-rate`** dựa trên phân tích độ trễ trung bình của $50$ gói tin đầu tiên.
    -   [ ] **AI 2 (OS Fingerprinting ML):** Xây dựng mô hình ML (**Scikit-learn Classifier**) để dự đoán HĐH dựa trên các đặc điểm gói tin đã thu thập.

### 📦 Sản Phẩm Cần Đạt (Deliverables)

-   [ ] 🔌 **Plugin Engine** hoạt động. Chức năng Evasion cơ bản tích hợp.
-   [ ] 🤖 **AI Adaptive Timing** hoạt động (tối ưu hóa tốc độ). **Mô hình OS Fingerprinting ML** hoạt động.

---

## 🚀 Giai Đoạn 4: Kiểm Thử Toàn Diện & Tổng Kết (1/12 - 14/12)

### 🎯 Nhiệm Vụ Kỹ Thuật (Tasks)

-   [ ] Xây dựng **Docker Testbed** (tạo $2-3$ container với dịch vụ/HĐH khác nhau).
-   [ ] **Kiểm thử toàn diện (End-to-end)** trên Docker Testbed.
-   [ ] Sửa lỗi, tối ưu hóa code và hiệu năng cuối cùng.
-   **Tài liệu & Báo cáo:**
    -   [ ] Viết bản nháp **Final Report** và **README.md** (bao gồm cảnh báo đạo đức/Ethical Disclosure).
    -   [ ] Hoàn thiện **Final Report** (đặc biệt tập trung vào **AI Architecture**).
    -   [ ] Thiết kế **Slide** thuyết trình chuyên nghiệp.
    -   [ ] **Ghi hình Video Demo** (5-7 phút) trình diễn các tính năng cốt lõi và đặc biệt là **AI Adaptive Timing** (minh họa tốc độ tối ưu).
    -   [ ] Bình luận (comment) code chi tiết và nộp sản phẩm cuối cùng.

### 📦 Sản Phẩm Cần Đạt (Deliverables)

-   [ ] 🐳 **Docker Testbed** hoạt động. **Code ổn định**, sẵn sàng cho demo.
-   [ ] ✅ Nộp đầy đủ mọi sản phẩm (**Final Report, Slide, Video Demo, Source Code**). **Dự án hoàn thành.**
