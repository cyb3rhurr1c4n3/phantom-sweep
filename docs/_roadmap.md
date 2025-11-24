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
-   **Kiến trúc cơ bản**
    -   [ ] Thiết lập kiến trúc **Bất đồng bộ (Asyncio)** cho việc quét cổng.
    -   [ ] Xây dựng **CLI Parser** cơ bản (Target Specification, Type Scan, Other Option).
    -   [ ] Xây dựng **Context schema** để lưu trữ ngữ cảnh, option, flag cho lần chạy lệnh.
    -   [ ] Xây dựng **Manager** để quản lý việc kết nối giữa tất cả các thành phần.
    -   [ ] Xây dựng **Plugin Engine**
    -   [ ] Xây dựng **Report Engine**
    -   [ ] Xây dựng **Script Engine**
    -   [ ] Triển khai module **Host Discovery** (ICMP Echo, TCP SYN/ACK ping, ARP scan).
    -   [ ] Triển khai module **Port Scanning** (TCP SYN, TCP Connect, UDP scan).
-   **Tiền AI**
    -   [ ] Xác định các tính năng sẽ dùng cho AI (ví dụ thông số gói tin (**TTL, Window Size, IHL, Latency**); Tính năng OS Fingerprinting)
-   **Tối ưu hóa Ban đầu:**
    -   [ ] Tối ưu hóa giá trị **Timeout ban đầu** (Ví dụ: $0.5$s) để đảm bảo độ tin cậy.
    -   [ ] Tối ưu hóa tốc độ quét, ít nhất phải bằng 90% Nmap

### 📦 Sản Phẩm Cần Đạt (Deliverables)

-   [ ] Kiến trúc ứng dụng hoạt động tốt (CLI -> Context -> Manager -> Các Engine)
-   [ ] Xác định rõ tính ứng dụng của AI trong dự án này
-   [ ] Thực hiện **Host Discovery** thành công với tốc độ lớn hơn hoặc bằng 90% Nmap
-   [ ] Thực hiện **Port Scanning** thành công với tốc độ lớn hơn hoặc bằng 90% Nmap

---

## 🔬 Giai Đoạn 2: Mở Rộng Tính Năng & Tích hợp AI (3/11 - 16/11)

### 🎯 Nhiệm Vụ Kỹ Thuật (Tasks)

-   **Triển khai hai tính năng còn lại**
    -   [ ] Triển khai **Service & Version Detection** bằng AI: Thu thập banner từ các cổng đang mở để xác định dịch vụ đang chạy (ví dụ: "Apache/2.4.41", "OpenSSH_8.2p1").
    -   [ ] Triển khai **OS Fingerprinting** bằng AI: Triển khai các kỹ thuật fingerprinting chủ động hoặc bị động cơ bản (Dựa trên TTL, Window Size, TCP/IP stack behavior.)
-   **Định dạng Đầu ra:**
    -   [ ] Hoàn thiện định dạng đầu ra **JSON** và **CSV**.
    -   [ ] Thiết kế cấu trúc và triển khai output **Nmap-XML**.
-   **Chuẩn bị AI:**

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
