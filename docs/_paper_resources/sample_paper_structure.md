# TÊN ĐỀ TÀI ĐỀ XUẤT

Tiếng Việt: PhantomSweep: Kiến trúc Quét mạng Hướng Module tích hợp Trí tuệ Nhân tạo cho Trinh sát Tốc độ cao và Khả năng Thích ứng.

Tiếng Anh: PhantomSweep: A Modular, AI-Enhanced Architecture for High-Speed and Adaptive Network Reconnaissance.

---

# CẤU TRÚC BÀI BÁO (OUTLINE)

## Tóm tắt (Abstract)

-   **Vấn đề:** Các công cụ quét mạng hiện tại hoặc quá chậm (Nmap) hoặc thiếu tính năng phân tích sâu và khó mở rộng (Masscan). Việc tích hợp AI và thêm tính năng, công cụ đòi hỏi sửa đổi mã nguồn phức tạp.
-   **Giải pháp:** Giới thiệu **PhantomSweep** - một công cụ quét mạng mã nguồn mở viết bằng Python.
-   **Điểm mới (Contributions):**
    1. Kiến trúc **Module hóa động (Dynamic Loading)** cho phép mở rộng về nhiều mặt không giới hạn (ví dụ kỹ thuật Host Discovery, kỹ thuật Port Scanning, các engine xuất định dạng, các script,...)
    2. Tích hợp **AI (Machine Learning)** vào phát hiện dịch vụ (Service Detection), nhận diện hệ điều hành (OS Fingerprinting) và cơ chế né tránh (Evasion).
    3. Thiết kế hướng tới hiệu năng cao (Lightweight & Fast) sử dụng kiến trúc bất đồng bộ (Asyncio).
-   **Kết quả:** Chứng minh được khả năng mở rộng dễ dàng và độ chính xác của mô hình AI so với các phương pháp truyền thống.

## 1. Giới thiệu (Introduction)

-   **1.1. Bối cảnh:** Tầm quan trọng của Network Reconnaissance trong bảo mật. Sự bùng nổ của thiết bị IoT và Cloud làm tăng bề mặt tấn công.
-   **1.2. Vấn đề nghiên cứu:** Hạn chế của các công cụ hiện có (Nmap dựa trên quy tắc tĩnh, khó tích hợp AI; Masscan nhanh nhưng thiếu ngữ cảnh).
-   **1.3. Mục tiêu của PhantomSweep:** Fast, Lightweight, Scalable, Smart.

## 2. Các công trình liên quan (Related Work)

-   **2.1. Nmap:** Phân tích cơ chế `nmap-os-db` (signature-based) và hạn chế về tốc độ quét dải rộng.
-   **2.2. Masscan/ZMap:** Phân tích cơ chế Stateless scanning (quét phi trạng thái) và hạn chế về độ chính xác thông tin dịch vụ.
-   **2.3. AI in Cybersecurity:** Tổng quan các nghiên cứu áp dụng ML vào OS Fingerprinting và IDS Evasion.

## 3. Kiến trúc Hệ thống (System Architecture) - _Trọng tâm "Scalable"_

_Đây là phần bạn đã làm tốt nhất, hãy viết sâu phần này._

-   **3.1. Tổng quan kiến trúc:** Sơ đồ khối `CLI -> Context -> Manager -> Modules`.
-   **3.2. Cơ chế Dynamic Plugin Loading:**
    -   Mô tả cách `PluginManager` quét thư mục, tự động nạp class kế thừa từ `ScannerBase` hoặc `AnalyzerBase`.
    -   Lợi ích: Thêm kỹ thuật quét mới (ví dụ: SCTP scan) hoặc định dạng output mới mà không cần biên dịch lại hay sửa Core.
-   **3.3. Luồng dữ liệu (Scan Pipeline):**
    -   Mô tả quy trình linh hoạt: `Host Discovery -> Port Scan -> (Conditional) -> Service/OS/Script`.
    -   Giải thích cơ chế phụ thuộc dữ liệu (Data Dependency) giúp tối ưu hiệu năng (chỉ chạy bước sau khi bước trước có kết quả).

## 4. Phương pháp Đề xuất (Proposed Methodology) - _Trọng tâm "Smart" & "Fast"_

-   **4.1. Tối ưu hóa Hiệu năng (Fast & Lightweight):**
    -   Mô hình I/O Bất đồng bộ (Asyncio): Giải thích lý thuyết về việc xử lý hàng nghìn kết nối đồng thời so với đa luồng truyền thống.
    -   _Lưu ý:_ Nếu chưa xong Raw Socket, hãy mô tả đây là "Kiến trúc được thiết kế" (Designed Architecture).
-   **4.2. Nhận diện HĐH thông minh (AI-based OS Fingerprinting):**
    -   **Feature Engineering:** Mô tả các đặc trưng gói tin TCP/IP được chọn (TTL, Window Size, DF bit, TCP Options ordering).
    -   **Mô hình:** Sử dụng Random Forest (hoặc mô hình bạn chọn).
    -   **Huấn luyện:** Mô tả bộ dữ liệu (dataset) và quá trình train.
-   **4.3. Cơ chế Né tránh Thích ứng (AI-Driven Evasion):**
    -   Mô tả thuật toán **Adaptive Timing**: Tự động điều chỉnh `timeout` và `rate` dựa trên độ trễ mạng (latency) phản hồi để tránh bị IDS phát hiện (Stealthy Mode).

## 5. Thực nghiệm và Đánh giá (Implementation & Evaluation)

-   **5.1. Môi trường thử nghiệm:** Docker Testbed (mô tả các container mục tiêu: Windows, Linux, Firewall).
-   **5.2. Đánh giá Khả năng Mở rộng (Scalability Test):**
    -   _Demo:_ Viết một plugin "Dummy Scanner" và hiển thị nó tự động xuất hiện trong CLI `--help`.
    -   _Kết quả:_ Chứng minh kiến trúc Plugin hoạt động trơn tru.
-   **5.3. Đánh giá AI OS Fingerprinting:**
    -   So sánh độ chính xác của PhantomSweep (AI Mode) với Nmap (Normal Mode) trên một tập mẫu các thiết bị (hoặc máy ảo) bị làm nhiễu banner.
-   **5.4. Đánh giá Hiệu năng (Sơ bộ):**
    -   So sánh thời gian quét TCP Connect giữa PhantomSweep và Nmap trên dải mạng nhỏ (chấp nhận kết quả tương đương hoặc PhantomSweep chậm hơn chút, nhưng nhấn mạnh vào tiềm năng của kiến trúc Asyncio).

## 6. Thảo luận và Hướng phát triển (Discussion & Future Work)

-   **6.1. Hạn chế hiện tại:** Thừa nhận tốc độ chưa đạt mức Masscan do đang trong giai đoạn chuyển đổi sang Raw Sockets hoàn toàn. Service Detection AI chưa hoàn thiện.
-   **6.2. Hướng phát triển:**
    -   Hoàn thiện Stateless Scanning (Raw Sockets) để đạt tốc độ "Insane".
    -   Mở rộng kho Plugin cộng đồng.
    -   Tích hợp AI Service Detection.

## 7. Kết luận (Conclusion)

-   Khẳng định PhantomSweep là một bước tiến trong việc xây dựng công cụ quét mạng thế hệ mới: Linh hoạt, Thông minh và Dễ tiếp cận cộng đồng.

---

### 💡 Mẹo nhỏ cho bài báo cáo của bạn

1. **Nhấn mạnh vào "Architecture" (Kiến trúc):** Vì bạn không kịp tối ưu tốc độ (Code), hãy bán cái "Thiết kế" (Design). Một thiết kế tốt (Modular, Asyncio) có giá trị khoa học rất cao vì nó là nền tảng cho sự phát triển lâu dài.
2. **AI là điểm nhấn:** Dù model AI của bạn đơn giản, hãy trình bày kỹ về quy trình: _Thu thập dữ liệu -> Trích chọn đặc trưng -> Huấn luyện_. Đây là quy trình chuẩn của một bài báo khoa học.
3. **Proof of Concept:** Với các tính năng chưa hoàn thiện (như Evasion phức tạp), hãy trình bày nó ở dạng ý tưởng thuật toán (Algorithm/Pseudocode) trong phần 4, và ghi vào phần Future Work là "đang cài đặt".

Sườn bài này vừa vặn với những gì bạn đang có (Draft), đồng thời vẽ ra một bức tranh đủ lớn và khoa học cho phiên bản Final.
