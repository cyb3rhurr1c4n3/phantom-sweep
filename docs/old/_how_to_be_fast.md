# Làm sao để PhantomSweep nhanh hơn Nmap?
--> Không thể tối ưu vì C (Nmap) nhanh hơn Python (PhantomSweep) rất nhiều. Chỉ còn giải pháp là tham khảo từ kiến trúc quét Masscan

# Tại sao Nmap lại chậm hơn Masscan rất nhiều???
### Nmap – dùng TCP/IP stack của hệ điều hành
Khi Nmap gửi một gói SYN, nó thường gửi qua kernel networking stack của OS. Kernel quản lý kết nối (socket, port, handshake, retransmission, timeout, buffer…). Điều này giúp đảm bảo độ chính xác và tương thích, nhưng: 
- Kernel chỉ cho phép một lượng kết nối đồng thời giới hạn (thường vài nghìn). 
- Mỗi kết nối có overhead về memory, context switching, timeout. 
- Khi quét hàng trăm nghìn IP, kernel trở thành điểm nghẽn (bottleneck).

--> Kết quả: Nmap rất chậm nếu quét diện rộng vì bị giới hạn bởi kernel.

### Masscan – viết TCP/IP stack riêng, “bỏ qua” kernel
Masscan không dùng socket bình thường. Nó tự tạo, gửi và nhận gói tin thô (raw packets) trực tiếp qua NIC. Có nghĩa là: 
- Nó không thiết lập kết nối thật (không handshake TCP 3-way).
- Nó không cần quản lý trạng thái của hàng triệu kết nối.
- Mỗi gói tin là “fire-and-forget” (bắn ra và quên luôn)
- Việc này cho phép Masscan gửi hàng triệu gói mỗi giây mà không cần đợi phản hồi.

--> Kết quả: tốc độ tăng lên hàng nghìn lần — chủ yếu giới hạn bởi băng thông mạng và tốc độ NIC chứ không phải CPU/kernel.

# Cách triển khai vào PhantomSweep
--> Áp dụng kiến trúc **Raw Socket Bất đồng bộ** với hai luồng chính của **Masscan**. Giải pháp này giúp vượt qua giới hạn của TCP stack trong hệ điều hành, đảm bảo tốc độ cực nhanh cho mọi quy mô quét. 
--> Tạo hai luồng riêng cho mỗi lần quét
- Một luồng gửi nhanh các gói tin cho toàn bộ đối tượng quét
- Một luồng lắng nghe độc lập các phản hồi.

### Luồng 1: Sender (Bộ Gửi gói tin)
#### Mục đích
- Gửi gói tin thăm dò TCP SYN đến tất cả các cổng và host được chỉ định trong file cấu hình Context với tốc độ cực nhanh, không chờ phản hồi.
- Có thể áp dụng tính năng tối ưu thời gian timeout vô đây để tối ưu thêm 1 bước nữa
#### Cách thức triển khai: Tích hợp logic gửi gói vào lớp Scanner.
- Kỹ thuật: Sử dụng hàm send() của Scapy trong luồng asyncio để hoạt động ở cấp độ raw socket (Layer 3/4), bỏ qua TCP stack của hệ điều hành.
- (nếu triển khai AI rồi) Manager yêu cầu tham số như ratelimit, blabla từ AITimingAdapter.
- Luồng Sender áp dụng rate_limit và timeout (await asyncio.sleep(1/rate_limit)) được cung cấp bởi AI cho mỗi gói tin được gửi.

### Luồng 2: Receiver (Bộ Lắng nghe Phản hồi)
#### Mục đích
- Liên tục lắng nghe (sniff) tất cả các gói tin đến trên giao diện mạng (interface) trong một khoảng thời gian cố định.
- Lọc các phản hồi SYN/ACK và RST để xác định trạng thái cổng.
#### Cách thức triển khai:: Tạo một phương thức lắng nghe và chạy nó trong một tác vụ asyncio riêng biệt.
- Kỹ thuật: Sử dụng hàm sniff() của Scapy với BPF filter (ví dụ: tcp and src host {target_ip}).
- Xử lý Dữ liệu: Khi nhận được gói tin, hàm xử lý (callback function) sẽ trích xuất:
	- Trạng thái Cổng (SYN/ACK = Mở, RST = Đóng).
	- Các trường dữ liệu quan trọng cho AI: TTL, Window Size, Latency (thời gian từ lúc gửi đến lúc nhận).
- Lưu trữ: Kết quả được lưu vào một cấu trúc dữ liệu chung (ví dụ Class Result như đã đề xuất).