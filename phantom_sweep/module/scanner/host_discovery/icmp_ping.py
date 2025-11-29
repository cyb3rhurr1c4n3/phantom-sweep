import asyncio
import socket
import time
import struct
from typing import Set, List
from dataclasses import dataclass
from phantom_sweep.module._base import ScannerBase

# Tự tạo template ICMP để sử dụng lại, tránh tạo đối tượng bằng Scapy vì mỗi lần chạy vì cực tốn tài nguyên
@dataclass
class ICMPPacket:
    # Echo Request
    type: int = 8
    code: int = 0 
    checksum: int = 0
    identifier: int = 0x5043 # 'PC' in hex
    sequence: int = 1
    payload: bytes = b'PhantomSweep'

    def to_bytes(self) -> bytes:

        # Tạo header chưa tính checksum
        header = struct.pack('!BBHHH', self.type, self.code, 0, self.identifier, self.sequence)
        data = header + self.payload

        # Tính checksm sau khi đã có packet tổng thể
        checksum = self._calculate_checksum(data)

        # Tạo lại header với thông tin checksum đã tính được
        header = struct.pack('!BBHHH', self.type, self.code, checksum, self.identifier, self.sequence)

        return header + self.payload

    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        total = 0
        
        # Cộng từng cặp byte (16-bit word)
        for i in range(0, len(data) - 1, 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
        
        # Nếu còn 1 byte lẻ
        if len(data) % 2 == 1:
            total += data[-1] << 8
        
        # Cộng carry bits
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        
        # One's complement (đảo bit)
        return ~total & 0xFFFF

# Class chính
class ICMPScanner(ScannerBase):
    
    # ========== Các hàm hỗ trợ cho dynamic module loading ==========
    @property
    def name(self) -> str:
        return "icmp"
    
    @property
    def type(self) -> str:
        return "host_discovery"
    
    @property
    def description(self) -> str:
        return "ICMP Echo Request (Ping) Discovery"
    
    def requires_root(self) -> bool:
        return True
     
    # ========== Các hàm chính ==========

    def __init__(self):
        self.discovered: Set[str] = set() # Biến tạm để lưu trữ kết quả quét
        self.packet_template = ICMPPacket() # Chỉ khởi tạo một lần, giảm đi cực nhiều tài nguyên tạo đối tượng

    # Scan interface để manager gọi
    def scan(self, context, result) -> None:
        hosts = context.targets.host
        if not hosts:
            return
        
        # Dùng biến này để lưu kết quả scan, clear để reset mỗi lần scan
        self.discovered.clear()

        try:
            asyncio.run(self._async_scan(context, result, hosts))
        except PermissionError:
            print("[!] Raw socket requires root/admin privileges!!!")
            print("[!] Run with: sudo python phantomsweep.py")
            return
        except Exception as e:
            if context.debug:
                print(f"[!] ICMP Scan error: {e}")
                import traceback
                traceback.print_exc()

    # ========== Ultilities ==========

    # Real scan logic
    async def _async_scan(self, context, result, hosts: List[str]):
        # Bước 1 - Tạo raw socket (need root)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Bước 2 - Ghi đè buffer mặc định của socket để chứa nhiều packet hơn (tránh mất gói vì sẽ gửi cực và nhận cực nhiều trong thời gian ngắn) 
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20) # 1MB
        recv_sock.setblocking(False) # Tắt chế độ blocking

        if context.debug:
            print(f"[DEBUG] ICMP sockets created")

        # Bước 3 - Bật receiver trước khi gửi packets
        recv_task = asyncio.create_task(self.listening(recv_sock, set(hosts), context))
        await asyncio.sleep(0.01) # Chờ nó bật hẳn

        # Bước 4 - Gửi tất cả packet mà không chờ phản hồi
        start_time = time.time()
        sent_count = await self.sending(send_sock, hosts, context)
        send_duration = time.time() - start_time

        if context.debug:
            pps = sent_count / send_duration if send_duration > 0 else 0
            print(f"[DEBUG] Sent {sent_count} ICMP packets in {send_duration:.3f}s ({pps:.0f} pps)")

        # Bước 5 - Đợi reply với chiến thuật timeout thông minh
        timeout = self.calculate_smart_timeout(len(hosts), context)
        if context.debug:
            print(f"[DEBUG] ICMP timeout: {timeout:.1f}s")

        try:
            await asyncio.wait_for(self.wait_for_completion(hosts, timeout), timeout=timeout)
        except asyncio.TimeoutError:
            pass

        # Bước 6 - Dừng receiver và đóng socket
        recv_task.cancel()
        try:
            await recv_task
        except asyncio.CancelledError:
            pass
        send_sock.close()
        recv_sock.close()

        # Bước 7 - Cập nhật kết quả
        for host in hosts:
            if host in self.discovered:
                result.add_host(host, state="up")
            else:
                result.add_host(host, state="down")

    async def sending(self, sock: socket.socket, hosts: List[str], context) -> int:
        # Chuẩn bị dữ liệu
        packet_bytes = self.packet_template.to_bytes()
        sent_count = 0
        pps = 1000 # Sau này sẽ thêm performence option sau
        batch_size = min(100, max(10, pps // 10)) # 10 - 100 packets/batch

        if context.debug:
            print(f"[DEBUG] ICMP rate: {pps} pps, batch: {batch_size}")

        # Gửi theo batch 
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i : i + batch_size]
            for host in batch:
                try:
                    sock.sendto(packet_bytes, (host, 0)) # Gửi ICMPPacket dạng byte đến port 0 của host
                    sent_count += 1
                except Exception as e:
                    if context.debug:
                            print(f"\t[!] Failed to send to {host}: {e}")
            # Sleep để giữ packet / second
            if i + batch_size < len(hosts):
                sleep_time = batch_size / pps
                await asyncio.sleep(sleep_time)

        return sent_count
    
    async def listening(self, sock: socket.socket, expected_hosts: Set[str], context):
        loop = asyncio.get_event_loop()
        
        while True:
            try:
                # Non-blocking receive
                data, addr = await loop.sock_recvfrom(sock, 1024)
                source_ip = addr[0]
                
                # DEBUG: Log all received packets
                if len(data) >= 20:  # IP header tối thiểu
                    ip_header_len = (data[0] & 0x0F) * 4
                    
                    # Validate bounds
                    if len(data) > ip_header_len and ip_header_len >= 20:
                        icmp_type = data[ip_header_len]
                        if icmp_type == 0:
                            if source_ip in expected_hosts and source_ip not in self.discovered:
                                self.discovered.add(source_ip)
                                if context.verbose:
                                    print(f"\t[+] Host {source_ip} is up")
                            elif source_ip not in expected_hosts and context.debug:
                                print(f"\t[!] Reply from {source_ip} not in expected hosts")
                
            except BlockingIOError:
                # No data available, sleep briefly
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                break
            except Exception as e:
                if context.debug:
                    print(f"[!] Receive error: {e}")
                await asyncio.sleep(0.01)
    
    async def wait_for_completion(self, hosts: List[str], max_timeout: float):
        """
        Đợi cho đến khi:
        1. Tìm được tất cả hosts, HOẶC
        2. Timeout
        
        Sử dụng exponential backoff để giảm CPU usage
        """
        start_time = time.time()
        check_interval = 0.02 # Bắt đầu check mỗi 20ms
        max_interval = 0.5 # Tối đa check mỗi 500ms

        while (time.time() - start_time) < max_timeout:
            if len(self.discovered) >= len(hosts): # Dừng sớm nếu tìm được hết
                return
            await asyncio.sleep(check_interval)

            # Exponential backoff: check ít dần (hầu hết replies đến sớm)
            check_interval = min(check_interval * 1.3, max_interval)
    
    def calculate_smart_timeout(self, num_hosts: int, context) -> float:
        """
        Tính timeout thông minh dựa trên:
        - Số lượng hosts
        - Base timeout từ config
        - Network conditions (RTT)
        """
        base = getattr(context.performance.timeout, 'timeout', 3.0)

        # Formula được tune cho performance tốt:
        # - Scan nhỏ (<100): base + 0.5s
        # - Scan vừa (100-1000): base + 1-3s  
        # - Scan lớn (>1000): base + 5s (hầu hết replies đến nhanh)

        if num_hosts <= 100:
            timeout = base + 0.5
        elif num_hosts <= 1000:
            timeout = base + 1.0 + ((num_hosts - 100) / 1000.0) * 2.0
        else:
            timeout = base + 5.0

        return max(2.0, min(30.0, timeout))