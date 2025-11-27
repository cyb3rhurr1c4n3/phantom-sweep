"""
ICMP Echo Host Discovery Scanner - Masscan-style with improved reliability
"""
import asyncio
import time
from typing import Set
from scapy.all import IP, ICMP, AsyncSniffer, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScannerBase

conf.verb = 0


# class ICMPPingScanner(ScannerBase):
#     """ICMP Echo Request (Ping) Discovery - Reliable async scanning"""
    
#     @property
#     def name(self) -> str:
#         return "icmp"
    
#     @property
#     def type(self) -> str:
#         return "host_discovery"
    
#     @property
#     def description(self) -> str:
#         return "ICMP Echo Request (Ping) Discovery"
    
#     def requires_root(self) -> bool:
#         return True
    
#     def scan(self, context: ScanContext, result: ScanResult) -> None:
#         """Perform ICMP ping host discovery"""
#         hosts = context.targets.host
#         if not hosts:
#             return
        
#         if context.verbose:
#             print(f"[*] Starting ICMP ping discovery on {len(hosts)} hosts...")
        
#         try:
#             asyncio.run(self._async_scan(context, result, hosts))
#         except Exception as e:
#             if context.debug:
#                 print(f"[!] ICMP scan error: {e}")
#                 import traceback
#                 traceback.print_exc()
    
#     async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
#         """Fire all ICMP packets and collect responses with adaptive waiting"""
#         discovered: Set[str] = set()
#         hosts_set = set(hosts)
        
#         # Use simple filter (faster) - check src in Python
#         bpf_filter = "icmp[icmptype] == icmp-echoreply"
        
#         # Packet handler
#         def handle_packet(pkt):
#             try:
#                 if pkt.haslayer(ICMP) and pkt.haslayer(IP):
#                     src = pkt[IP].src
#                     if src not in discovered and src in hosts_set:
#                         discovered.add(src)
#                         result.add_host(src, state="up")
#                         if context.verbose:
#                             print(f"  [+] {src} is up")
#             except:
#                 pass
        
#         # Start sniffer FIRST (before sending)
#         sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
#         sniffer.start()
        
#         # Give sniffer time to initialize
#         await asyncio.sleep(0.05)
        
#         # Fire ALL packets (batch send for speed)
#         start_send = time.time()
#         sent_count = 0
#         for host in hosts:
#             pkt = IP(dst=host) / ICMP(id=0x1234, seq=1)
#             try:
#                 send(pkt, verbose=0)
#                 sent_count += 1
#             except Exception as e:
#                 if context.debug:
#                     print(f"[DEBUG] Failed to send to {host}: {e}")
        
#         send_time = time.time() - start_send
#         if context.debug:
#             print(f"[DEBUG] Sent {sent_count}/{len(hosts)} ICMP packets in {send_time:.3f}s")
        
#         # Adaptive timeout: longer for larger scans
#         # Base: min 2s, +0.5s per 100 hosts, max 30s
#         base_timeout = context.performance.timeout
#         adaptive_timeout = max(2.0, min(30.0, base_timeout + (len(hosts) / 100.0) * 0.5))
        
#         if context.debug:
#             print(f"[DEBUG] Waiting {adaptive_timeout:.1f}s for responses (base={base_timeout}s)")
        
#         # Wait for responses with proper async sleep
#         start_wait = time.time()
#         while (time.time() - start_wait) < adaptive_timeout:
#             await asyncio.sleep(0.05)
#             # Early exit if we found all hosts
#             if len(discovered) == len(hosts):
#                 if context.debug:
#                     print(f"[DEBUG] Found all {len(discovered)} hosts, exiting early")
#                 break
        
#         total_wait = time.time() - start_wait
#         sniffer.stop()
        
#         if context.debug:
#             print(f"[DEBUG] Response collection took {total_wait:.3f}s, found {len(discovered)} hosts")
        
#         # Mark undiscovered hosts as down
#         for host in hosts:
#             if host not in discovered:
#                 result.add_host(host, state="down")

"""
PhantomSweep - Ultra-Fast ICMP Scanner
Kết hợp tốc độ của Masscan với sự linh hoạt của Nmap
"""

import asyncio
import socket
import struct
import time
from typing import Set, List
from dataclasses import dataclass
from phantom_sweep.module._base import ScannerBase


@dataclass
class ICMPPacket:
    """ICMP Echo Request packet structure"""
    type: int = 8      # Echo Request
    code: int = 0
    checksum: int = 0
    identifier: int = 0x5043  # 'PC' in hex
    sequence: int = 1
    payload: bytes = b'PhantomSweep'
    
    def to_bytes(self) -> bytes:
        """Chuyển packet thành bytes để gửi"""
        # Pack header: type(1) + code(1) + checksum(2) + id(2) + seq(2)
        header = struct.pack('!BBHHH', 
                           self.type, self.code, 0,  # checksum tạm thời = 0
                           self.identifier, self.sequence)
        
        # Tính checksum cho toàn bộ packet
        data = header + self.payload
        checksum = self._calculate_checksum(data)
        
        # Pack lại với checksum đúng
        header = struct.pack('!BBHHH',
                           self.type, self.code, checksum,
                           self.identifier, self.sequence)
        
        return header + self.payload
    
    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """
        Tính ICMP checksum (RFC 1071)
        Đơn giản: cộng tất cả 16-bit words, lấy phần bù 1
        """
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


class RawSocketICMPScanner(ScannerBase):
    """
    Scanner ICMP siêu nhanh sử dụng raw socket
    Có thể đạt 10,000+ packets/giây
    """
    
    def __init__(self):
        self.discovered: Set[str] = set()
        self.packet_template = ICMPPacket()

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
            
    def scan(self, context, result) -> None:
        """Entry point cho scan"""
        hosts = context.targets.host
        if not hosts:
            return
        
        # Reset discovered set for each scan
        self.discovered.clear()
            
        if context.verbose:
            print(f"[*] 🚀 Ultra-fast ICMP scan on {len(hosts)} hosts...")
            
        try:
            # Chạy async scan
            asyncio.run(self._async_scan(context, result, hosts))
        except PermissionError:
            print("[!] ❌ Raw socket requires root/admin privileges")
            print("[!] Run with: sudo python phantomsweep.py")
            return
        except Exception as e:
            if context.debug:
                print(f"[!] Scan error: {e}")
                import traceback
                traceback.print_exc()
    
    async def _async_scan(self, context, result, hosts: List[str]):
        """Main async scanning logic"""
        
        # Bước 1: Tạo raw socket (cần root privileges)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Tăng buffer size cho socket nhận (tránh mất packets)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20)  # 1MB
        recv_sock.setblocking(False)  # Non-blocking mode
        
        if context.debug:
            print(f"[DEBUG] 📡 Created raw sockets (send + recv)")
        
        # Bước 2: Start receiver trước khi gửi packets
        receiver_task = asyncio.create_task(
            self._receive_replies(recv_sock, set(hosts), context)
        )
        
        # Chờ receiver sẵn sàng
        await asyncio.sleep(0.05)
        
        # Bước 3: Gửi tất cả ICMP packets siêu nhanh
        start_time = time.time()
        sent_count = await self._send_packets_fast(send_sock, hosts, context)
        send_duration = time.time() - start_time
        
        if context.verbose:
            pps = sent_count / send_duration if send_duration > 0 else 0
            print(f"[*] ⚡ Sent {sent_count} packets in {send_duration:.3f}s ({pps:.0f} pps)")
        
        # Bước 4: Đợi replies với timeout thông minh
        timeout = self._calculate_smart_timeout(len(hosts), context)
        
        if context.debug:
            print(f"[DEBUG] ⏳ Waiting {timeout:.1f}s for replies...")
        
        try:
            await asyncio.wait_for(
                self._wait_for_completion(hosts, timeout),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            pass
        
        # Bước 5: Dừng receiver và đóng sockets
        receiver_task.cancel()
        try:
            await receiver_task
        except asyncio.CancelledError:
            pass
        
        send_sock.close()
        recv_sock.close()
        
        # Bước 6: Update kết quả
        if context.verbose:
            print(f"[*] ✅ Discovery complete: {len(self.discovered)}/{len(hosts)} hosts alive")
        
        for host in hosts:
            if host in self.discovered:
                result.add_host(host, state="up")
            else:
                result.add_host(host, state="down")
    
    async def _send_packets_fast(self, sock: socket.socket, 
                                 hosts: List[str], context) -> int:
        """
        Gửi ICMP packets cực nhanh với rate limiting
        Technique: Batch sending + async sleep cho rate control
        """
        packet_bytes = self.packet_template.to_bytes()
        sent_count = 0
        
        # Lấy packets per second từ config (default 1000)
        pps = getattr(context.performance, 'packets_per_second', 1000)
        batch_size = min(100, max(10, pps // 10))  # 10-100 packets/batch
        
        if context.debug:
            print(f"[DEBUG] 📤 Sending with rate limit: {pps} pps, batch size: {batch_size}")
        
        # Gửi theo batches
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            
            # Gửi cả batch (rất nhanh vì không có async overhead)
            for host in batch:
                try:
                    sock.sendto(packet_bytes, (host, 0))
                    sent_count += 1
                except Exception as e:
                    if context.debug:
                        print(f"[DEBUG] ❌ Failed to send to {host}: {e}")
            
            # Rate limiting: sleep để maintain PPS
            if i + batch_size < len(hosts):
                sleep_time = batch_size / pps
                await asyncio.sleep(sleep_time)
        
        return sent_count
    
    async def _receive_replies(self, sock: socket.socket, 
                               expected_hosts: Set[str], context):
        """
        Nhận ICMP Echo Reply packets
        Chạy trong background task, không blocking
        
        FIX: Kiểm tra đúng ICMP type từ raw IP packet
        """
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
                        
                        if context.debug:
                            print(f"[DEBUG] Received packet from {source_ip}: IP_hdr_len={ip_header_len}, ICMP_type={icmp_type}")
                        
                        # Type 0 = Echo Reply - FIX: Remove redundant check on expected_hosts
                        # Redundancy caused the bug - was filtering BEFORE adding
                        if icmp_type == 0:
                            if source_ip in expected_hosts and source_ip not in self.discovered:
                                self.discovered.add(source_ip)
                                if context.verbose:
                                    print(f"  [+] 🟢 {source_ip} is up")
                            elif source_ip not in expected_hosts and context.debug:
                                print(f"[DEBUG] Reply from {source_ip} not in expected hosts")
                
            except BlockingIOError:
                # No data available, sleep briefly
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                break
            except Exception as e:
                if context.debug:
                    print(f"[DEBUG] Receive error: {e}")
                await asyncio.sleep(0.01)
    
    async def _wait_for_completion(self, hosts: List[str], max_timeout: float):
        """
        Đợi cho đến khi:
        1. Tìm được tất cả hosts, HOẶC
        2. Timeout
        
        Sử dụng exponential backoff để giảm CPU usage
        """
        start = time.time()
        check_interval = 0.02  # Bắt đầu check mỗi 20ms
        max_interval = 0.5     # Tối đa 500ms
        
        while (time.time() - start) < max_timeout:
            # Early exit nếu tìm được tất cả
            if len(self.discovered) >= len(hosts):
                return
            
            await asyncio.sleep(check_interval)
            
            # Exponential backoff: check ít dần (hầu hết replies đến sớm)
            check_interval = min(check_interval * 1.3, max_interval)
    
    def _calculate_smart_timeout(self, num_hosts: int, context) -> float:
        """
        Tính timeout thông minh dựa trên:
        - Số lượng hosts
        - Base timeout từ config
        - Network conditions (RTT)
        """
        base = getattr(context.performance, 'timeout', 3.0)
        
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
        
        # Cap trong khoảng hợp lý
        return max(2.0, min(30.0, timeout))


# ============== FALLBACK: Scapy-based Scanner ==============
# Dùng khi không có root privileges

class ScapyFallbackScanner(ScannerBase):
    """
    Fallback scanner sử dụng Scapy (không cần root trên 1 số OS)
    Chậm hơn raw socket nhưng dễ dùng hơn
    """
    
    @property
    def name(self) -> str:
        return "icmp"
    
    @property
    def type(self) -> str:
        return "host_discovery"
    
    @property
    def description(self) -> str:
        return "ICMP Echo Request (Ping) Discovery - Scapy Fallback"
    
    def requires_root(self) -> bool:
        return False
    
    def scan(self, context, result) -> None:
        """Scapy-based scan với optimization"""
        try:
            from scapy.all import IP, ICMP, sr, conf
            conf.verb = 0  # Tắt verbose
            
            hosts = context.targets.host
            if not hosts:
                return
            
            if context.verbose:
                print(f"[*] Scapy ICMP scan on {len(hosts)} hosts (slower mode)...")
            
            # Tạo tất cả packets trước
            packets = [IP(dst=h)/ICMP(id=0x5043) for h in hosts]
            
            # Gửi và nhận với timeout
            timeout = min(5, len(hosts) * 0.01)
            answered, _ = sr(packets, timeout=timeout, verbose=0)
            
            # Process results
            for sent, received in answered:
                host = sent[IP].dst
                result.add_host(host, state="up")
                if context.verbose:
                    print(f"  [+] {host} is up")
            
            # Mark unanswered as down
            answered_hosts = {sent[IP].dst for sent, _ in answered}
            for host in hosts:
                if host not in answered_hosts:
                    result.add_host(host, state="down")
                    
        except ImportError:
            print("[!] Scapy not installed. Install: pip install scapy")


# ============== Smart Wrapper ==============

def create_best_scanner():
    """
    Tự động chọn scanner tốt nhất:
    1. Raw socket nếu có root
    2. Scapy fallback nếu không
    """
    try:
        # Test raw socket permission
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        test_sock.close()
        if True:  # Suppress output during test
            return RawSocketICMPScanner()
    except (PermissionError, OSError):
        pass
    
    # Fallback to Scapy
    return ScapyFallbackScanner()