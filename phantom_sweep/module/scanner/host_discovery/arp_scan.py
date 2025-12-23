"""
ARP Scanner - Ultra-fast host discovery using ARP requests
Optimized with techniques from ICMP Ping and TCP SYN Scan for maximum performance
"""
import asyncio
import socket
import time
import struct
from typing import Set, List, Dict, Tuple, Optional
from dataclasses import dataclass
from phantom_sweep.module._base import ScannerBase


@dataclass
class ARPPacket:
    """ARP Request packet template for efficient reuse"""
    # Hardware type (Ethernet = 1)
    hw_type: int = 1
    # Protocol type (IPv4 = 0x0800)
    proto_type: int = 0x0800
    # Hardware address length
    hw_len: int = 6
    # Protocol address length
    proto_len: int = 4
    # Operation (1 = Request, 2 = Reply)
    operation: int = 1
    # Sender MAC
    sender_mac: bytes = b'\x00\x00\x00\x00\x00\x00'
    # Sender IP
    sender_ip: bytes = b'\x00\x00\x00\x00'
    # Target MAC (broadcast for request)
    target_mac: bytes = b'\xff\xff\xff\xff\xff\xff'
    # Target IP (will be filled dynamically)
    target_ip: bytes = b'\x00\x00\x00\x00'

    def to_bytes(self) -> bytes:
        """Convert ARP packet to bytes"""
        packet = struct.pack('!HHBBH',
                            self.hw_type,
                            self.proto_type,
                            self.hw_len,
                            self.proto_len,
                            self.operation)
        packet += self.sender_mac
        packet += self.sender_ip
        packet += self.target_mac
        packet += self.target_ip
        return packet

    @staticmethod
    def create_for_ip(target_ip: str, sender_mac: bytes, sender_ip: str) -> bytes:
        """Create ARP request packet for specific target IP"""
        packet = struct.pack('!HHBBH',
                            1,              # Ethernet
                            0x0800,         # IPv4
                            6,              # MAC length
                            4,              # IP length
                            1)              # Request
        packet += sender_mac
        packet += socket.inet_aton(sender_ip)
        packet += b'\xff\xff\xff\xff\xff\xff'  # Target MAC (broadcast)
        packet += socket.inet_aton(target_ip)
        return packet


class ARPScanner(ScannerBase):
    """Ultra-fast ARP-based host discovery scanner"""

    @property
    def name(self) -> str:
        return "arp"

    @property
    def type(self) -> str:
        return "host_discovery"

    @property
    def description(self) -> str:
        return "ARP Scan (Ultra-fast, local network only)"

    def requires_root(self) -> bool:
        return True

    def __init__(self):
        self.discovered: Set[str] = set()
        # Cache for optimizing performance
        self.local_ip: Optional[str] = None
        self.gateway: Optional[str] = None
        self.iface: Optional[str] = None

    def scan(self, context, result) -> None:
        """
        Entry point for ARP scan
        Performs ARP requests to discover active hosts on local network
        """
        hosts = context.targets.host
        if not hosts:
            return

        self.discovered.clear()

        try:
            asyncio.run(self._async_scan(context, result, hosts))
        except PermissionError:
            print("[!] ARP scan requires root/admin privileges!!!")
            print("[!] Run with: sudo python phantomsweep.py")
            return
        except Exception as e:
            if context.debug:
                print(f"[!] ARP Scan error: {e}")
                import traceback
                traceback.print_exc()

    # ========== Async Scan Logic ==========

    async def _async_scan(self, context, result, hosts: List[str]):
        """
        Main async ARP scan logic with 3-phase approach:
        1. Initialization (get interface info)
        2. Send all ARP requests at maximum rate (no waiting)
        3. Listen for ARP replies with smart timeout
        """
        # Phase 1: Initialization
        try:
            self.local_ip, self.gateway, self.iface = await self._get_interface_info()
            if context.debug:
                print(f"[DEBUG] ARP: Local IP={self.local_ip}, Gateway={self.gateway}, Interface={self.iface}")
        except Exception as e:
            if context.debug:
                print(f"[!] Failed to get interface info: {e}")
            return

        # Phase 2: Create raw socket for ARP
        try:
            # Create ARP socket (SOCK_PACKET for raw ARP frames)
            send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))  # 3 = ARPHRD_ETHER
            recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

            # Bind to interface
            send_sock.bind((self.iface, 0))
            recv_sock.bind((self.iface, 0))

            # Optimize receive buffer (Technique from ICMP: maximize packet buffer)
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20)  # 1MB
            recv_sock.setblocking(False)

            if context.debug:
                print(f"[DEBUG] ARP sockets created and bound to {self.iface}")

        except Exception as e:
            if context.debug:
                print(f"[!] Failed to create ARP sockets: {e}")
            return

        # Phase 3: Get local MAC address
        try:
            local_mac = self._get_mac_address(self.iface)
            if context.debug:
                print(f"[DEBUG] Local MAC: {local_mac.hex()}")
        except Exception as e:
            if context.debug:
                print(f"[!] Failed to get MAC address: {e}")
            return

        # Phase 4: Start receiver before sending (Technique from ICMP)
        recv_task = asyncio.create_task(
            self._listening(recv_sock, set(hosts), context, self.iface)
        )
        await asyncio.sleep(0.01)  # Wait for receiver to start

        # Phase 5: Send all ARP requests at maximum rate (Technique from TCP SYN)
        start_time = time.time()
        sent_count = await self._send_arp_requests(
            send_sock, hosts, self.local_ip, local_mac, context
        )
        send_duration = time.time() - start_time

        if context.debug:
            pps = sent_count / send_duration if send_duration > 0 else 0
            print(f"[DEBUG] Sent {sent_count} ARP requests in {send_duration:.3f}s ({pps:.0f} pps)")

        # Phase 6: Wait for replies with smart timeout (Technique from ICMP)
        timeout = self._calculate_smart_timeout(len(hosts), context)
        if context.debug:
            print(f"[DEBUG] ARP timeout: {timeout:.1f}s")

        try:
            await asyncio.wait_for(
                self._wait_for_completion(hosts, timeout),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            pass

        # Phase 7: Cleanup
        recv_task.cancel()
        try:
            await recv_task
        except asyncio.CancelledError:
            pass

        send_sock.close()
        recv_sock.close()

        # Phase 8: Update results
        for host in hosts:
            if host in self.discovered:
                result.add_host(host, state="up")
            else:
                result.add_host(host, state="down")

    # ========== Utilities ==========

    async def _send_arp_requests(self, sock: socket.socket, hosts: List[str],
                                  local_ip: str, local_mac: bytes, context) -> int:
        """
        Send all ARP requests at maximum rate using batching
        Technique from TCP SYN Scan: batch sending for ultra-fast rate
        """
        sent_count = 0
        pps = 1000  # Packets per second (tunable)
        batch_size = min(100, max(10, pps // 10))  # 10-100 packets per batch

        if context.debug:
            print(f"[DEBUG] ARP rate: {pps} pps, batch: {batch_size}")

        # Ethernet header for ARP
        ethernet_header = self._create_ethernet_header(b'\xff\xff\xff\xff\xff\xff', local_mac)

        # Pre-build ARP packet template
        arp_template = struct.pack('!HHBBH',
                                   1,          # Ethernet
                                   0x0800,     # IPv4
                                   6,          # MAC len
                                   4,          # IP len
                                   1)          # Request

        arp_base = (arp_template +
                   local_mac +
                   socket.inet_aton(local_ip) +
                   b'\xff\xff\xff\xff\xff\xff')  # Broadcast MAC

        # Send requests in batches
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i : i + batch_size]
            for host in batch:
                try:
                    # Build full packet: Ethernet + ARP
                    arp_packet = arp_base + socket.inet_aton(host)
                    full_packet = ethernet_header + arp_packet
                    sock.send(full_packet)
                    sent_count += 1
                except Exception as e:
                    if context.debug:
                        print(f"\t[!] Failed to send ARP to {host}: {e}")

            # Rate limiting: sleep to maintain desired PPS
            if i + batch_size < len(hosts):
                sleep_time = batch_size / pps
                await asyncio.sleep(sleep_time)

        return sent_count

    async def _listening(self, sock: socket.socket, expected_hosts: Set[str], 
                        context, iface: str):
        """
        Listen for ARP replies (Type 2)
        Non-blocking async receiver with efficient buffering (Technique from ICMP)
        """
        loop = asyncio.get_event_loop()

        while True:
            try:
                # Non-blocking receive
                data, addr = await loop.sock_recvfrom(sock, 1024)

                # ARP reply structure (after 14-byte Ethernet header):
                # 0-1: Hardware type
                # 2-3: Protocol type
                # 4: Hardware size
                # 5: Protocol size
                # 6-7: Operation (2 = Reply)
                # 8-13: Sender hardware address (MAC)
                # 14-17: Sender IP address
                # 18-23: Target hardware address
                # 24-27: Target IP address

                if len(data) >= 28:  # 14 (Eth) + 14 (ARP header)
                    # Skip Ethernet header (14 bytes)
                    arp_data = data[14:]

                    if len(arp_data) >= 28:
                        # Check operation code (bytes 6-7)
                        operation = struct.unpack('!H', arp_data[6:8])[0]

                        # ARP Reply = 2
                        if operation == 2:
                            # Extract sender IP (bytes 14-17 of ARP)
                            sender_ip = socket.inet_ntoa(arp_data[14:18])

                            if sender_ip in expected_hosts and sender_ip not in self.discovered:
                                self.discovered.add(sender_ip)
                                if context.verbose:
                                    # Extract sender MAC (bytes 8-13 of ARP)
                                    sender_mac = arp_data[8:14].hex(':')
                                    print(f"\t[+] Host {sender_ip} is up ({sender_mac})")
                        elif context.debug and operation not in [1]:  # Not a request
                            pass  # Ignore other operations

            except BlockingIOError:
                # No data available
                await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                break
            except Exception as e:
                if context.debug:
                    print(f"[!] Receive error: {e}")
                await asyncio.sleep(0.01)

    async def _wait_for_completion(self, hosts: List[str], max_timeout: float):
        """
        Wait for completion with exponential backoff
        Technique from ICMP: reduce CPU usage by increasing check interval over time
        """
        start_time = time.time()
        check_interval = 0.02  # Start checking every 20ms
        max_interval = 0.5     # Max check interval 500ms

        while (time.time() - start_time) < max_timeout:
            # Early exit if all hosts found
            if len(self.discovered) >= len(hosts):
                return

            await asyncio.sleep(check_interval)

            # Exponential backoff: check less frequently over time
            # Most replies come quickly, so gradually reduce frequency
            check_interval = min(check_interval * 1.3, max_interval)

    # ========== Helper Functions ==========

    @staticmethod
    def _create_ethernet_header(dest_mac: bytes, src_mac: bytes, ether_type: int = 0x0806) -> bytes:
        """Create Ethernet II header for ARP frames"""
        return dest_mac + src_mac + struct.pack('!H', ether_type)

    @staticmethod
    def _get_mac_address(iface: str) -> bytes:
        """
        Get MAC address of interface
        Uses socket approach instead of reading /sys files for portability
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Get hardware address
            import fcntl
            info = fcntl.ioctl(
                sock.fileno(),
                0x8927,  # SIOCGIFHWADDR
                struct.pack('256s', iface.encode('utf-8')[:15])
            )
            mac = info[18:24]
            return mac
        finally:
            sock.close()

    @staticmethod
    async def _get_interface_info() -> Tuple[str, str, str]:
        """
        Get local IP, gateway, and interface information
        Uses async subprocess for non-blocking network queries
        """
        import subprocess

        # Get default gateway and interface
        try:
            result = subprocess.run(
                ['ip', 'route', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    parts = line.split()
                    gateway = parts[2]
                    iface = parts[4]

                    # Get local IP on this interface
                    result2 = subprocess.run(
                        ['ip', 'addr', 'show', iface],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    for line2 in result2.stdout.split('\n'):
                        if 'inet ' in line2:
                            local_ip = line2.split()[1].split('/')[0]
                            return local_ip, gateway, iface

        except Exception:
            pass

        # Fallback: try to detect from /proc
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    parts = line.split()
                    if parts[1] == '00000000':  # Default route
                        iface = parts[0]
                        gateway_hex = parts[2]
                        gateway = '.'.join(str(int(gateway_hex[i:i+2], 16)) for i in (6, 4, 2, 0))

                        result = subprocess.run(
                            ['ip', 'addr', 'show', iface],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        for line2 in result.stdout.split('\n'):
                            if 'inet ' in line2:
                                local_ip = line2.split()[1].split('/')[0]
                                return local_ip, gateway, iface
        except Exception:
            pass

        raise RuntimeError("Could not determine network interface information")

    def _calculate_smart_timeout(self, num_hosts: int, context) -> float:
        """
        Calculate smart timeout based on number of hosts
        Technique from ICMP: tune timeout formula for different scan sizes
        """
        base = getattr(context.performance.timeout, 'timeout', 3.0)

        # Formula tuned for ARP (local network, very fast):
        # - ARP is local-only, so typically much faster than ICMP
        # - Most replies come within 100ms
        if num_hosts <= 100:
            timeout = base + 0.2
        elif num_hosts <= 1000:
            timeout = base + 0.5 + ((num_hosts - 100) / 1000.0) * 1.0
        else:
            timeout = base + 1.5

        return max(1.0, min(10.0, timeout))
