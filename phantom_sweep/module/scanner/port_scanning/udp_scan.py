"""
UDP Scanner - Ultra-fast async UDP port scanning
Optimized with async I/O, ICMP monitoring, and service-specific probes

Challenges:
- UDP is connectionless (no handshake)
- Open ports often don't respond
- ICMP Port Unreachable = closed (but rate-limited)
- Need service-specific payloads for accuracy

Solutions:
- Async batch sending with rate control
- ICMP sniffer for closed port detection
- Service-specific probes (DNS, SNMP, NTP, etc.)
- Smart timeout and retry logic
"""
import asyncio
import socket
import time
from typing import List, Optional, Dict, Set, Tuple
from scapy.all import AsyncSniffer, ICMP, IP, conf

from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScannerBase
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports

# Disable scapy verbose
conf.verb = 0


class UDPScanner(ScannerBase):
    
    # Service-specific payloads for common UDP services
    # These are carefully crafted probes that trigger responses from known services
    SERVICE_PROBES = {
        53: b'\x00\x1e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',  # DNS version.bind query
        67: b'\x01\x01\x06\x00' + b'\x00' * 300,  # DHCP DISCOVER
        69: b'\x00\x01test\x00netascii\x00',  # TFTP read request
        123: b'\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf1',  # NTP request (mode 3)
        137: b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01',  # NetBIOS name query
        161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x72\x64\x9f\x35\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP v2c GET sysDescr
        162: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x72\x64\x9f\x35\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP trap
        389: b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00',  # LDAP rootDSE query
        500: b'\x00' * 8 + b'\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x84' + b'\x00' * 116,  # IKE (VPN) Security Association
        514: b'<14>test\n',  # Syslog
        520: b'\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10',  # RIP v1 request
        1194: b'\x38' + b'\x00' * 13,  # OpenVPN
        1434: b'\x02',  # MS-SQL ping
        1604: b'\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Citrix
        1900: b'M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: "ssdp:discover"\r\nMX: 1\r\n\r\n',  # SSDP (UPnP)
        4500: b'\x00' * 8 + b'\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x84' + b'\x00' * 116,  # IKE NAT-T
        5060: b'OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=foo\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\nContact: <sip:nm@nm>\r\nAccept: application/sdp\r\n\r\n',  # SIP OPTIONS
        5353: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',  # mDNS _services
        5683: b'\x40\x01\x00\x00\xbb.well-known\x04core',  # CoAP discovery
    }
    
    @property
    def name(self) -> str:
        return "udp"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "UDP Scan (async, ICMP-aware, service probes)"
    
    def requires_root(self) -> bool:
        return False  # UDP socket doesn't need root, but ICMP sniffer does
    
    def __init__(self, max_pps: int = 500):
        """
        Args:
            max_pps: Max packets per second (conservative for UDP due to ICMP rate limiting)
        """
        self.max_pps = max_pps
        self.discovered_closed: Set[Tuple[str, int]] = set()
        self.discovered_open: Set[Tuple[str, int]] = set()
        self.sniffer: Optional[AsyncSniffer] = None
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Entry point for UDP scan"""
        targets = self._prepare_targets(context, result)
        
        if not targets:
            return
        
        if context.verbose:
            num_hosts = len(set(t[0] for t in targets))
            num_ports = len(set(t[1] for t in targets))
            print(f"[*] UDP Scan: {num_hosts} host(s) x {num_ports} port(s) = {len(targets)} probes")
            print(f"[*] Rate limit: {self.max_pps} pps (UDP is slower due to ICMP limiting)")
        
        try:
            asyncio.run(self._async_scan(context, result, targets))
        except PermissionError:
            print("[!] ICMP sniffing requires root for best accuracy")
            print("[!] Falling back to probe-only mode (less accurate)")
            asyncio.run(self._async_scan_no_icmp(context, result, targets))
        except Exception as e:
            if context.debug:
                import traceback
                print(f"[!] Scan error: {e}")
                traceback.print_exc()
    
    def _prepare_targets(self, context: ScanContext, result: ScanResult) -> List[Tuple[str, int]]:
        """Prepare list of (host, port) tuples to scan"""
        # Get UP hosts from discovery phase
        hosts = result.get_discovered_hosts() if result.hosts else context.targets.host
        
        if not hosts:
            if context.verbose:
                print("[*] No hosts available for UDP scanning")
            return []
        
        # Parse ports from context
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        
        # Apply exclude ports
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        # Create all (host, port) combinations
        targets = [(host, port) for host in hosts for port in ports]
        
        return targets
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, 
                         targets: List[Tuple[str, int]]) -> None:
        """Main async UDP scan with ICMP monitoring and UDP response detection"""
        
        if context.debug:
            print(f"[DEBUG] Starting UDP scan with ICMP monitoring and response listening...")
        
        # Step 1: Start ICMP sniffer to detect closed ports
        await self._start_icmp_sniffer(targets, context)
        
        # Step 2: Start UDP response listener
        listener_task = asyncio.create_task(
            self._listen_for_udp_responses(targets, context)
        )
        
        # Step 3: Send UDP probes (with retry for common ports)
        start_time = time.time()
        sent_count = await self._send_udp_probes_with_retry(targets, context)
        send_duration = time.time() - start_time
        
        if context.verbose:
            pps = sent_count / send_duration if send_duration > 0 else 0
            print(f"[*] Sent {sent_count} UDP probes in {send_duration:.2f}s ({pps:.0f} pps)")
        
        # Step 4: Wait for ICMP responses and UDP responses
        timeout = self._calculate_timeout(len(targets), context)
        
        if context.debug:
            print(f"[DEBUG] Waiting {timeout:.1f}s for responses...")
        
        await self._wait_for_responses(targets, timeout, context)
        
        # Step 5: Stop listener and sniffer
        listener_task.cancel()
        try:
            await listener_task
        except asyncio.CancelledError:
            pass
        
        if self.sniffer:
            self.sniffer.stop()
        
        # Step 6: Process results
        await self._process_results(targets, result, context)
        
        duration = time.time() - start_time
        
        # Print summary
        if context.verbose:
            open_count = len(self.discovered_open)
            closed_count = len(self.discovered_closed)
            open_filtered = len(targets) - open_count - closed_count
            rate = len(targets) / duration if duration > 0 else 0
            print(f"[*] UDP scan complete in {duration:.2f}s ({rate:.0f} ports/sec):")
            print(f"    • Open (confirmed): {open_count}")
            print(f"    • Closed: {closed_count}")
            print(f"    • Open|Filtered: {open_filtered}")
    
    async def _listen_for_udp_responses(self, targets: List[Tuple[str, int]],
                                       context: ScanContext) -> None:
        """
        Listen for UDP responses to confirm OPEN ports
        Uses async non-blocking I/O for efficiency
        """
        # Create listening socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        # Bind to ephemeral port
        sock.bind(('', 0))
        
        # Increase receive buffer
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20)  # 1MB
        
        loop = asyncio.get_event_loop()
        
        try:
            while True:
                try:
                    data, addr = await loop.sock_recvfrom(sock, 4096)
                    host = addr[0]
                    
                    # Find matching target (could be from any port we sent to)
                    for target_host, target_port in targets:
                        if target_host == host:
                            key = (host, target_port)
                            if key not in self.discovered_open:
                                self.discovered_open.add(key)
                                if context.verbose:
                                    print(f"  [+] {host}:{target_port}/udp responded (OPEN)")
                            break
                            
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                    
        except asyncio.CancelledError:
            pass
        finally:
            sock.close()

    async def _async_scan_no_icmp(self, context: ScanContext, result: ScanResult,
                                  targets: List[Tuple[str, int]]) -> None:
        """Fallback scan without ICMP monitoring (no root)"""
        
        if context.verbose:
            print("[*] Running probe-only mode (no ICMP monitoring)")
        
        start_time = time.time()
        
        # Start UDP response listener
        listener_task = asyncio.create_task(
            self._listen_for_udp_responses(targets, context)
        )
        
        # Just send probes and wait for responses
        sent_count = await self._send_udp_probes_with_retry(targets, context)
        timeout = self._calculate_timeout(len(targets), context)
        
        await asyncio.sleep(timeout)
        
        # Stop listener
        listener_task.cancel()
        try:
            await listener_task
        except asyncio.CancelledError:
            pass
        
        # All ports are open|filtered (no ICMP to confirm closed)
        for host, port in targets:
            if (host, port) in self.discovered_open:
                result.add_port(host, port, "open", protocol="udp")
            else:
                result.add_port(host, port, "open|filtered", protocol="udp")
        
        duration = time.time() - start_time
        if context.verbose:
            print(f"[*] UDP scan complete in {duration:.2f}s")
    
    async def _start_icmp_sniffer(self, targets: List[Tuple[str, int]], 
                                  context: ScanContext) -> None:
        """
        Start ICMP sniffer to detect ICMP Port Unreachable messages
        ICMP Type 3 Code 3 = Destination Port Unreachable = Port CLOSED
        """
        
        # BPF filter: Only ICMP Type 3 Code 3 (Port Unreachable)
        bpf_filter = "icmp and icmp[icmptype] == icmp-unreach and icmp[icmpcode] == 3"
        
        def handle_icmp_unreachable(pkt):
            """Handle ICMP Port Unreachable packets"""
            try:
                if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                    if pkt[ICMP].type == 3 and pkt[ICMP].code == 3:
                        # Extract original packet info from ICMP payload
                        if hasattr(pkt[ICMP], 'payload') and hasattr(pkt[ICMP].payload, 'original'):
                            orig_data = bytes(pkt[ICMP].payload.original)
                            if len(orig_data) >= 28:  # IP(20) + UDP(8) headers
                                # Parse original destination IP (bytes 16-20)
                                dst_ip = socket.inet_ntoa(orig_data[16:20])
                                # Parse original destination port (bytes 22-24)
                                dst_port = int.from_bytes(orig_data[22:24], 'big')
                                
                                # Mark as closed
                                key = (dst_ip, dst_port)
                                if key not in self.discovered_closed:
                                    self.discovered_closed.add(key)
                                    if context.debug:
                                        print(f"  [DEBUG] {dst_ip}:{dst_port} closed (ICMP unreachable)")
            except Exception as e:
                if context.debug:
                    print(f"[DEBUG] Error parsing ICMP: {e}")
        
        # Start async sniffer
        self.sniffer = AsyncSniffer(
            filter=bpf_filter,
            prn=handle_icmp_unreachable,
            store=False
        )
        self.sniffer.start()
        
        # Give sniffer time to initialize
        await asyncio.sleep(0.1)
        
        if context.debug:
            print(f"[DEBUG] ICMP sniffer started with filter: {bpf_filter}")
    
    async def _send_udp_probes(self, targets: List[Tuple[str, int]], 
                              context: ScanContext) -> int:
        """
        Send UDP probes with rate limiting and service-specific payloads
        
        KEY OPTIMIZATIONS:
        1. Async batch sending
        2. Service-specific payloads
        3. Conservative rate limiting (UDP is rate-limited by ICMP)
        4. Single socket reuse
        """
        sent_count = 0
        
        # Create UDP socket (reuse for all probes)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)  # Non-blocking
        
        # Calculate batch size based on PPS
        batch_size = min(50, max(10, self.max_pps // 10))
        
        if context.debug:
            print(f"[DEBUG] UDP batch size: {batch_size}, rate: {self.max_pps} pps")
        
        # Send in batches with rate control
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            
            # Send entire batch
            for host, port in batch:
                try:
                    # Get service-specific payload or use default
                    payload = self.SERVICE_PROBES.get(port, b'\x00')
                    
                    # Send UDP probe
                    sock.sendto(payload, (host, port))
                    sent_count += 1
                    
                except Exception as e:
                    if context.debug:
                        print(f"[DEBUG] Failed to send UDP to {host}:{port}: {e}")
            
            # Rate limiting between batches
            if i + batch_size < len(targets):
                sleep_time = batch_size / self.max_pps
                await asyncio.sleep(sleep_time)
        
        sock.close()
        return sent_count
    
    async def _send_udp_probes_with_retry(self, targets: List[Tuple[str, int]], 
                                          context: ScanContext) -> int:
        """
        Send UDP probes with retry for common service ports
        
        KEY OPTIMIZATIONS:
        1. Async batch sending
        2. Service-specific payloads
        3. Conservative rate limiting (UDP is rate-limited by ICMP)
        4. Single socket reuse
        5. Retry for ports with known services (increases accuracy)
        """
        sent_count = 0
        retries = 2  # Number of retries for service ports
        
        # Ports that benefit from retries (common services)
        retry_ports = {53, 67, 123, 137, 161, 500, 514, 1434, 1900, 5353}
        
        # Create UDP socket (reuse for all probes)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        # Calculate batch size based on PPS
        batch_size = min(50, max(10, self.max_pps // 10))
        
        if context.debug:
            print(f"[DEBUG] UDP batch size: {batch_size}, rate: {self.max_pps} pps, retries: {retries}")
        
        # Send initial probes in batches with rate control
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            
            for host, port in batch:
                try:
                    payload = self.SERVICE_PROBES.get(port, b'\x00')
                    sock.sendto(payload, (host, port))
                    sent_count += 1
                except Exception as e:
                    if context.debug:
                        print(f"[DEBUG] Failed to send UDP to {host}:{port}: {e}")
            
            if i + batch_size < len(targets):
                sleep_time = batch_size / self.max_pps
                await asyncio.sleep(sleep_time)
        
        # Retry for service ports (improves accuracy)
        for retry in range(retries):
            await asyncio.sleep(0.5)  # Wait between retries
            
            retry_targets = [(h, p) for h, p in targets 
                            if p in retry_ports 
                            and (h, p) not in self.discovered_closed
                            and (h, p) not in self.discovered_open]
            
            if not retry_targets:
                break
                
            if context.debug:
                print(f"[DEBUG] Retry {retry + 1}: {len(retry_targets)} service ports")
            
            for host, port in retry_targets:
                try:
                    payload = self.SERVICE_PROBES.get(port, b'\x00')
                    sock.sendto(payload, (host, port))
                    sent_count += 1
                except Exception:
                    pass
            
            await asyncio.sleep(0.2)
        
        sock.close()
        return sent_count
    
    async def _wait_for_responses(self, targets: List[Tuple[str, int]], 
                                  timeout: float, context: ScanContext) -> None:
        """
        Wait for responses with exponential backoff
        
        OPTIMIZATION: Check frequently early (responses arrive fast),
        then check less frequently (ICMP rate-limited)
        """
        start = time.time()
        check_interval = 0.1  # Start with 100ms (UDP slower than TCP)
        max_interval = 1.0    # Max 1 second
        
        while (time.time() - start) < timeout:
            # Early exit if we have responses for all targets
            total_responses = len(self.discovered_closed) + len(self.discovered_open)
            if total_responses >= len(targets):
                return
            
            await asyncio.sleep(check_interval)
            
            # Exponential backoff
            check_interval = min(check_interval * 1.5, max_interval)
    
    async def _process_results(self, targets: List[Tuple[str, int]], 
                               result: ScanResult, context: ScanContext) -> None:
        """
        Process scan results and update result object
        
        UDP Result Logic:
        - ICMP Port Unreachable received → CLOSED (confirmed)
        - No ICMP → OPEN|FILTERED (ambiguous)
        - Service response received → OPEN (confirmed, but requires deeper inspection)
        """
        
        for host, port in targets:
            key = (host, port)
            
            if key in self.discovered_closed:
                # ICMP Port Unreachable = definitely CLOSED
                result.add_port(host, port, "closed", protocol="udp")
                
            elif key in self.discovered_open:
                # Service responded = definitely OPEN
                result.add_port(host, port, "open", protocol="udp")
                if context.verbose:
                    print(f"  [+] {host}:{port}/udp is open")
                
            else:
                # No response = OPEN or FILTERED (can't distinguish)
                result.add_port(host, port, "open|filtered", protocol="udp")
                if context.verbose:
                    print(f"  [?] {host}:{port}/udp is open|filtered")
    
    def _calculate_timeout(self, num_targets: int, context: ScanContext) -> float:
        """
        Calculate optimal timeout for UDP scan
        
        UDP needs LONGER timeout than TCP because:
        1. ICMP responses are rate-limited (~100-500/sec)
        2. Services take time to process UDP probes
        3. Network may drop ICMP messages
        
        FORMULA: Base timeout × scale factor × network multiplier
        """
        base = getattr(context.performance, 'timeout', 5.0)
        
        # Scale based on number of targets
        if num_targets <= 100:
            scale = 1.0  # Small scan
        elif num_targets <= 1000:
            scale = 1.5  # Medium scan
        else:
            scale = 2.0  # Large scan
        
        # UDP needs longer timeout than TCP
        timeout = base * scale
        
        # Clamp to reasonable range
        return max(3.0, min(30.0, timeout))


# ============================================================
# PERFORMANCE NOTES
# ============================================================

"""
UDP SCAN PERFORMANCE CHARACTERISTICS:

SPEED COMPARISON (1000 ports on 1 host):
┌─────────────────┬──────────┬─────────┬──────────────┐
│ Method          │ Duration │ Rate    │ Accuracy     │
├─────────────────┼──────────┼─────────┼──────────────┤
│ Basic UDP       │ 10-20s   │ 50/s    │ Low          │
│ With ICMP       │ 10-30s   │ 50/s    │ Medium       │
│ Advanced        │ 15-40s   │ 30/s    │ High         │
└─────────────────┴──────────┴─────────┴──────────────┘

WHY UDP IS SLOWER:
1. No handshake → Can't confirm open ports easily
2. ICMP rate limiting → ~100-500 ICMP/sec max
3. Services slow to respond → Need longer timeouts
4. Many false positives → Requires verification

OPTIMIZATIONS APPLIED:
✅ Async batch sending (like TCP Connect)
✅ Single socket reuse (minimize overhead)
✅ Service-specific probes (better accuracy)
✅ ICMP monitoring (detect closed ports)
✅ Conservative rate limiting (avoid ICMP throttling)
✅ Exponential backoff (efficient waiting)
✅ Response detection (confirm open ports)

BOTTLENECKS:
🔴 ICMP rate limiting (kernel/router level)
🔴 UDP service response time (application level)
🔴 Network latency (physical)

BEST PRACTICES:
1. Use UDP scan only for specific services (DNS, SNMP, etc.)
2. Combine with version detection for confirmation
3. Use lower PPS (300-500) for best accuracy
4. Scan known UDP ports first (53, 161, 123, etc.)
5. Consider multiple scan passes for important targets
"""