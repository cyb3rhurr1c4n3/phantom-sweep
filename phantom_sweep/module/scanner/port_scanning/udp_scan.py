"""
UDP Port Scan - Stateless UDP port detection using ICMP responses
Fire all UDP packets, collect ICMP unreachable responses
"""
import asyncio
import time
from typing import Set, Tuple, Dict
from scapy.all import IP, UDP, ICMP, AsyncSniffer, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base import ScannerBase

conf.verb = 0

# Common UDP ports
COMMON_UDP_PORTS = [
    53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 389, 445, 514, 515,
    631, 1434, 3306, 3389, 5353, 5355, 5432, 5672, 9200, 11211, 27017
]


class UDPScanner(ScannerBase):
    """UDP Port Scan - Masscan-style UDP scanning with ICMP detection"""
    
    @property
    def name(self) -> str:
        return "udp"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "UDP Port Scan (ICMP-based)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform UDP port scan on discovered hosts"""
        hosts = context.targets.host
        if not hosts:
            return
        
        # Get up hosts
        up_hosts = [h for h in hosts if h in result.hosts and result.hosts[h].state == "up"]
        if not up_hosts:
            if context.verbose:
                print("[*] No up hosts to scan")
            return
        
        if context.verbose:
            print(f"[*] Starting UDP scan on {len(up_hosts)} hosts...")
        
        try:
            asyncio.run(self._async_scan(context, result, up_hosts))
        except Exception as e:
            if context.debug:
                print(f"[!] UDP scan error: {e}")
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Masscan-style: Send all UDP → Collect ICMP unreachable responses"""
        closed_ports: Dict[str, Set[int]] = {h: set() for h in hosts}
        
        # Use provided ports or common UDP ports
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        # BPF filter for ICMP unreachable
        bpf_filter = "icmp[icmptype] == 3"  # ICMP Destination Unreachable
        
        # Packet handler
        def handle_packet(pkt):
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 3:
                # ✅ Access the ICMP payload (original packet that triggered error)
                if pkt.haslayer(IP) and IP in pkt[ICMP].payload:
                    orig_pkt = pkt[ICMP].payload  # Original IP packet
                    
                    # ✅ Check if it's from our scan
                    if orig_pkt.haslayer(IP) and orig_pkt.haslayer(UDP):
                        target_ip = orig_pkt[IP].dst  # ✅ Target we sent to
                        target_port = orig_pkt[UDP].dport  # ✅ Port we scanned
                        
                        # ICMP code 3 = Port Unreachable
                        if pkt[ICMP].code == 3 and target_ip in closed_ports:
                            closed_ports[target_ip].add(target_port)
        
        # Start sniffer
        sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
        sniffer.start()
        await asyncio.sleep(0.1)
        
        # Fire ALL UDP packets (Masscan-style) with rate limiting
        start = time.time()
        packet_count = 0
        packets = []
        
        # ✅ Build all packets first
        for host in hosts:
            for port in ports:
                pkt = IP(dst=host) / UDP(dport=port) / b"X"
                packets.append(pkt)
        
        # ✅ Send in batches with rate limiting
        BATCH_SIZE = 100
        for i in range(0, len(packets), BATCH_SIZE):
            batch = packets[i:i + BATCH_SIZE]
            send(batch, verbose=0, inter=0)
            packet_count += len(batch)
            await asyncio.sleep(0.01)  # ✅ Small delay between batches
        
        send_time = time.time() - start
        
        if context.debug:
            print(f"[DEBUG] Sent {packet_count} UDP packets in {send_time:.3f}s ({packet_count/send_time:.0f} pps)")
        
        # ✅ Wait longer for UDP responses (UDP is slow!)
        wait_time = max(5.0, context.performance.timeout * 3)
        await asyncio.sleep(wait_time)
        sniffer.stop()
        
        # Add results
        for host in hosts:
            for port in ports:
                if port in closed_ports[host]:
                    state = "closed"
                else:
                    state = "open|filtered"  # Can't distinguish without response
                result.add_port(host, port, protocol="udp", state=state)
        
        if context.verbose:
            total_closed = sum(len(p) for p in closed_ports.values())
            total_scanned = len(hosts) * len(ports)
            total_open_filtered = total_scanned - total_closed
            print(f"[*] UDP scan completed: {total_open_filtered} open|filtered, {total_closed} closed")