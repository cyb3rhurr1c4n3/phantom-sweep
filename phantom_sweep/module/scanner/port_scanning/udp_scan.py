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
        port_to_host: Dict[Tuple[str, int], bool] = {}
        
        # Use provided ports or common UDP ports
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        # BPF filter for ICMP unreachable
        bpf_filter = "icmp[icmptype] == 3"  # ICMP Destination Unreachable
        
        # Packet handler
        def handle_packet(pkt):
            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                if pkt[ICMP].type == 3:  # Destination Unreachable
                    # Extract original packet from ICMP payload
                    if pkt.haslayer(IP):
                        orig_dst = pkt[IP].dst
                        if orig_dst in hosts and pkt[ICMP].code == 3:  # Port unreachable
                            # Try to extract port from nested packet
                            try:
                                if pkt.haslayer(UDP):
                                    port = pkt[UDP].dport
                                    if orig_dst in closed_ports:
                                        closed_ports[orig_dst].add(port)
                            except:
                                pass
        
        # Start sniffer
        sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
        sniffer.start()
        await asyncio.sleep(0.1)
        
        # Fire ALL UDP packets (Masscan-style)
        start = time.time()
        packet_count = 0
        for host in hosts:
            for port in ports:
                # Send UDP packet with minimal payload
                pkt = IP(dst=host) / UDP(dport=port) / b"X"
                send(pkt, verbose=0)
                port_to_host[(host, port)] = False  # False = open/filtered
                packet_count += 1
        send_time = time.time() - start
        
        if context.debug:
            print(f"[DEBUG] Sent {packet_count} UDP packets in {send_time:.3f}s ({packet_count/send_time:.0f} pps)")
        
        # Wait for ICMP responses
        await asyncio.sleep(context.performance.timeout * 2)
        sniffer.stop()
        
        # Add results
        for host in hosts:
            for port in ports:
                if port in closed_ports[host]:
                    state = "closed"
                else:
                    state = "open|filtered"  # Can't distinguish without response
                result.add_port(host, port, protocol="udp", state=state)
