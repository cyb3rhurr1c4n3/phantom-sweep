"""
TCP Connect Scan - Stateless fast port scanning using Scapy
Fire all SYN packets, match responses with sequence numbers
"""
import asyncio
import time
from typing import Set, Tuple, Dict
from scapy.all import IP, TCP, AsyncSniffer, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base import ScannerBase

conf.verb = 0


class TCPConnectScanner(ScannerBase):
    """TCP Connect Scan - Masscan-style stateless scanning for all ports"""
    
    @property
    def name(self) -> str:
        return "connect"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP Connect Scan (stateless)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform TCP connect scan on discovered hosts"""
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
            print(f"[*] Starting TCP Connect scan on {len(up_hosts)} hosts...")
        
        try:
            asyncio.run(self._async_scan(context, result, up_hosts))
        except Exception as e:
            if context.debug:
                print(f"[!] TCP Connect scan error: {e}")
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Masscan-style: Fire all SYN packets → Collect responses → Match by seq number"""
        open_ports: Dict[str, Set[int]] = {h: set() for h in hosts}
        seq_to_port: Dict[int, Tuple[str, int]] = {}  # seq -> (host, port)
        
        # Parse ports from context
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        # Build BPF filter
        bpf_filter = "tcp[tcpflags] & tcp-ack != 0"  # Any TCP ACK/RST
        
        # Packet handler
        def handle_packet(pkt):
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                src = pkt[IP].src
                ack = pkt[TCP].ack
                
                if ack in seq_to_port:
                    host, port = seq_to_port[ack]
                    if src == host:
                        # Check if SYN-ACK (open) or RST (closed)
                        if pkt[TCP].flags.S and pkt[TCP].flags.A:
                            open_ports[host].add(port)
                            if context.verbose and len(open_ports[host]) % 10 == 0:
                                print(f"  [{host}] Found {len(open_ports[host])} open ports...")
        
        # Start sniffer
        sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
        sniffer.start()
        await asyncio.sleep(0.1)
        
        # Fire ALL SYN packets (Masscan-style)
        start = time.time()
        seq_counter = 0x1000
        for host in hosts:
            for port in ports:
                pkt = IP(dst=host) / TCP(dport=port, flags="S", seq=seq_counter)
                seq_to_port[seq_counter] = (host, port)
                send(pkt, verbose=0)
                seq_counter += 1
        send_time = time.time() - start
        
        total_packets = len(hosts) * len(ports)
        if context.debug:
            print(f"[DEBUG] Sent {total_packets} TCP SYN packets in {send_time:.3f}s ({total_packets/send_time:.0f} pps)")
        
        # Wait for responses
        await asyncio.sleep(context.performance.timeout * 2)
        sniffer.stop()
        
        # Add results
        for host in hosts:
            for port in ports:
                state = "open" if port in open_ports[host] else "closed"
                result.add_port(host, port, protocol="tcp", state=state)
