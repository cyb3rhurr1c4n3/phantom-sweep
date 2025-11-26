"""
TCP SYN Scan (Stealth) - Ultra-fast stateless port scanning
Fire all SYN packets at max rate, match responses by sequence number
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


class TCPSynScanner(ScannerBase):
    """TCP SYN Scan (Stealth) - Masscan-style ultra-fast scanning"""
    
    @property
    def name(self) -> str:
        return "stealth"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP SYN Scan (stealth scan, ultra-fast)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform TCP SYN scan on discovered hosts"""
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
            print(f"[*] Starting TCP SYN (Stealth) scan on {len(up_hosts)} hosts ({len(context.targets.port)} ports)...")
        
        try:
            asyncio.run(self._async_scan(context, result, up_hosts))
        except Exception as e:
            if context.debug:
                print(f"[!] TCP SYN scan error: {e}")
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Masscan-style: Send all SYN → Collect SYN-ACK/RST → Stateless response matching"""
        open_ports: Dict[str, Set[int]] = {h: set() for h in hosts}
        filtered_ports: Dict[str, Set[int]] = {h: set() for h in hosts}
        seq_to_port: Dict[int, Tuple[str, int]] = {}  # seq -> (host, port)
        
        # Parse ports from context
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        # BPF filter for responses
        bpf_filter = "tcp[tcpflags] & (tcp-syn|tcp-rst) != 0"
        
        # Packet handler
        def handle_packet(pkt):
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                src = pkt[IP].src
                ack = pkt[TCP].ack
                flags = pkt[TCP].flags
                
                if ack in seq_to_port:
                    host, port = seq_to_port[ack]
                    if src == host:
                        if flags.S:  # SYN flag set = open
                            open_ports[host].add(port)
                        elif flags.R:  # RST = closed
                            pass
        
        # Start sniffer
        sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
        sniffer.start()
        await asyncio.sleep(0.05)
        
        # Fire ALL SYN packets (TRUE Masscan-style fire-and-forget)
        start = time.time()
        seq_counter = 0x2000
        for host in hosts:
            for port in ports:
                pkt = IP(dst=host, ttl=64) / TCP(dport=port, flags="S", seq=seq_counter, window=64240)
                seq_to_port[seq_counter] = (host, port)
                send(pkt, verbose=0)
                seq_counter += 1
        send_time = time.time() - start
        
        total_packets = len(hosts) * len(ports)
        if context.debug:
            print(f"[DEBUG] Sent {total_packets} TCP SYN packets in {send_time:.3f}s ({total_packets/send_time:.0f} pps)")
        
        # Wait for responses (shorter timeout for SYN scan)
        await asyncio.sleep(max(context.performance.timeout, 1.0))
        sniffer.stop()
        
        # Add results
        for host in hosts:
            for port in ports:
                if port in open_ports[host]:
                    state = "open"
                elif port in filtered_ports[host]:
                    state = "filtered"
                else:
                    state = "closed"
                result.add_port(host, port, protocol="tcp", state=state)
