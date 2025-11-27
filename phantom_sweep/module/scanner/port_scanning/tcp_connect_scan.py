"""
TCP Connect Scan - Ultra-fast Masscan-style scanning
Optimized for maximum speed
"""
import asyncio
import time
from typing import Set, Dict
from scapy.all import IP, TCP, AsyncSniffer, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base import ScannerBase

conf.verb = 0


class TCPConnectScanner(ScannerBase):
    """TCP Connect Scan - Ultra-fast stateless scanning"""
    
    @property
    def name(self) -> str:
        return "connect"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP Connect Scan (ultra-fast)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform ultra-fast TCP connect scan"""
        hosts = context.targets.host
        if not hosts:
            return
        
        # Get up hosts
        up_hosts = [h for h in hosts if h in result.hosts and result.hosts[h].state == "up"]
        if not up_hosts:
            if context.verbose:
                print("[*] No up hosts to scan")
            return
        
        # Parse ports
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        if context.verbose:
            print(f"[*] Starting TCP SYN (Stealth) scan on {len(up_hosts)} hosts ({len(ports)} ports)...")
        
        try:
            asyncio.run(self._ultra_fast_scan(context, result, up_hosts, ports))
        except Exception as e:
            if context.debug:
                print(f"[!] TCP scan error: {e}")
    
    async def _ultra_fast_scan(self, context: ScanContext, result: ScanResult, hosts: list, ports: list):
        """Ultra-fast scanning: Batch send + adaptive timeout"""
        
        open_ports: Dict[str, Set[int]] = {h: set() for h in hosts}
        seq_map = {}  # seq -> (host, port)
        
        # BPF filter - only SYN-ACK for speed
        bpf_filter = "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
        
        # Packet handler
        def handle_packet(pkt):
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                ack = pkt[TCP].ack
                if ack in seq_map:
                    host, port = seq_map[ack]
                    if pkt[IP].src == host and pkt[TCP].flags & 0x12 == 0x12:  # SYN-ACK
                        open_ports[host].add(port)
        
        # Start sniffer
        sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
        sniffer.start()
        await asyncio.sleep(0.05)
        
        # === ULTRA-FAST BATCH SENDING ===
        start = time.time()
        seq = 0x10000
        packets = []
        
        # Build all packets first (faster than sending one by one)
        for host in hosts:
            for port in ports:
                pkt = IP(dst=host)/TCP(dport=port, flags="S", seq=seq)
                packets.append(pkt)
                seq_map[seq] = (host, port)
                seq += 1
        
        # Batch send with rate limiting
        BATCH_SIZE = 1000  # Send 1000 packets per batch
        for i in range(0, len(packets), BATCH_SIZE):
            batch = packets[i:i+BATCH_SIZE]
            send(batch, verbose=0, inter=0)  # inter=0 for max speed
            await asyncio.sleep(0.001)  # Tiny delay between batches
        
        send_time = time.time() - start
        
        if context.debug:
            pps = len(packets) / send_time if send_time > 0 else 0
            print(f"[DEBUG] Sent {len(packets)} packets in {send_time:.3f}s ({pps:.0f} pps)")
        
        # === ADAPTIVE TIMEOUT ===
        # Wait based on network size, not fixed timeout
        total_targets = len(hosts) * len(ports)
        
        if total_targets <= 100:
            wait_time = 0.5
        elif total_targets <= 1000:
            wait_time = 1.0
        elif total_targets <= 10000:
            wait_time = 2.0
        else:
            wait_time = 3.0
        
        if context.debug:
            print(f"[DEBUG] Waiting {wait_time}s for responses...")
        
        # Progressive timeout with early exit
        start_wait = time.time()
        last_count = 0
        check_interval = 0.1
        no_change_threshold = 0.3  # Exit if no new opens for 300ms
        no_change_time = 0
        
        while (time.time() - start_wait) < wait_time:
            await asyncio.sleep(check_interval)
            
            current_count = sum(len(ports) for ports in open_ports.values())
            if current_count == last_count:
                no_change_time += check_interval
                if no_change_time >= no_change_threshold:
                    if context.debug:
                        print(f"[DEBUG] Early exit after {time.time()-start_wait:.2f}s (no new responses)")
                    break
            else:
                no_change_time = 0
                last_count = current_count
        
        sniffer.stop()
        
        # Add results
        for host in hosts:
            for port in ports:
                state = "open" if port in open_ports[host] else "closed"
                result.add_port(host, port, protocol="tcp", state=state)
        
        if context.verbose:
            total_open = sum(len(p) for p in open_ports.values())
            print(f"[*] Scan completed in {time.time()-start:.2f}s - {total_open} open ports")