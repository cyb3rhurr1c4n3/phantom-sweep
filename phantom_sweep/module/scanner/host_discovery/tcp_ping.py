"""
TCP Ping Host Discovery Scanner - Masscan-style async for hosts without ICMP
Fire SYN to common ports, collect SYN-ACK responses asynchronously
"""
import asyncio
import time
from typing import Dict, Set
from scapy.all import IP, TCP, AsyncSniffer, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScannerBase

conf.verb = 0

# Common ports for TCP ping discovery
DISCOVERY_PORTS = [80, 443, 22, 135, 139, 445, 3306, 3389, 5432, 8080, 8443, 27017]


class TCPPingScanner(ScannerBase):
    """TCP SYN Ping Discovery - Reliable async for ICMP-filtered hosts"""
    
    @property
    def name(self) -> str:
        return "tcp"
    
    @property
    def type(self) -> str:
        return "host_discovery"
    
    @property
    def description(self) -> str:
        return "TCP SYN Ping to common ports (80, 443, 22, etc.)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform TCP ping host discovery"""
        hosts = context.targets.host
        if not hosts:
            return
        
        if context.verbose:
            print(f"[*] Starting TCP ping discovery on {len(hosts)} hosts...")
        
        try:
            asyncio.run(self._async_scan(context, result, hosts))
        except Exception as e:
            if context.debug:
                print(f"[!] TCP ping scan error: {e}")
                import traceback
                traceback.print_exc()
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Fire all SYN packets and collect SYN-ACK responses"""
        discovered: Set[str] = set()
        hosts_set = set(hosts)
        ports = DISCOVERY_PORTS
        
        # Simple BPF filter
        bpf_filter = "tcp[tcpflags] & tcp-ack != 0"
        
        # Packet handler
        def handle_packet(pkt):
            try:
                if pkt.haslayer(TCP) and pkt.haslayer(IP):
                    src = pkt[IP].src
                    if src not in discovered and src in hosts_set:
                        discovered.add(src)
                        result.add_host(src, state="up")
                        if context.verbose:
                            print(f"  [+] {src} is up (port {pkt[TCP].sport})")
            except:
                pass
        
        # Start sniffer
        sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
        sniffer.start()
        await asyncio.sleep(0.05)
        
        # Fire ALL SYN packets
        start_send = time.time()
        sent_count = 0
        for host in hosts:
            for port in ports:
                pkt = IP(dst=host) / TCP(dport=port, flags="S", seq=0x1234)
                try:
                    send(pkt, verbose=0)
                    sent_count += 1
                except:
                    pass
        
        send_time = time.time() - start_send
        total_packets = len(hosts) * len(ports)
        if context.debug:
            print(f"[DEBUG] Sent {sent_count}/{total_packets} TCP SYN packets in {send_time:.3f}s")
        
        # Adaptive timeout
        base_timeout = context.performance.timeout
        adaptive_timeout = max(2.0, min(30.0, base_timeout + (len(hosts) / 100.0) * 0.5))
        
        if context.debug:
            print(f"[DEBUG] Waiting {adaptive_timeout:.1f}s for TCP responses")
        
        # Wait for responses
        start_wait = time.time()
        while (time.time() - start_wait) < adaptive_timeout:
            await asyncio.sleep(0.05)
            if len(discovered) == len(hosts):
                if context.debug:
                    print(f"[DEBUG] Found all {len(discovered)} hosts, exiting early")
                break
        
        sniffer.stop()
        
        if context.debug:
            print(f"[DEBUG] Found {len(discovered)} hosts via TCP")
        
        # Mark undiscovered
        for host in hosts:
            if host not in discovered:
                result.add_host(host, state="down")