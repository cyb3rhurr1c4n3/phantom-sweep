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


class ICMPPingScanner(ScannerBase):
    """ICMP Echo Request (Ping) Discovery - Reliable async scanning"""
    
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
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform ICMP ping host discovery"""
        hosts = context.targets.host
        if not hosts:
            return
        
        if context.verbose:
            print(f"[*] Starting ICMP ping discovery on {len(hosts)} hosts...")
        
        try:
            asyncio.run(self._async_scan(context, result, hosts))
        except Exception as e:
            if context.debug:
                print(f"[!] ICMP scan error: {e}")
                import traceback
                traceback.print_exc()
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Fire all ICMP packets and collect responses with adaptive waiting"""
        discovered: Set[str] = set()
        hosts_set = set(hosts)
        
        # Use simple filter (faster) - check src in Python
        bpf_filter = "icmp[icmptype] == icmp-echoreply"
        
        # Packet handler
        def handle_packet(pkt):
            try:
                if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                    src = pkt[IP].src
                    if src not in discovered and src in hosts_set:
                        discovered.add(src)
                        result.add_host(src, state="up")
                        if context.verbose:
                            print(f"  [+] {src} is up")
            except:
                pass
        
        # Start sniffer FIRST (before sending)
        sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False)
        sniffer.start()
        
        # Give sniffer time to initialize
        await asyncio.sleep(0.05)
        
        # Fire ALL packets (batch send for speed)
        start_send = time.time()
        sent_count = 0
        for host in hosts:
            pkt = IP(dst=host) / ICMP(id=0x1234, seq=1)
            try:
                send(pkt, verbose=0)
                sent_count += 1
            except Exception as e:
                if context.debug:
                    print(f"[DEBUG] Failed to send to {host}: {e}")
        
        send_time = time.time() - start_send
        if context.debug:
            print(f"[DEBUG] Sent {sent_count}/{len(hosts)} ICMP packets in {send_time:.3f}s")
        
        # Adaptive timeout: longer for larger scans
        # Base: min 2s, +0.5s per 100 hosts, max 30s
        base_timeout = context.performance.timeout
        adaptive_timeout = max(2.0, min(30.0, base_timeout + (len(hosts) / 100.0) * 0.5))
        
        if context.debug:
            print(f"[DEBUG] Waiting {adaptive_timeout:.1f}s for responses (base={base_timeout}s)")
        
        # Wait for responses with proper async sleep
        start_wait = time.time()
        while (time.time() - start_wait) < adaptive_timeout:
            await asyncio.sleep(0.05)
            # Early exit if we found all hosts
            if len(discovered) == len(hosts):
                if context.debug:
                    print(f"[DEBUG] Found all {len(discovered)} hosts, exiting early")
                break
        
        total_wait = time.time() - start_wait
        sniffer.stop()
        
        if context.debug:
            print(f"[DEBUG] Response collection took {total_wait:.3f}s, found {len(discovered)} hosts")
        
        # Mark undiscovered hosts as down
        for host in hosts:
            if host not in discovered:
                result.add_host(host, state="down")
