"""
ARP Scan Host Discovery - Reliable async for LAN discovery
Fire all ARP requests at max speed, collect responses asynchronously
"""
import asyncio
import time
from typing import Set
from scapy.all import Ether, ARP, AsyncSniffer, sendp, conf, get_if_hwaddr, get_working_if
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScannerBase

conf.verb = 0


class ARPScanner(ScannerBase):
    """ARP Discovery - Fast LAN host discovery using Scapy async"""
    
    @property
    def name(self) -> str:
        return "arp"
    
    @property
    def type(self) -> str:
        return "host_discovery"
    
    @property
    def description(self) -> str:
        return "ARP Discovery (LAN only)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform ARP discovery scan"""
        hosts = context.targets.host
        if not hosts:
            return
        
        if context.verbose:
            print(f"[*] Starting ARP discovery on {len(hosts)} hosts...")
        
        try:
            asyncio.run(self._async_scan(context, result, hosts))
        except Exception as e:
            if context.debug:
                print(f"[!] ARP scan error: {e}")
                import traceback
                traceback.print_exc()
    
    def _get_interface(self) -> str:
        """Detect working network interface"""
        interfaces_to_try = ["eth0", "en0", "wlan0", "ens0", "ens1", "wlan1"]
        
        try:
            # Try get_working_if first
            return get_working_if()
        except:
            pass
        
        # Try each interface
        for iface in interfaces_to_try:
            try:
                get_if_hwaddr(iface)
                return iface
            except:
                continue
        
        # Default fallback
        return "eth0"
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Fire all ARP requests and collect replies"""
        discovered: Set[str] = set()
        hosts_set = set(hosts)
        
        # Get working interface
        iface = self._get_interface()
        if context.debug:
            print(f"[DEBUG] Using interface: {iface}")
        
        try:
            local_mac = get_if_hwaddr(iface)
        except:
            local_mac = "00:00:00:00:00:00"
        
        # ARP reply filter
        bpf_filter = "arp[oper] == 2"
        
        # Packet handler
        def handle_packet(pkt):
            try:
                if pkt.haslayer(ARP):
                    psrc = pkt[ARP].psrc
                    if psrc not in discovered and psrc in hosts_set:
                        discovered.add(psrc)
                        result.add_host(psrc, state="up")
                        if context.verbose:
                            hwsrc = pkt[ARP].hwsrc
                            print(f"  [+] {psrc} is up ({hwsrc})")
            except:
                pass
        
        # Start sniffer on specific interface
        try:
            sniffer = AsyncSniffer(filter=bpf_filter, prn=handle_packet, store=False, iface=iface)
            sniffer.start()
            await asyncio.sleep(0.05)
        except Exception as e:
            if context.debug:
                print(f"[DEBUG] Failed to start sniffer: {e}")
            return
        
        # Fire ALL ARP requests with interface specified
        start_send = time.time()
        sent_count = 0
        for host in hosts:
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=host)
                sendp(pkt, iface=iface, verbose=0)
                sent_count += 1
            except Exception as e:
                if context.debug and sent_count == 0:
                    print(f"[DEBUG] First ARP send error: {e}")
        
        send_time = time.time() - start_send
        if context.debug:
            print(f"[DEBUG] Sent {sent_count}/{len(hosts)} ARP requests in {send_time:.3f}s")
        
        # Adaptive timeout - longer for ARP
        base_timeout = context.performance.timeout
        # ARP needs more time: base + 0.5s per 100 hosts, min 2s, max 20s
        adaptive_timeout = max(2.0, min(20.0, base_timeout + (len(hosts) / 100.0) * 0.5))
        
        if context.debug:
            print(f"[DEBUG] Waiting {adaptive_timeout:.1f}s for ARP responses")
        
        # Wait for responses
        start_wait = time.time()
        while (time.time() - start_wait) < adaptive_timeout:
            await asyncio.sleep(0.05)
            if len(discovered) == len(hosts):
                if context.debug:
                    print(f"[DEBUG] Found all {len(discovered)} hosts, exiting early")
                break
        
        # Stop sniffer safely
        try:
            # sniffer.stop()
            pass
        except Exception as e:
            if context.debug:
                print(f"[DEBUG] Error stopping sniffer: {e}")
        
        if context.debug:
            print(f"[DEBUG] Found {len(discovered)} hosts via ARP")
        
        # Mark undiscovered
        for host in hosts:
            if host not in discovered:
                result.add_host(host, state="down")