"""
ARP Host Discovery Scanner (for local networks)
"""
import asyncio
import socket
import time
from typing import Dict, Set
from scapy.all import ARP, srp, send, conf, get_if_addr
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class ARPScanner(ScannerBase):
    """
    ARP Host Discovery Scanner.
    Only works on local networks (same subnet).
    Uses async architecture with sender and receiver threads.
    """
    
    def name(self) -> str:
        return "arp_scan"
    
    def requires_root(self) -> bool:
        return True  # ARP requires root
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform ARP host discovery using async sender/receiver architecture.
        """
        hosts_to_scan = context.targets.host
        if not hosts_to_scan:
            return
        
        if context.verbose:
            print(f"[*] Starting ARP discovery for {len(hosts_to_scan)} hosts...")
        
        # Run async scan
        asyncio.run(self._async_scan(context, result, hosts_to_scan))
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """
        Async scan with sender and receiver tasks.
        """
        # Shared data structure for results
        discovered_hosts: Set[str] = set()
        sent_packets: Dict[str, float] = {}  # host -> timestamp
        
        # Create tasks
        sender_task = asyncio.create_task(
            self._sender(context, hosts, sent_packets)
        )
        receiver_task = asyncio.create_task(
            self._receiver(context, hosts, sent_packets, discovered_hosts, result)
        )
        
        # Wait for sender to finish
        await sender_task
        
        # Wait for responses
        await asyncio.sleep(context.performance.timeout * 2)
        receiver_task.cancel()
        
        try:
            await receiver_task
        except asyncio.CancelledError:
            pass
        
        # Mark undiscovered hosts as down
        for host in hosts:
            if host not in discovered_hosts:
                result.add_host(host, state="down")
    
    async def _sender(self, context: ScanContext, hosts: list, 
                     sent_packets: Dict[str, float]):
        """
        Sender thread: Send ARP requests quickly.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)
        
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                
                # Create ARP request
                arp_request = ARP(pdst=ip)
                send(arp_request, verbose=0)
                sent_packets[ip] = time.time()
                
                # Rate limiting
                if rate_limit > 0:
                    await asyncio.sleep(1.0 / rate_limit)
                    
            except (socket.gaierror, Exception) as e:
                if context.debug:
                    print(f"  [DEBUG-ARP] Error sending to {host}: {e}")
                continue
    
    async def _receiver(self, context: ScanContext, hosts: list,
                       sent_packets: Dict[str, float],
                       discovered_hosts: Set[str],
                       result: ScanResult):
        """
        Receiver thread: Listen for ARP responses.
        """
        timeout = context.performance.timeout * 2
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(0.1)
                
                if sent_packets:
                    # Use srp() for ARP (layer 2)
                    target_ip = max(sent_packets.keys(), key=lambda k: sent_packets[k])
                    if target_ip in sent_packets:
                        arp_request = ARP(pdst=target_ip)
                        ans, unans = srp(arp_request, timeout=0.5, verbose=0, retry=0)
                        
                        for sent, received in ans:
                            if received.haslayer(ARP):
                                arp = received.getlayer(ARP)
                                src_ip = arp.psrc
                                
                                if src_ip not in discovered_hosts:
                                    discovered_hosts.add(src_ip)
                                    result.add_host(src_ip, state="up")
                                    if context.verbose:
                                        print(f"  [+] Host {src_ip} is up (ARP response)")
                                    
                                    if src_ip in sent_packets:
                                        del sent_packets[src_ip]
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-ARP] Error in receiver: {e}")
                continue
        
        # Final check: Use srp() to get all ARP responses
        try:
            arp_requests = []
            for host in hosts:
                if host not in discovered_hosts:
                    try:
                        ip = socket.gethostbyname(host)
                        arp_requests.append(ARP(pdst=ip))
                    except:
                        continue
            
            if arp_requests:
                ans, unans = srp(arp_requests, timeout=context.performance.timeout,
                                verbose=0, retry=1)
                for sent, received in ans:
                    if received.haslayer(ARP):
                        arp = received.getlayer(ARP)
                        src_ip = arp.psrc
                        if src_ip not in discovered_hosts:
                            discovered_hosts.add(src_ip)
                            result.add_host(src_ip, state="up")
        except Exception:
            pass
    
    def _get_rate_limit(self, rate: str) -> float:
        """Convert rate string to packets per second."""
        rate_map = {
            "stealthy": 10,
            "balanced": 100,
            "fast": 1000,
            "insane": 10000
        }
        return rate_map.get(rate, 100)

