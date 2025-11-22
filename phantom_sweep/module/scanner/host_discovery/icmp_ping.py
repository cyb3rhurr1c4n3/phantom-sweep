"""
ICMP Echo (Ping) Host Discovery Scanner
"""
import asyncio
import socket
import time
from typing import Dict, Set, Tuple
from scapy.all import IP, ICMP, sr, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class ICMPPingScanner(ScannerBase):
    """
    ICMP Echo Request (Ping) Host Discovery Scanner.
    Uses async architecture with sender and receiver threads.
    """
    
    def name(self) -> str:
        return "icmp_ping"
    
    def requires_root(self) -> bool:
        return False  # ICMP ping usually doesn't require root on most systems
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform ICMP ping host discovery using async sender/receiver architecture.
        """
        hosts_to_scan = context.targets.host
        if not hosts_to_scan:
            return
        
        if context.verbose:
            print(f"[*] Starting ICMP ping discovery for {len(hosts_to_scan)} hosts...")
        
        # Run async scan
        asyncio.run(self._async_scan(context, result, hosts_to_scan))
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """
        Async scan with sender and receiver tasks.
        """
        # Map hostnames to IPs for proper tracking
        host_to_ip: Dict[str, str] = {}
        ip_to_host: Dict[str, str] = {}
        
        # Resolve all hostnames first
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                host_to_ip[host] = ip
                ip_to_host[ip] = host
            except socket.gaierror:
                # Cannot resolve, mark as down
                result.add_host(host, state="down")
        
        # Shared data structure for results
        discovered_ips: Set[str] = set()
        sent_packets: Dict[str, float] = {}  # ip -> timestamp
        
        # Create tasks
        sender_task = asyncio.create_task(
            self._sender(context, list(host_to_ip.values()), sent_packets)
        )
        receiver_task = asyncio.create_task(
            self._receiver(context, list(host_to_ip.values()), sent_packets, 
                         discovered_ips, ip_to_host, result)
        )
        
        # Wait for sender to finish
        await sender_task
        
        # Wait a bit more for responses, then cancel receiver
        await asyncio.sleep(context.performance.timeout * 2)
        receiver_task.cancel()
        
        try:
            await receiver_task
        except asyncio.CancelledError:
            pass
        
        # Mark undiscovered hosts as down
        for host, ip in host_to_ip.items():
            if ip not in discovered_ips:
                result.add_host(host, state="down")
    
    async def _sender(self, context: ScanContext, ips: list, sent_packets: Dict[str, float]):
        """
        Sender thread: Send ICMP echo requests to all IPs quickly.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)
        
        for ip in ips:
            try:
                # Create and send ICMP packet
                packet = IP(dst=ip) / ICMP()
                send(packet, verbose=0)
                
                sent_packets[ip] = time.time()
                
                # Rate limiting
                if rate_limit > 0:
                    await asyncio.sleep(1.0 / rate_limit)
                    
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-ICMP] Error sending to {ip}: {e}")
                continue
    
    async def _receiver(self, context: ScanContext, ips: list,
                       sent_packets: Dict[str, float], 
                       discovered_ips: Set[str],
                       ip_to_host: Dict[str, str],
                       result: ScanResult):
        """
        Receiver thread: Listen for ICMP echo replies.
        Uses batch processing for efficiency.
        """
        timeout = context.performance.timeout * 2
        start_time = time.time()
        check_interval = 0.5  # Check every 0.5 seconds
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(check_interval)
                
                # Batch check: send probes for all pending IPs
                if sent_packets:
                    pending_ips = list(sent_packets.keys())[:20]  # Check up to 20 at a time
                    packets = [IP(dst=ip) / ICMP() for ip in pending_ips]
                    
                    if packets:
                        # Use sr() in a thread to avoid blocking
                        ans, unans = await asyncio.to_thread(
                            sr, packets, timeout=0.3, verbose=0, retry=0
                        )
                        
                        for sent, received in ans:
                            if received.haslayer(ICMP):
                                icmp = received.getlayer(ICMP)
                                if icmp.type == 0:  # Echo Reply
                                    src_ip = received[IP].src
                                    if src_ip not in discovered_ips:
                                        discovered_ips.add(src_ip)
                                        # Get hostname if available, otherwise use IP
                                        host = ip_to_host.get(src_ip, src_ip)
                                        result.add_host(host, state="up")
                                        if context.verbose:
                                            print(f"  [+] Host {host} ({src_ip}) is up")
                                        
                                        # Remove from sent_packets
                                        if src_ip in sent_packets:
                                            del sent_packets[src_ip]
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-ICMP] Error in receiver: {e}")
                continue
        
        # Final batch check for all remaining IPs
        try:
            remaining_ips = [ip for ip in ips if ip not in discovered_ips]
            if remaining_ips:
                packets = [IP(dst=ip) / ICMP() for ip in remaining_ips]
                
                if packets:
                    ans, unans = await asyncio.to_thread(
                        sr, packets, timeout=context.performance.timeout, 
                        verbose=0, retry=1
                    )
                    for sent, received in ans:
                        if received.haslayer(ICMP) and received.getlayer(ICMP).type == 0:
                            src_ip = received[IP].src
                            if src_ip not in discovered_ips:
                                discovered_ips.add(src_ip)
                                host = ip_to_host.get(src_ip, src_ip)
                                result.add_host(host, state="up")
        except Exception:
            pass
    
    def _get_rate_limit(self, rate: str) -> float:
        """
        Convert rate string to packets per second.
        """
        rate_map = {
            "stealthy": 10,      # 10 pps
            "balanced": 100,      # 100 pps
            "fast": 1000,         # 1000 pps
            "insane": 10000       # 10000 pps
        }
        return rate_map.get(rate, 100)

