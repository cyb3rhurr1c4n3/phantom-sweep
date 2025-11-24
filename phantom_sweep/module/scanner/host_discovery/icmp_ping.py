"""
ICMP Echo (Ping) Host Discovery Scanner with Auto-fallback
"""
import asyncio
import socket
import time
from typing import Dict, Set
from scapy.all import IP, ICMP, sr, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class ICMPPingScanner(ScannerBase):
    """
    ICMP Echo Request (Ping) Host Discovery Scanner.
    Auto-fallback: If no hosts respond, assumes all hosts are up.
    """
    
    def name(self) -> str:
        return "icmp_ping"
    
    def requires_root(self) -> bool:
        return False
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform ICMP ping host discovery with auto-fallback.
        """
        hosts_to_scan = context.targets.host
        if not hosts_to_scan:
            return
        
        if context.verbose or context.debug:
            print(f"[*] Starting ICMP ping discovery for {len(hosts_to_scan)} hosts...")
        
        # Run async scan with error handling
        try:
            asyncio.run(self._async_scan(context, result, hosts_to_scan))
        except Exception as e:
            if context.debug:
                print(f"[DEBUG-ICMP] Ping failed: {e}")
                import traceback
                traceback.print_exc()
        
        # === AUTO-FALLBACK: If no hosts discovered, assume all are up ===
        up_count = sum(1 for h in result.hosts.values() if h.state == "up")
        
        if up_count == 0:
            if context.verbose or context.debug:
                print(f"[!] ICMP ping failed to discover any hosts")
                print(f"[*] Assuming all {len(hosts_to_scan)} host(s) are up (auto-fallback)")
            
            # Mark all hosts as up
            for host in hosts_to_scan:
                result.add_host(host, state="up")
        
        elif context.verbose or context.debug:
            print(f"[*] Host discovery completed: {up_count}/{len(hosts_to_scan)} hosts up")
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Async scan with sender and receiver tasks."""
        # Map hostnames to IPs
        host_to_ip: Dict[str, str] = {}
        ip_to_host: Dict[str, str] = {}
        
        # Resolve all hostnames first
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                host_to_ip[host] = ip
                ip_to_host[ip] = host
                
                if context.debug:
                    print(f"[DEBUG-ICMP] Resolved {host} → {ip}")
            except socket.gaierror as e:
                if context.debug:
                    print(f"[DEBUG-ICMP] Cannot resolve {host}: {e}")
                # Don't mark as down yet - wait for fallback
        
        if not host_to_ip:
            return  # No resolvable hosts
        
        # Shared data structure
        discovered_ips: Set[str] = set()
        sent_packets: Dict[str, float] = {}
        
        # Create tasks with timeout
        try:
            sender_task = asyncio.create_task(
                self._sender(context, list(host_to_ip.values()), sent_packets)
            )
            receiver_task = asyncio.create_task(
                self._receiver(context, list(host_to_ip.values()), sent_packets, 
                             discovered_ips, ip_to_host, result)
            )
            
            # Wait for sender
            await asyncio.wait_for(sender_task, timeout=30.0)
            
            # Wait for responses
            await asyncio.sleep(context.performance.timeout * 2)
            receiver_task.cancel()
            
            try:
                await receiver_task
            except asyncio.CancelledError:
                pass
        
        except Exception as e:
            if context.debug:
                print(f"[DEBUG-ICMP] Scan error: {e}")
        
        # Mark only discovered hosts (don't mark as down - let fallback handle it)
        for host, ip in host_to_ip.items():
            if ip in discovered_ips:
                # Already added by receiver
                pass
    
    async def _sender(self, context: ScanContext, ips: list, sent_packets: Dict[str, float]):
        """Sender thread: Send ICMP echo requests."""
        rate_limit = self._get_rate_limit(context.performance.rate)
        
        for ip in ips:
            try:
                packet = IP(dst=ip) / ICMP()
                send(packet, verbose=0)
                sent_packets[ip] = time.time()
                
                if context.debug:
                    print(f"[DEBUG-ICMP] Sent ping to {ip}")
                
                if rate_limit > 0:
                    await asyncio.sleep(1.0 / rate_limit)
                    
            except Exception as e:
                if context.debug:
                    print(f"[DEBUG-ICMP] Error sending to {ip}: {e}")
    
    async def _receiver(self, context: ScanContext, ips: list,
                       sent_packets: Dict[str, float], 
                       discovered_ips: Set[str],
                       ip_to_host: Dict[str, str],
                       result: ScanResult):
        """Receiver thread: Listen for ICMP echo replies."""
        timeout = context.performance.timeout * 2
        start_time = time.time()
        check_interval = 0.5
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(check_interval)
                
                if sent_packets:
                    pending_ips = list(sent_packets.keys())[:20]
                    packets = [IP(dst=ip) / ICMP() for ip in pending_ips]
                    
                    if packets:
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
                                        host = ip_to_host.get(src_ip, src_ip)
                                        result.add_host(host, state="up")
                                        
                                        if context.verbose or context.debug:
                                            print(f"  [+] Host {host} ({src_ip}) is UP")
                                        
                                        if src_ip in sent_packets:
                                            del sent_packets[src_ip]
            except Exception as e:
                if context.debug:
                    print(f"[DEBUG-ICMP] Receiver error: {e}")
        
        # Final batch check
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
                                
                                if context.verbose or context.debug:
                                    print(f"  [+] Host {host} ({src_ip}) is UP (final check)")
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