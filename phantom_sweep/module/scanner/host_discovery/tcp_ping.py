"""
TCP SYN/ACK Ping Host Discovery Scanner with Auto-fallback
"""
import asyncio
import socket
import time
from typing import Dict, Set
from scapy.all import IP, TCP, sr, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class TCPPingScanner(ScannerBase):
    """
    TCP SYN/ACK Ping Host Discovery Scanner.
    Auto-fallback: If no hosts respond, assumes all hosts are up.
    """
    
    COMMON_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
    
    def name(self) -> str:
        return "tcp_ping"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform TCP SYN/ACK ping host discovery with auto-fallback.
        """
        hosts_to_scan = context.targets.host
        if not hosts_to_scan:
            return
        
        if context.verbose or context.debug:
            print(f"[*] Starting TCP SYN/ACK ping discovery for {len(hosts_to_scan)} hosts...")
        
        # Run async scan
        try:
            asyncio.run(self._async_scan(context, result, hosts_to_scan))
        except Exception as e:
            if context.debug:
                print(f"[DEBUG-TCP-Ping] Error: {e}")
        
        # === AUTO-FALLBACK ===
        up_count = sum(1 for h in result.hosts.values() if h.state == "up")
        
        if up_count == 0:
            if context.verbose or context.debug:
                print(f"[!] TCP ping failed to discover any hosts")
                print(f"[*] Assuming all {len(hosts_to_scan)} host(s) are up (auto-fallback)")
            
            for host in hosts_to_scan:
                result.add_host(host, state="up")
        
        elif context.verbose or context.debug:
            print(f"[*] Host discovery completed: {up_count}/{len(hosts_to_scan)} hosts up")
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Async scan with sender and receiver tasks."""
        discovered_hosts: Set[str] = set()
        sent_packets: Dict[tuple, float] = {}
        
        sender_task = asyncio.create_task(
            self._sender(context, hosts, sent_packets)
        )
        receiver_task = asyncio.create_task(
            self._receiver(context, hosts, sent_packets, discovered_hosts, result)
        )
        
        await sender_task
        await asyncio.sleep(context.performance.timeout * 2)
        receiver_task.cancel()
        
        try:
            await receiver_task
        except asyncio.CancelledError:
            pass
    
    async def _sender(self, context: ScanContext, hosts: list, 
                     sent_packets: Dict[tuple, float]):
        """Sender thread: Send TCP SYN packets."""
        rate_limit = self._get_rate_limit(context.performance.rate)
        
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                
                for port in self.COMMON_PORTS:
                    packet = IP(dst=ip) / TCP(dport=port, flags="S")
                    send(packet, verbose=0)
                    sent_packets[(ip, port)] = time.time()
                    
                    if rate_limit > 0:
                        await asyncio.sleep(1.0 / rate_limit)
                        
            except Exception as e:
                if context.debug:
                    print(f"[DEBUG-TCP-Ping] Error sending to {host}: {e}")
    
    async def _receiver(self, context: ScanContext, hosts: list,
                       sent_packets: Dict[tuple, float],
                       discovered_hosts: Set[str],
                       result: ScanResult):
        """Receiver thread: Listen for TCP responses."""
        timeout = context.performance.timeout * 2
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(0.1)
                
                if sent_packets:
                    target_key = max(sent_packets.keys(), key=lambda k: sent_packets[k])
                    target_ip, target_port = target_key
                    
                    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
                    ans, unans = sr(packet, timeout=0.5, verbose=0, retry=0)
                    
                    for sent, received in ans:
                        if received.haslayer(TCP):
                            tcp = received.getlayer(TCP)
                            src_ip = received[IP].src
                            
                            if tcp.flags in [0x12, 0x14]:
                                if src_ip not in discovered_hosts:
                                    discovered_hosts.add(src_ip)
                                    result.add_host(src_ip, state="up")
                                    
                                    if context.verbose or context.debug:
                                        print(f"  [+] Host {src_ip} is UP (TCP response)")
                                    
                                    keys_to_remove = [k for k in sent_packets.keys() if k[0] == src_ip]
                                    for k in keys_to_remove:
                                        del sent_packets[k]
            except Exception as e:
                if context.debug:
                    print(f"[DEBUG-TCP-Ping] Receiver error: {e}")
        
        # Final check
        try:
            packets = []
            for host in hosts:
                if host not in discovered_hosts:
                    try:
                        ip = socket.gethostbyname(host)
                        for port in self.COMMON_PORTS[:3]:
                            packets.append(IP(dst=ip) / TCP(dport=port, flags="S"))
                    except:
                        continue
            
            if packets:
                ans, unans = sr(packets, timeout=context.performance.timeout, 
                               verbose=0, retry=1)
                for sent, received in ans:
                    if received.haslayer(TCP):
                        tcp = received.getlayer(TCP)
                        if tcp.flags in [0x12, 0x14]:
                            src_ip = received[IP].src
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