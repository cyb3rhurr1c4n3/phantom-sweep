"""
TCP SYN/ACK Ping Host Discovery Scanner
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
    Sends TCP SYN packets to common ports to discover hosts.
    Uses async architecture with sender and receiver threads.
    """
    
    # Common ports for TCP ping
    COMMON_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
    
    def name(self) -> str:
        return "tcp_ping"
    
    def requires_root(self) -> bool:
        return True  # Raw sockets for TCP SYN require root
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform TCP SYN/ACK ping host discovery using async sender/receiver architecture.
        """
        hosts_to_scan = context.targets.host
        if not hosts_to_scan:
            return
        
        if context.verbose:
            print(f"[*] Starting TCP SYN/ACK ping discovery for {len(hosts_to_scan)} hosts...")
        
        # Run async scan
        asyncio.run(self._async_scan(context, result, hosts_to_scan))
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """
        Async scan with sender and receiver tasks.
        """
        # Shared data structure for results
        discovered_hosts: Set[str] = set()
        sent_packets: Dict[tuple, float] = {}  # (host, port) -> timestamp
        
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
                     sent_packets: Dict[tuple, float]):
        """
        Sender thread: Send TCP SYN packets to common ports quickly.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)
        
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                
                # Send SYN to common ports
                for port in self.COMMON_PORTS:
                    packet = IP(dst=ip) / TCP(dport=port, flags="S")
                    send(packet, verbose=0)
                    sent_packets[(ip, port)] = time.time()
                    
                    # Rate limiting
                    if rate_limit > 0:
                        await asyncio.sleep(1.0 / rate_limit)
                        
            except (socket.gaierror, Exception) as e:
                if context.debug:
                    print(f"  [DEBUG-TCP-Ping] Error sending to {host}: {e}")
                continue
    
    async def _receiver(self, context: ScanContext, hosts: list,
                       sent_packets: Dict[tuple, float],
                       discovered_hosts: Set[str],
                       result: ScanResult):
        """
        Receiver thread: Listen for TCP SYN/ACK or RST responses.
        """
        timeout = context.performance.timeout * 2
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(0.1)
                
                if sent_packets:
                    # Check for responses
                    target_key = max(sent_packets.keys(), key=lambda k: sent_packets[k])
                    target_ip, target_port = target_key
                    
                    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
                    ans, unans = sr(packet, timeout=0.5, verbose=0, retry=0)
                    
                    for sent, received in ans:
                        if received.haslayer(TCP):
                            tcp = received.getlayer(TCP)
                            src_ip = received[IP].src
                            
                            # SYN/ACK (0x12) or RST (0x14) means host is up
                            if tcp.flags in [0x12, 0x14]:
                                if src_ip not in discovered_hosts:
                                    discovered_hosts.add(src_ip)
                                    result.add_host(src_ip, state="up")
                                    if context.verbose:
                                        print(f"  [+] Host {src_ip} is up (TCP response)")
                                    
                                    # Remove all packets for this host
                                    keys_to_remove = [k for k in sent_packets.keys() if k[0] == src_ip]
                                    for k in keys_to_remove:
                                        del sent_packets[k]
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-TCP-Ping] Error in receiver: {e}")
                continue
        
        # Final check: Use sr() to get all responses
        try:
            packets = []
            for host in hosts:
                if host not in discovered_hosts:
                    try:
                        ip = socket.gethostbyname(host)
                        for port in self.COMMON_PORTS[:3]:  # Check first 3 ports
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

