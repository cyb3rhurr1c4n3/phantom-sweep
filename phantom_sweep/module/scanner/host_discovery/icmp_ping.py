"""
ICMP Echo (Ping) Host Discovery Scanner - Masscan-style architecture
"""
import asyncio
import socket
import time
import threading
from typing import Dict, Set
from scapy.all import IP, ICMP, send, sniff, conf, get_if_list
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class ICMPPingScanner(ScannerBase):
    """
    ICMP Echo Request (Ping) Host Discovery Scanner.
    Uses raw socket with separate sender and receiver threads.
    - Sender: Fire-and-forget ICMP echo requests
    - Receiver: Continuous sniffing for ICMP echo replies
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
        # Resolve all hostnames to IPs
        host_to_ip: Dict[str, str] = {}
        ip_to_host: Dict[str, str] = {}
        target_ips = set()
        
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                host_to_ip[host] = ip
                ip_to_host[ip] = host
                target_ips.add(ip)
            except socket.gaierror:
                result.add_host(host, state="down")
        
        if not target_ips:
            return
        
        # Shared data structures
        sent_packets: Dict[str, float] = {}  # ip -> timestamp
        discovered_ips: Set[str] = set()
        sniff_stop_event = threading.Event()
        
        # Build BPF filter for ICMP echo replies
        bpf_filter = f"icmp and icmp[0]==0 and ({' or '.join([f'host {ip}' for ip in target_ips])})"
        
        # Create receiver thread (sniffing)
        receiver_thread = threading.Thread(
            target=self._receiver_sniff,
            args=(context, target_ips, discovered_ips, ip_to_host, result, 
                  bpf_filter, sniff_stop_event),
            daemon=True
        )
        receiver_thread.start()
        
        # Give receiver a moment to start
        await asyncio.sleep(0.1)
        
        # Create sender task (fire-and-forget)
        sender_task = asyncio.create_task(
            self._sender(context, list(target_ips), sent_packets)
        )
        
        # Wait for sender to finish
        await sender_task
        
        # Wait for responses
        wait_time = context.performance.timeout * 2
        await asyncio.sleep(wait_time)
        
        # Stop sniffing
        sniff_stop_event.set()
        receiver_thread.join(timeout=2)
        
        # Mark undiscovered hosts as down
        for host, ip in host_to_ip.items():
            if ip not in discovered_ips:
                result.add_host(host, state="down")
    
    async def _sender(self, context: ScanContext, ips: list, sent_packets: Dict[str, float]):
        """
        Sender thread: Fire-and-forget ICMP echo requests.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)
        
        # Apply randomization if evasion mode includes it
        if context.performance.evasion_mode and "randomize" in context.performance.evasion_mode:
            import random
            ips = list(ips)
            random.shuffle(ips)
        
        for ip in ips:
            try:
                # Create and send ICMP echo request
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
    
    def _receiver_sniff(self, context: ScanContext, target_ips: Set[str],
                       discovered_ips: Set[str], ip_to_host: Dict[str, str],
                       result: ScanResult, bpf_filter: str, stop_event: threading.Event):
        """
        Receiver thread: Continuously sniff for ICMP echo replies.
        """
        def process_packet(packet):
            """Process a received ICMP echo reply"""
            try:
                if not packet.haslayer(ICMP) or not packet.haslayer(IP):
                    return
                
                icmp = packet.getlayer(ICMP)
                ip_layer = packet.getlayer(IP)
                src_ip = ip_layer.src
                
                # Check if this is an echo reply (type 0) from our targets
                if icmp.type == 0 and src_ip in target_ips:
                    if src_ip not in discovered_ips:
                        discovered_ips.add(src_ip)
                        host = ip_to_host.get(src_ip, src_ip)
                        result.add_host(host, state="up")
                        
                        if context.verbose:
                            print(f"  [+] Host {host} ({src_ip}) is up")
                
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-ICMP] Error processing packet: {e}")
        
        # Start sniffing with BPF filter
        try:
            # Get network interface
            iface = None
            try:
                ifaces = get_if_list()
                if ifaces:
                    for preferred in ['eth0', 'eth1', 'wlan0', 'enp0s3']:
                        if preferred in ifaces:
                            iface = preferred
                            break
                    if not iface:
                        iface = ifaces[0]
            except:
                pass
            
            # Sniff until stop event is set
            timeout = context.performance.timeout * 2
            start_time = time.time()
            
            while not stop_event.is_set() and (time.time() - start_time) < timeout:
                try:
                    sniff(
                        filter=bpf_filter,
                        prn=process_packet,
                        timeout=0.5,
                        iface=iface,
                        stop_filter=lambda x: stop_event.is_set(),
                        store=False
                    )
                except Exception as e:
                    if context.debug:
                        print(f"  [DEBUG-ICMP] Sniff error: {e}")
                    time.sleep(0.1)
                    
        except Exception as e:
            if context.debug:
                print(f"  [DEBUG-ICMP] Receiver error: {e}")
    
    def _get_rate_limit(self, rate: str) -> float:
        """Convert rate string to packets per second."""
        rate_map = {
            "stealthy": 10,
            "balanced": 100,
            "fast": 1000,
            "insane": 10000
        }
        return rate_map.get(rate, 100)
