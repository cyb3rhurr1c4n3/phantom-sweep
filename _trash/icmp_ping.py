"""
ICMP Echo (Ping) Host Discovery Scanner - Masscan-style architecture
"""
import asyncio
import socket
import time
from typing import Dict
from scapy.all import IP, ICMP, send, AsyncSniffer, conf
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
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform ICMP ping host discovery using async sender/receiver architecture.
        """
        hosts_to_scan = context.targets.host
        if not hosts_to_scan:
            return
        
        if context.verbose or context.debug:
            print(f"[*] Starting ICMP ping discovery for {len(hosts_to_scan)} hosts...")
        
        try:
            asyncio.run(self._async_scan(context, result, hosts_to_scan))
        except Exception as e:
            if context.debug:
                print(f"  [DEBUG-ICMP] Error during ICMP ping scan: {e}")
                import traceback
                traceback.print_exc()

        up_count = sum(1 for h in result.hosts.values() if h.state == "up")
        if up_count == 0:
            if context.verbose or context.debug:
                print(f"[!] ICMP ping failed to discover any hosts")
                print(f"[*] Assuming all {len(hosts_to_scan)} host(s) are up (auto-fallback)")
            for host in hosts_to_scan:
                result.add_host(host, state="up")
        elif context.verbose or context.debug:
            print(f"[*] Host discovery completed: {up_count}/{len(hosts_to_scan)} hosts up")

    # Ultility Methods
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """
        Async scan with sender and receiver tasks.
        """
        # Resolve all hostnames to IPs
        host_to_ip: Dict[str, str] = {}
        ip_to_host: Dict[str, str] = {}
        
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                host_to_ip[host] = ip
                ip_to_host[ip] = host
                if context.debug:
                    print(f"[DEBUG-ICMP] Resolved {host} → {ip}")
            except socket.gaierror:
                result.add_host(host, state="down")
                if context.debug:
                    print(f"[DEBUG-ICMP] Cannot resolve {host}!")        
        if not host_to_ip:
            return
        
        target_ips = set(host_to_ip.values())
        discovered_ips = set()

        # Build BPF filter for sniffing
        if len(target_ips) <= 50:
            # For small lists, use explicit host filter
            host_filter = " or ".join([f"src host {ip}" for ip in target_ips])
            bpf_filter = f"icmp[icmptype] == icmp-echoreply and ({host_filter})"
        else:
            # For large lists, just filter by type
            bpf_filter = "icmp[icmptype] == icmp-echoreply" 

        # Define packet handler for receiver
        def handle_packet(pkt):
            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                icmp = pkt[ICMP]
                if icmp.type == 0: # Echo Reply
                    src_ip = pkt[IP].src
                    if src_ip in target_ips and src_ip not in discovered_ips:
                        discovered_ips.add(src_ip)
                        host = ip_to_host.get(src_ip, src_ip)
                        result.add_host(host, state="up")
                        if context.verbose:
                            print(f"  [+] Host {host} ({src_ip}) is up")

        # ===== Step 1: Start sniffer before sending packets =====
        sniffer = AsyncSniffer(
            filter=bpf_filter,
            prn=handle_packet,
            store=False
        )
        sniffer.start()
        await asyncio.sleep(0.1)  # Give sniffer time to start

        # ===== Step 2: Firing all packet as fast as possible =====
        start_time = time.time()
        await self._send_all_packets(context, list(target_ips))
        send_duration = time.time() - start_time

        if context.debug:
            print(f"[DEBUG-ICMP] Sent {len(target_ips)} packets in {send_duration:.3f}s")

        # ===== Step 3: Wait for responses =====
        wait_time = context.performance.timeout * 2
        await asyncio.sleep(wait_time)

        # ===== Step 4: Stop sniffer =====
        sniffer.stop()

        if context.debug:
            print(f"[DEBUG-ICMP] Discovered {len(discovered_ips)}/{len(target_ips)} hosts")

    async def _send_all_packets(self, context: ScanContext, ips: list):
        """
        Send ALL packets with minimal delay.
        This is the KEY to Masscan's speed.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)

        # Calculate delay between packets
        if rate_limit > 0:
            delay = 1.0 / rate_limit
        else:
            delay = 0.0
        
        # Build all packet at once, avoid per-packet overhead
        packets = [IP(dst=ip)/ICMP(id=0x1234, seq=i) for i, ip in enumerate(ips)]

        if context.debug:
            print(f"[DEBUG-ICMP] Sending at rate: {rate_limit} pps (delay: {delay:.6f}s)")

        # Send packets with rate limiting
        try:
            # For very high rates, send in batch to minimize overhead
            if rate_limit >= 1000:
                batch_size = min(100, len(packets))
                for i in range(0, len(packets), batch_size):
                    batch = packets[i:i+batch_size]
                    for pkt in batch:
                        send(pkt, verbose=0)
                    if delay > 0:
                        await asyncio.sleep(delay * batch_size)
            else:
                # For lower rates, send one by one
                for pkt in packets:
                    send(pkt, verbose=0)
                    if delay > 0:
                        await asyncio.sleep(delay)
        except Exception as e:
            if context.debug:
                print(f"[DEBUG-ICMP] Send error: {e}")

    def _get_rate_limit(self, rate: str) -> float:
        """Convert rate string to packets per second."""
        rate_map = {
            "stealthy": 10,
            "balanced": 500,
            "fast": 5000,
            "insane": 50000
        }
        return rate_map.get(rate, 500)