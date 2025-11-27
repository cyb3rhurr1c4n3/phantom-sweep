"""
TCP SYN Port Scanner - Masscan-style architecture
"""
import asyncio
import socket
import time
import threading
from typing import Dict, Set, Tuple
from scapy.all import IP, TCP, send, sniff, conf, get_if_list
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class TCPSynScanner(ScannerBase):
    """
    TCP SYN Port Scanner (Stealth Scan) - Masscan-style architecture.
    Uses raw socket with separate sender and receiver threads for high-speed scanning.
    - Sender: Fire-and-forget packet sending (no waiting for responses)
    - Receiver: Continuous sniffing with BPF filter for responses
    """
    
    def name(self) -> str:
        return "tcp_syn_scan"
    
    def requires_root(self) -> bool:
        return True  # Raw sockets for TCP SYN require root
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform TCP SYN port scanning using async sender/receiver architecture.
        """
        # Get hosts to scan (only up hosts from discovery phase)
        hosts_to_scan = [host for host, info in result.hosts.items() 
                        if info.state == "up"]
        
        # If no hosts are up and ping_tech was "none", scan all targets anyway
        if not hosts_to_scan and context.pipeline.ping_tech == "none":
            hosts_to_scan = context.targets.host
            # Mark them as up for scanning purposes
            for host in hosts_to_scan:
                result.add_host(host, state="up")
        
        if not hosts_to_scan:
            if context.verbose:
                print("[*] No hosts to scan")
            return
        
        # Parse ports
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        if context.verbose:
            print(f"[*] Starting TCP SYN scan on {len(hosts_to_scan)} hosts, {len(ports)} ports...")
        
        # Run async scan
        asyncio.run(self._async_scan(context, result, hosts_to_scan, ports))
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, 
                         hosts: list, ports: list):
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
                if context.verbose:
                    print(f"  [!] Cannot resolve {host}")
                continue
        
        if not target_ips:
            return
        
        # Shared data structures
        sent_packets: Dict[Tuple[str, int], float] = {}  # (ip, port) -> timestamp
        port_states: Dict[Tuple[str, int], str] = {}  # (ip, port) -> state
        received_responses: Set[Tuple[str, int]] = set()  # Track processed responses
        sniff_stop_event = threading.Event()
        
        # Build BPF filter for all target IPs
        # Format: "tcp and (src host 192.168.1.1 or src host 192.168.1.2 ...)"
        bpf_filter = f"tcp and ({' or '.join([f'src host {ip}' for ip in target_ips])})"
        
        # Create receiver thread (sniffing)
        receiver_thread = threading.Thread(
            target=self._receiver_sniff,
            args=(context, target_ips, ports, port_states, received_responses, 
                  result, ip_to_host, bpf_filter, sniff_stop_event),
            daemon=True
        )
        receiver_thread.start()
        
        # Give receiver a moment to start
        await asyncio.sleep(0.1)
        
        # Create sender task (fire-and-forget)
        sender_task = asyncio.create_task(
            self._sender(context, list(target_ips), ports, sent_packets)
        )
        
        # Wait for sender to finish
        await sender_task
        
        if context.verbose:
            print(f"  [*] Finished sending {len(sent_packets)} packets, waiting for responses...")
        
        # Wait for responses with adaptive timeout
        # Check periodically if we've received all responses or timeout
        max_wait_time = min(context.performance.timeout * 2, 10.0)  # Cap at 10 seconds max
        check_interval = 0.5  # Check every 0.5 seconds
        elapsed = 0.0
        last_response_count = len(received_responses)
        no_response_count = 0
        
        while elapsed < max_wait_time:
            await asyncio.sleep(check_interval)
            elapsed += check_interval
            
            # Check if we got new responses
            current_response_count = len(received_responses)
            if current_response_count > last_response_count:
                last_response_count = current_response_count
                no_response_count = 0
            else:
                no_response_count += 1
                # If no new responses for 2 seconds, we're probably done
                if no_response_count * check_interval >= 2.0:
                    if context.verbose:
                        print(f"  [*] No new responses for 2s, finishing early...")
                    break
        
        # Stop sniffing
        sniff_stop_event.set()
        receiver_thread.join(timeout=2)
        
        # Mark filtered ports (no response received)
        for ip in target_ips:
            host = ip_to_host.get(ip, ip)
            host_info = result.add_host(host)
            for port in ports:
                key = (ip, port)
                if key not in port_states:
                    # No response = filtered or open|filtered
                    result.add_port(host, port, "filtered", "tcp")
    
    async def _sender(self, context: ScanContext, ips: list, ports: list,
                     sent_packets: Dict[Tuple[str, int], float]):
        """
        Sender thread: Fire-and-forget TCP SYN packets to all host:port combinations.
        Uses send() for maximum speed - no waiting for responses.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)
        total_packets = len(ips) * len(ports)
        sent_count = 0
        
        # Apply randomization if evasion mode includes it
        if context.performance.evasion_mode and "randomize" in context.performance.evasion_mode:
            import random
            # Create all combinations and shuffle
            combinations = [(ip, port) for ip in ips for port in ports]
            random.shuffle(combinations)
        else:
            combinations = [(ip, port) for ip in ips for port in ports]
        
        for ip, port in combinations:
            try:
                # Create TCP SYN packet
                packet = IP(dst=ip) / TCP(dport=port, flags="S")
                
                # Fire-and-forget: send without waiting
                send(packet, verbose=0)
                
                sent_packets[(ip, port)] = time.time()
                sent_count += 1
                
                if context.verbose and sent_count % 1000 == 0:
                    print(f"  [*] Sent {sent_count}/{total_packets} packets...")
                
                # Rate limiting
                if rate_limit > 0:
                    await asyncio.sleep(1.0 / rate_limit)
                    
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-TCP-SYN] Error sending to {ip}:{port}: {e}")
                continue
        
        if context.verbose:
            print(f"  [*] Finished sending {sent_count} packets")
    
    def _receiver_sniff(self, context: ScanContext, target_ips: Set[str], ports: list,
                       port_states: Dict[Tuple[str, int], str],
                       received_responses: Set[Tuple[str, int]],
                       result: ScanResult, ip_to_host: Dict[str, str],
                       bpf_filter: str, stop_event: threading.Event):
        """
        Receiver thread: Continuously sniff for TCP responses using BPF filter.
        Processes SYN/ACK (open) and RST (closed) responses.
        """
        def process_packet(packet):
            """Process a received packet"""
            try:
                if not packet.haslayer(TCP) or not packet.haslayer(IP):
                    return
                
                tcp = packet.getlayer(TCP)
                ip_layer = packet.getlayer(IP)
                src_ip = ip_layer.src
                dst_port = tcp.dport  # Destination port in response = our target port
                
                # Check if this is a response to one of our targets
                if src_ip not in target_ips:
                    return
                
                # Check if we're scanning this port
                if dst_port not in ports:
                    return
                
                key = (src_ip, dst_port)
                
                # Skip if already processed
                if key in received_responses:
                    return
                
                # SYN/ACK (0x12) = port is open
                if tcp.flags == 0x12:
                    port_states[key] = "open"
                    received_responses.add(key)
                    host = ip_to_host.get(src_ip, src_ip)
                    result.add_port(host, dst_port, "open", "tcp")
                    
                    if context.verbose:
                        print(f"  [+] {host}:{dst_port}/tcp open")
                    
                    # Send RST to close connection (optional, but good practice)
                    try:
                        rst_packet = IP(dst=src_ip) / TCP(dport=dst_port, flags="R")
                        send(rst_packet, verbose=0)
                    except:
                        pass
                
                # RST (0x14) = port is closed
                elif tcp.flags == 0x14:
                    port_states[key] = "closed"
                    received_responses.add(key)
                    host = ip_to_host.get(src_ip, src_ip)
                    result.add_port(host, dst_port, "closed", "tcp")
                    
                    if context.debug:
                        print(f"  [DEBUG] {host}:{dst_port}/tcp closed")
                
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-TCP-SYN] Error processing packet: {e}")
        
        # Start sniffing with BPF filter
        try:
            # Get network interface (use default if available)
            iface = None
            try:
                ifaces = get_if_list()
                if ifaces:
                    # Prefer eth0, eth1, or first available
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
                    # Sniff with short timeout to check stop_event periodically
                    sniff(
                        filter=bpf_filter,
                        prn=process_packet,
                        timeout=0.5,
                        iface=iface,
                        stop_filter=lambda x: stop_event.is_set(),
                        store=False  # Don't store packets, just process them
                    )
                except Exception as e:
                    if context.debug:
                        print(f"  [DEBUG-TCP-SYN] Sniff error: {e}")
                    # Continue sniffing
                    time.sleep(0.1)
                    
        except Exception as e:
            if context.debug:
                print(f"  [DEBUG-TCP-SYN] Receiver error: {e}")
    
    def _get_rate_limit(self, rate: str) -> float:
        """Convert rate string to packets per second."""
        rate_map = {
            "stealthy": 50,      # 50 pps
            "balanced": 500,     # 500 pps
            "fast": 5000,        # 5000 pps
            "insane": 50000      # 50000 pps (very fast)
        }
        return rate_map.get(rate, 500)
