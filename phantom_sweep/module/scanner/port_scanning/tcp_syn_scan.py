"""
TCP SYN Port Scanner
"""
import asyncio
import socket
import time
from typing import Dict, Set, Tuple
from scapy.all import IP, TCP, sr, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class TCPSynScanner(ScannerBase):
    """
    TCP SYN Port Scanner (Stealth Scan).
    Uses async architecture with sender and receiver threads for high-speed scanning.
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
        # If no hosts discovered or all down, check if we should scan anyway
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
        # Shared data structures
        sent_packets: Dict[Tuple[str, int], float] = {}  # (host, port) -> timestamp
        port_states: Dict[Tuple[str, int], str] = {}  # (host, port) -> state
        
        # Create tasks
        sender_task = asyncio.create_task(
            self._sender(context, hosts, ports, sent_packets)
        )
        receiver_task = asyncio.create_task(
            self._receiver(context, hosts, ports, sent_packets, port_states, result)
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
        
        # Mark filtered ports (no response received)
        for host in hosts:
            host_info = result.add_host(host)
            for port in ports:
                key = (host, port)
                if key not in port_states:
                    # No response = filtered or open|filtered
                    result.add_port(host, port, "filtered", "tcp")
    
    async def _sender(self, context: ScanContext, hosts: list, ports: list,
                     sent_packets: Dict[Tuple[str, int], float]):
        """
        Sender thread: Send TCP SYN packets to all host:port combinations quickly.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)
        total_packets = len(hosts) * len(ports)
        sent_count = 0
        
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                
                for port in ports:
                    # Create TCP SYN packet
                    packet = IP(dst=ip) / TCP(dport=port, flags="S")
                    send(packet, verbose=0)
                    
                    sent_packets[(ip, port)] = time.time()
                    sent_count += 1
                    
                    if context.verbose and sent_count % 100 == 0:
                        print(f"  [*] Sent {sent_count}/{total_packets} packets...")
                    
                    # Rate limiting
                    if rate_limit > 0:
                        await asyncio.sleep(1.0 / rate_limit)
                        
            except (socket.gaierror, Exception) as e:
                if context.debug:
                    print(f"  [DEBUG-TCP-SYN] Error sending to {host}: {e}")
                continue
        
        if context.verbose:
            print(f"  [*] Finished sending {sent_count} packets")
    
    async def _receiver(self, context: ScanContext, hosts: list, ports: list,
                       sent_packets: Dict[Tuple[str, int], float],
                       port_states: Dict[Tuple[str, int], str],
                       result: ScanResult):
        """
        Receiver thread: Listen for TCP SYN/ACK, RST, or ICMP responses.
        """
        timeout = context.performance.timeout * 2
        start_time = time.time()
        processed = set()
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(0.1)
                
                # Process pending packets in batch
                if sent_packets:
                    # Get a batch of packets to check
                    keys_to_check = [k for k in sent_packets.keys() 
                                   if k not in processed][:50]  # Larger batch
                    
                    if keys_to_check:
                        try:
                            # Create batch of packets
                            packets = [IP(dst=host_ip) / TCP(dport=port, flags="S") 
                                     for host_ip, port in keys_to_check]
                            
                            # Use asyncio.to_thread for non-blocking sr()
                            ans, unans = await asyncio.to_thread(
                                sr, packets, timeout=0.3, verbose=0, retry=0
                            )
                            
                            for sent, received in ans:
                                if received.haslayer(TCP):
                                    tcp = received.getlayer(TCP)
                                    src_ip = received[IP].src
                                    port = sent[TCP].dport
                                    
                                    # SYN/ACK (0x12) = open
                                    if tcp.flags == 0x12:
                                        port_states[(src_ip, port)] = "open"
                                        result.add_port(src_ip, port, "open", "tcp")
                                        
                                        # Send RST to close connection
                                        try:
                                            rst_packet = IP(dst=src_ip) / TCP(dport=port, flags="R")
                                            send(rst_packet, verbose=0)
                                        except:
                                            pass
                                    
                                    # RST (0x14) = closed
                                    elif tcp.flags == 0x14:
                                        port_states[(src_ip, port)] = "closed"
                                        result.add_port(src_ip, port, "closed", "tcp")
                                    
                                    processed.add((src_ip, port))
                                    if (src_ip, port) in sent_packets:
                                        del sent_packets[(src_ip, port)]
                        except Exception as e:
                            if context.debug:
                                print(f"  [DEBUG-TCP-SYN] Batch processing error: {e}")
                            continue
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-TCP-SYN] Error in receiver: {e}")
                continue
        
        # Final batch check for remaining packets
        try:
            remaining = [(h, p) for h, p in sent_packets.keys() 
                        if (h, p) not in processed]
            
            if remaining:
                packets = []
                host_port_map = {}
                for host_ip, port in remaining[:100]:  # Limit batch size
                    try:
                        packet = IP(dst=host_ip) / TCP(dport=port, flags="S")
                        packets.append(packet)
                        host_port_map[len(packets) - 1] = (host_ip, port)
                    except:
                        continue
                
                if packets:
                    ans, unans = await asyncio.to_thread(
                        sr, packets, timeout=context.performance.timeout,
                        verbose=0, retry=1
                    )
                    
                    for sent, received in ans:
                        idx = ans.index((sent, received))
                        if idx in host_port_map:
                            host_ip, port = host_port_map[idx]
                            
                            if received.haslayer(TCP):
                                tcp = received.getlayer(TCP)
                                src_ip = received[IP].src
                                
                                if tcp.flags == 0x12:  # SYN/ACK
                                    result.add_port(src_ip, port, "open", "tcp")
                                elif tcp.flags == 0x14:  # RST
                                    result.add_port(src_ip, port, "closed", "tcp")
        except Exception:
            pass
    
    def _get_rate_limit(self, rate: str) -> float:
        """Convert rate string to packets per second."""
        rate_map = {
            "stealthy": 50,
            "balanced": 500,
            "fast": 5000,
            "insane": 50000
        }
        return rate_map.get(rate, 500)

