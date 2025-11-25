"""
UDP Port Scanner
"""
import asyncio
import socket
import time
from typing import Dict, Tuple
from scapy.all import IP, UDP, ICMP, sr, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base.scanner_base import ScannerBase

conf.verb = 0


class UDPScanner(ScannerBase):
    """
    UDP Port Scanner.
    Uses async architecture with sender and receiver threads.
    UDP scanning is slower than TCP due to lack of reliable responses.
    """
    
    def name(self) -> str:
        return "udp_scan"
    
    def requires_root(self) -> bool:
        return True  # Raw sockets for UDP require root
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform UDP port scanning using async sender/receiver architecture.
        """
        print("[TEST] UDP WAS HERE!*******************************************************")
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
        ports = parse_port_spec(context.ports.port, context.ports.port_list, is_udp=True)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        if context.verbose:
            print(f"[*] Starting UDP scan on {len(hosts_to_scan)} hosts, {len(ports)} ports...")
            print(f"[!] Note: UDP scanning is slower and less reliable than TCP")
        
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
        
        # UDP needs longer timeout (no reliable responses)
        await asyncio.sleep(context.performance.timeout * 3)
        receiver_task.cancel()
        
        try:
            await receiver_task
        except asyncio.CancelledError:
            pass
        
        # Mark ports with no response as open|filtered (UDP characteristic)
        for host in hosts:
            host_info = result.add_host(host)
            for port in ports:
                key = (host, port)
                if key not in port_states:
                    # No response = open|filtered (common in UDP)
                    result.add_port(host, port, "open|filtered", "udp")
    
    async def _sender(self, context: ScanContext, hosts: list, ports: list,
                     sent_packets: Dict[Tuple[str, int], float]):
        """
        Sender thread: Send UDP packets to all host:port combinations.
        """
        rate_limit = self._get_rate_limit(context.performance.rate)
        total_packets = len(hosts) * len(ports)
        sent_count = 0
        
        for host in hosts:
            try:
                ip = socket.gethostbyname(host)
                
                for port in ports:
                    # Create UDP packet (with minimal payload)
                    packet = IP(dst=ip) / UDP(dport=port) / b"X"
                    send(packet, verbose=0)
                    
                    sent_packets[(ip, port)] = time.time()
                    sent_count += 1
                    
                    if context.verbose and sent_count % 100 == 0:
                        print(f"  [*] Sent {sent_count}/{total_packets} UDP packets...")
                    
                    # Rate limiting (UDP is slower)
                    if rate_limit > 0:
                        await asyncio.sleep(1.0 / rate_limit)
                        
            except (socket.gaierror, Exception) as e:
                if context.debug:
                    print(f"  [DEBUG-UDP] Error sending to {host}: {e}")
                continue
        
        if context.verbose:
            print(f"  [*] Finished sending {sent_count} UDP packets")
    
    async def _receiver(self, context: ScanContext, hosts: list, ports: list,
                       sent_packets: Dict[Tuple[str, int], float],
                       port_states: Dict[Tuple[str, int], str],
                       result: ScanResult):
        """
        Receiver thread: Listen for UDP responses or ICMP error messages.
        """
        timeout = context.performance.timeout * 3
        start_time = time.time()
        processed = set()
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(0.2)  # Longer delay for UDP
                
                if sent_packets:
                    # Process pending packets in batch
                    keys_to_check = [k for k in sent_packets.keys() 
                                   if k not in processed][:30]  # Batch size for UDP
                    
                    if keys_to_check:
                        try:
                            # Create batch of packets
                            packets = [IP(dst=host_ip) / UDP(dport=port) / b"X" 
                                     for host_ip, port in keys_to_check]
                            
                            # Use asyncio.to_thread for non-blocking sr()
                            ans, unans = await asyncio.to_thread(
                                sr, packets, timeout=0.5, verbose=0, retry=0
                            )
                            
                            for sent, received in ans:
                                src_ip = received[IP].src
                                port = sent[UDP].dport
                                
                                # UDP response = port is open
                                if received.haslayer(UDP):
                                    port_states[(src_ip, port)] = "open"
                                    result.add_port(src_ip, port, "open", "udp")
                                    processed.add((src_ip, port))
                                
                                # ICMP Port Unreachable (type 3, code 3) = port is closed
                                elif received.haslayer(ICMP):
                                    icmp = received.getlayer(ICMP)
                                    if icmp.type == 3 and icmp.code == 3:
                                        port_states[(src_ip, port)] = "closed"
                                        result.add_port(src_ip, port, "closed", "udp")
                                        processed.add((src_ip, port))
                                    
                                    # Other ICMP type 3 = filtered
                                    elif icmp.type == 3:
                                        port_states[(src_ip, port)] = "filtered"
                                        result.add_port(src_ip, port, "filtered", "udp")
                                        processed.add((src_ip, port))
                                
                                if (src_ip, port) in sent_packets:
                                    del sent_packets[(src_ip, port)]
                        except Exception as e:
                            if context.debug:
                                print(f"  [DEBUG-UDP] Batch processing error: {e}")
                            continue
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-UDP] Error in receiver: {e}")
                continue
        
        # Final batch check
        try:
            remaining = [(h, p) for h, p in sent_packets.keys() 
                        if (h, p) not in processed]
            
            if remaining:
                packets = []
                host_port_map = {}
                for host_ip, port in remaining[:50]:  # Smaller batch for UDP
                    try:
                        packet = IP(dst=host_ip) / UDP(dport=port) / b"X"
                        packets.append(packet)
                        host_port_map[len(packets) - 1] = (host_ip, port)
                    except:
                        continue
                
                if packets:
                    ans, unans = await asyncio.to_thread(
                        sr, packets, timeout=context.performance.timeout * 2,
                        verbose=0, retry=1
                    )
                    
                    for sent, received in ans:
                        idx = ans.index((sent, received))
                        if idx in host_port_map:
                            host_ip, port = host_port_map[idx]
                            src_ip = received[IP].src
                            
                            if received.haslayer(UDP):
                                result.add_port(src_ip, port, "open", "udp")
                            elif received.haslayer(ICMP):
                                icmp = received.getlayer(ICMP)
                                if icmp.type == 3 and icmp.code == 3:
                                    result.add_port(src_ip, port, "closed", "udp")
                                elif icmp.type == 3:
                                    result.add_port(src_ip, port, "filtered", "udp")
        except Exception:
            pass
    
    def _get_rate_limit(self, rate: str) -> float:
        """Convert rate string to packets per second (slower for UDP)."""
        rate_map = {
            "stealthy": 20,
            "balanced": 200,
            "fast": 2000,
            "insane": 20000
        }
        return rate_map.get(rate, 200)

