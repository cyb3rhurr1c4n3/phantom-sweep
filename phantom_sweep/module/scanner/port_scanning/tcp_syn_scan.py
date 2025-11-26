"""
TCP SYN Port Scanner with AI Enhancement
"""
import asyncio
import socket
import time
from typing import Dict, Set, Tuple, List
from scapy.all import IP, TCP, sr, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base.scanner_base import ScannerBase

# Import AI enhancer
try:
    from phantom_sweep.module.scanner.port_scanning.ai.scanner_enhancer import AIScannerEnhancer
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIScannerEnhancer = object  # Dummy for inheritance

conf.verb = 0


class TCPSynScanner(ScannerBase, AIScannerEnhancer):
    """
    TCP SYN Port Scanner (Stealth Scan) with optional AI enhancement.
    Uses async architecture with sender and receiver threads for high-speed scanning.
    
    Features:
    - Standard stealth scanning
    - AI-powered adaptive evasion (if enabled)
    - Real-time strategy adjustment
    """
    
    def __init__(self):
        super().__init__()
        if AI_AVAILABLE:
            AIScannerEnhancer.__init__(self)
    
    def name(self) -> str:
        return "tcp_syn_scan"
    
    def requires_root(self) -> bool:
        return True  # Raw sockets for TCP SYN require root
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform TCP SYN port scanning with optional AI enhancement.
        """
        # Get hosts to scan
        hosts_to_scan = [host for host, info in result.hosts.items() 
                        if info.state == "up"]
        
        if not hosts_to_scan and context.pipeline.ping_tech == "none":
            hosts_to_scan = context.targets.host
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
        
        # === FIX: Check AI evasion properly ===
        ai_mode = False
        
        if context.performance.evasion_mode:
        # Check if 'ai' is in the evasion_mode list
            if isinstance(context.performance.evasion_mode, list):
                if 'ai' in context.performance.evasion_mode:
                    if AI_AVAILABLE:
                        ai_mode = self.enable_ai(verbose=context.verbose or context.debug)
                        if ai_mode:
                            print("[AI] ✓ Evasion mode: ENABLED")
                    else:
                        print("[AI] ✗ AI not available")
            elif context.performance.evasion_mode == 'ai':
                if AI_AVAILABLE:
                    ai_mode = self.enable_ai(verbose=context.verbose or context.debug)
    
        # Add debug output
        if context.debug:
            print(f"[DEBUG] AI Mode: {ai_mode}")
            print(f"[DEBUG] Evasion mode value: {context.performance.evasion_mode}")
        
        # Run async scan
        asyncio.run(self._async_scan(context, result, hosts_to_scan, ports, ai_mode))
        
        # Print AI stats if enabled
        if ai_mode and (context.verbose or context.debug):
            stats = self.get_ai_stats()
            if stats:
                print(f"\n[AI] Scan Statistics:")
                print(f"    Ports scanned: {stats['ports_scanned']}/{stats['total_ports']}")
                print(f"    Detections: {stats['detected_count']}")
                print(f"    Status: {'⚠️ ABORTED' if stats['should_abort'] else '✅ COMPLETE'}")
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, 
                         hosts: list, ports: list, ai_mode: bool = False):
        """
        Async scan with optional AI enhancement.
        """
        if ai_mode:
            await self._ai_async_scan(context, result, hosts, ports)
        else:
            await self._normal_async_scan(context, result, hosts, ports)
    
    async def _normal_async_scan(self, context: ScanContext, result: ScanResult,
                                 hosts: list, ports: list):
        """Normal async scan (original implementation)"""
        print("[DEBUG] NORMAL DA DUOC GOI")
        # Shared data structures
        sent_packets: Dict[Tuple[str, int], float] = {}
        port_states: Dict[Tuple[str, int], str] = {}
        
        # Create tasks
        sender_task = asyncio.create_task(
            self._sender(context, hosts, ports, sent_packets, ai_config=None)
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
        
        # Mark filtered ports
        for host in hosts:
            for port in ports:
                key = (host, port)
                if key not in port_states:
                    result.add_port(host, port, "filtered", "tcp")
    
    async def _ai_async_scan(self, context: ScanContext, result: ScanResult,
                            hosts: List[str], ports: List[int]):
        """AI-enhanced async scan with adaptive strategy"""
        if context.debug:
            print("[DEBUG] ✓ AI async scan started")
        
        for host in hosts:
            if context.verbose or context.debug:
                print(f"\n[*] Scanning {host} (AI mode)...")
            
            # Initialize AI for this host
            self.init_ai_for_scan(len(ports), context.verbose or context.debug)
            
            # Resolve hostname
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                if context.debug:
                    print(f"  [!] Cannot resolve {host}")
                continue
            
            # Scan in adaptive batches
            ports_remaining = list(ports)
            batch_count = 0
            
            while ports_remaining and not self.should_ai_abort():
                # Get AI strategy
                strategy = self.get_ai_strategy()
                
                # Apply strategy
                scan_config = self.apply_ai_strategy(strategy, ports_remaining)
                
                # Get batch
                batch_size = scan_config['batch_size']
                batch_ports = scan_config['ports'][:batch_size]
                ports_remaining = scan_config['ports'][batch_size:]
                
                if context.debug and batch_count % 5 == 0:
                    print(f"  [AI] Batch {batch_count}: {len(batch_ports)} ports, "
                          f"strategy={strategy['timing'] if strategy else 'default'}")
                
                # Execute batch scan
                batch_results = await self._scan_batch_with_config(
                    ip, batch_ports, scan_config, context
                )
                
                # Update results
                for port, state in batch_results.items():
                    result.add_port(host, port, state, "tcp")
                
                # Simulate detection (placeholder - replace with real defender feedback)
                detected = self._simulate_detection(scan_config, batch_count)
                
                # Update AI state
                self.update_ai_state(
                    ports_scanned=len(batch_ports),
                    detected=detected,
                    confidence=0.15 if detected else 0.0
                )
                
                batch_count += 1
            
            # Check abort
            if self.should_ai_abort():
                if context.verbose or context.debug:
                    print(f"  [!] Scan aborted for {host} (AI detected too many alerts)")
    
    async def _scan_batch_with_config(self, ip: str, ports: List[int],
                                     config: Dict, context: ScanContext) -> Dict[int, str]:
        """Scan a batch with specific config"""
        results = {}
        
        # Build packets with config
        packets = []
        for port in ports:
            pkt = IP(dst=ip, ttl=config['ttl']) / TCP(
                dport=port,
                flags='S',
                window=config['window']
            )
            
            if config['tcp_options']:
                pkt[TCP].options = config['tcp_options']
            
            packets.append(pkt)
        
        # Send with timing
        ans, unans = await asyncio.to_thread(
            sr,
            packets,
            timeout=config['timeout'],
            verbose=0,
            retry=0,
            inter=config['inter_delay']
        )
        
        # Parse responses
        for sent, recv in ans:
            port = sent[TCP].dport
            
            if recv.haslayer(TCP):
                tcp = recv.getlayer(TCP)
                
                if tcp.flags == 0x12:  # SYN-ACK
                    results[port] = "open"
                    # Send RST
                    try:
                        rst = IP(dst=ip) / TCP(dport=port, flags='R')
                        send(rst, verbose=0)
                    except:
                        pass
                elif tcp.flags == 0x14:  # RST
                    results[port] = "closed"
        
        # Mark unresponsive as filtered
        for sent in unans:
            port = sent[TCP].dport
            results[port] = "filtered"
        
        return results
    
    def _simulate_detection(self, config: Dict, batch_count: int) -> bool:
        """
        Simulate detection (placeholder for real defender integration).
        Replace this with actual defender API calls in production.
        """
        import random
        
        # Base detection probability
        detection_prob = 0.05
        
        # Adjust based on timing
        if config['inter_delay'] >= 0.5:
            detection_prob *= 0.3  # Slow = less detectable
        elif config['inter_delay'] >= 0.05:
            detection_prob *= 1.0  # Medium
        else:
            detection_prob *= 2.0  # Fast = more detectable
        
        return random.random() < detection_prob
    
    async def _sender(self, context: ScanContext, hosts: list, ports: list,
                     sent_packets: Dict[Tuple[str, int], float],
                     ai_config: Dict = None):
        """
        Sender thread: Send TCP SYN packets.
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
                    
                    # Apply AI config if provided
                    if ai_config:
                        packet[IP].ttl = ai_config.get('ttl', 64)
                        if ai_config.get('tcp_options'):
                            packet[TCP].options = ai_config['tcp_options']
                        if ai_config.get('window'):
                            packet[TCP].window = ai_config['window']
                    
                    send(packet, verbose=0)
                    sent_packets[(ip, port)] = time.time()
                    sent_count += 1
                    
                    if context.verbose and sent_count % 100 == 0:
                        print(f"  [*] Sent {sent_count}/{total_packets} packets...")
                    
                    # Rate limiting
                    if rate_limit > 0:
                        delay = 1.0 / rate_limit
                        if ai_config and 'inter_delay' in ai_config:
                            delay = ai_config['inter_delay']
                        await asyncio.sleep(delay)
                        
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
        """Receiver thread: Listen for TCP responses."""
        timeout = context.performance.timeout * 2
        start_time = time.time()
        processed = set()
        
        while time.time() - start_time < timeout:
            try:
                await asyncio.sleep(0.1)
                
                if sent_packets:
                    keys_to_check = [k for k in sent_packets.keys() 
                                   if k not in processed][:50]
                    
                    if keys_to_check:
                        try:
                            packets = [IP(dst=host_ip) / TCP(dport=port, flags="S") 
                                     for host_ip, port in keys_to_check]
                            
                            ans, unans = await asyncio.to_thread(
                                sr, packets, timeout=0.3, verbose=0, retry=0
                            )
                            
                            for sent, received in ans:
                                if received.haslayer(TCP):
                                    tcp = received.getlayer(TCP)
                                    src_ip = received[IP].src
                                    port = sent[TCP].dport
                                    
                                    if tcp.flags == 0x12:
                                        port_states[(src_ip, port)] = "open"
                                        result.add_port(src_ip, port, "open", "tcp")
                                        
                                        try:
                                            rst_packet = IP(dst=src_ip) / TCP(dport=port, flags="R")
                                            send(rst_packet, verbose=0)
                                        except:
                                            pass
                                    
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
    
    def _get_rate_limit(self, rate: str) -> float:
        """Convert rate string to packets per second."""
        rate_map = {
            "stealthy": 50,
            "balanced": 500,
            "fast": 5000,
            "insane": 50000
        }
        return rate_map.get(rate, 500)