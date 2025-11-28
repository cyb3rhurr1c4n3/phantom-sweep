"""
TCP Connect Scan - Fast parallel full-connection scanning
Optimized for speed while maintaining service detection compatibility
"""
import socket
import asyncio
import time
from typing import Set, Dict, List
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base import ScannerBase

# === ADD AI IMPORT ===
try:
    from phantom_sweep.module.scanner.port_scanning.ai.scanner_enhancer import AIScannerEnhancer
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIScannerEnhancer = object


class TCPConnectScanner(ScannerBase, AIScannerEnhancer if AI_AVAILABLE else object):
    """TCP Connect Scan - Fast parallel full TCP connection scanning with optional AI evasion"""
    
    def __init__(self):
        ScannerBase.__init__(self)
        if AI_AVAILABLE:
            AIScannerEnhancer.__init__(self)
    
    @property
    def name(self) -> str:
        return "connect"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP Connect Scan (fast parallel, service detection compatible, AI-enhanced)"
    
    def requires_root(self) -> bool:
        return False
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform ultra-fast TCP connect scan with optional AI evasion"""
        hosts = context.targets.host
        if not hosts:
            return
        
        # Get up hosts
        up_hosts = [h for h in hosts if h in result.hosts and result.hosts[h].state == "up"]
        if not up_hosts:
            if context.verbose:
                print("[*] No up hosts to scan")
            return
        
        # Parse ports
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        # === CHECK AI MODE ===
        ai_mode = False
        if AI_AVAILABLE and context.performance.evasion_mode:
            if 'ai' in context.performance.evasion_mode:
                ai_mode = self.enable_ai(verbose=context.verbose or context.debug)
                if ai_mode:
                    print("[AI] ✓ AI Evasion Mode: ENABLED")
        
        if context.verbose:
            mode_str = "AI-Enhanced " if ai_mode else ""
            print(f"[*] Starting {mode_str}TCP Connect scan on {len(up_hosts)} hosts ({len(ports)} ports)...")
        
        try:
            asyncio.run(self._async_connect_scan(context, result, up_hosts, ports, ai_mode))
        except Exception as e:
            if context.debug:
                print(f"[!] TCP scan error: {e}")
        
        # Print AI stats
        if ai_mode and (context.verbose or context.debug):
            stats = self.get_ai_stats()
            if stats:
                print(f"\n[AI] Scan Statistics:")
                print(f"    Ports scanned: {stats['ports_scanned']}/{stats['total_ports']}")
                print(f"    Detections: {stats['detected_count']}")
    
    async def _async_connect_scan(
        self, context: ScanContext, result: ScanResult, hosts: list, ports: list, ai_mode: bool = False
    ):
        """Async connect scan with optional AI evasion"""
        
        if ai_mode:
            # AI scan mode
            await self._ai_async_scan(context, result, hosts, ports)
        else:
            # Normal fast scan mode
            await self._normal_async_scan(context, result, hosts, ports)
    
    async def _normal_async_scan(self, context: ScanContext, result: ScanResult, hosts: list, ports: list):
        """Normal ultra-fast scan (original implementation)"""
        start_time = time.time()
        open_ports: Dict[str, Set[int]] = {h: set() for h in hosts}
        
        max_concurrent = context.performance.thread * 20
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_port(host: str, port: int) -> tuple:
            async with semaphore:
                is_open = await self._async_test_port(host, port, context.performance.timeout)
                return (host, port, is_open)
        
        tasks = []
        for host in hosts:
            for port in ports:
                task = asyncio.create_task(test_port(host, port))
                tasks.append(task)
        
        if context.debug:
            print(f"[DEBUG] Created {len(tasks)} async tasks with {max_concurrent} max concurrent")
        
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            host, port, is_open = await coro
            if is_open:
                open_ports[host].add(port)
            
            completed += 1
            
            if context.verbose and completed % 1000 == 0:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                print(f"[*] Progress: {completed}/{total} ({rate:.0f} ports/sec)")
        
        for host in hosts:
            for port in ports:
                state = "open" if port in open_ports[host] else "closed"
                result.add_port(host, port, protocol="tcp", state=state)
        
        if context.verbose:
            total_open = sum(len(p) for p in open_ports.values())
            elapsed = time.time() - start_time
            print(f"[*] Scan completed in {elapsed:.2f}s - {total_open} open ports")
    
    async def _ai_async_scan(self, context: ScanContext, result: ScanResult, hosts: List[str], ports: List[int]):
        """AI-enhanced adaptive scan"""
        for host in hosts:
            if context.verbose or context.debug:
                print(f"\n[*] Scanning {host} (AI mode)...")
            
            # Initialize AI
            self.init_ai_for_scan(len(ports), context.verbose or context.debug)
            
            ports_remaining = list(ports)
            batch_count = 0
            
            while ports_remaining and not self.should_ai_abort():
                # Get AI strategy
                strategy = self.get_ai_strategy()
                
                if strategy is None:
                    break
                
                # Apply strategy
                scan_config = self.apply_ai_strategy(strategy, ports_remaining)
                
                # Get batch
                batch_size = min(scan_config['batch_size'], len(ports_remaining))
                batch_ports = scan_config['ports'][:batch_size]
                ports_remaining = scan_config['ports'][batch_size:]
                
                if context.debug and batch_count % 5 == 0:
                    print(f"  [AI] Batch {batch_count}: {len(batch_ports)} ports, "
                          f"timing={strategy['timing']}, delay={scan_config['inter_delay']:.3f}s")
                
                # Scan batch
                for port in batch_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(scan_config['timeout'])
                        
                        result_code = sock.connect_ex((host, port))
                        
                        if result_code == 0:
                            result.add_port(host, port, protocol="tcp", state="open")
                            if context.verbose:
                                print(f"  [+] {port}/tcp open")
                        else:
                            result.add_port(host, port, protocol="tcp", state="closed")
                        
                        sock.close()
                        
                        # AI delay
                        await asyncio.sleep(scan_config['inter_delay'])
                        
                    except socket.timeout:
                        result.add_port(host, port, protocol="tcp", state="filtered")
                    except Exception as e:
                        if context.debug:
                            print(f"  [!] Error: {e}")
                
                # Simulate detection
                detected = self._simulate_detection(scan_config)
                
                # Update AI
                self.update_ai_state(
                    ports_scanned=len(batch_ports),
                    detected=detected,
                    confidence=0.15 if detected else 0.0
                )
                
                batch_count += 1
            
            if self.should_ai_abort():
                print(f"  [!] AI scan aborted (too many detections)")
    
    async def _async_test_port(self, host: str, port: int, timeout: float) -> bool:
        """Async test if port is open"""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except asyncio.TimeoutError:
            return False
        except ConnectionRefusedError:
            return False
        except OSError:
            return False
        except Exception:
            return False
    
    def _simulate_detection(self, config: Dict) -> bool:
        """Simulate detection probability"""
        import random
        detection_prob = 0.05
        
        if config['inter_delay'] >= 0.5:
            detection_prob *= 0.3
        elif config['inter_delay'] >= 0.05:
            detection_prob *= 1.0
        else:
            detection_prob *= 2.0
        
        return random.random() < detection_prob