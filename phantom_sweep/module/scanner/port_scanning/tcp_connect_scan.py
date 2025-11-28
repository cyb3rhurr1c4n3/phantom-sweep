"""
TCP Connect Scan - Fast parallel full-connection scanning
Optimized for speed while maintaining service detection compatibility
"""
import socket
import asyncio
import time
from typing import Set, Dict
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base import ScannerBase


class TCPConnectScanner(ScannerBase):
    """TCP Connect Scan - Fast parallel full TCP connection scanning"""
    
    @property
    def name(self) -> str:
        return "connect"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP Connect Scan (fast parallel, service detection compatible)"
    
    def requires_root(self) -> bool:
        return False  # Connect scan không cần root
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform ultra-fast TCP connect scan"""
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
        
        if context.verbose:
            print(f"[*] Starting TCP Connect scan on {len(up_hosts)} hosts ({len(ports)} ports)...")
        
        try:
            asyncio.run(self._async_connect_scan(context, result, up_hosts, ports))
        except Exception as e:
            if context.debug:
                print(f"[!] TCP scan error: {e}")
    
    async def _async_connect_scan(
        self, context: ScanContext, result: ScanResult, hosts: list, ports: list
    ):
        """
        Ultra-fast async connect scan using asyncio
        
        Speed optimizations:
        1. Asyncio for massive parallelism (thousands of concurrent connections)
        2. Adaptive semaphore based on thread count
        3. Early timeout detection
        4. Batch result processing
        """
        start_time = time.time()
        open_ports: Dict[str, Set[int]] = {h: set() for h in hosts}
        
        # Adaptive semaphore: limit concurrent connections
        # Higher thread count = more concurrent connections
        max_concurrent = context.performance.thread * 20  # Multiply for async efficiency
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_port(host: str, port: int) -> tuple:
            """Test single port with semaphore control"""
            async with semaphore:
                is_open = await self._async_test_port(host, port, context.performance.timeout)
                return (host, port, is_open)
        
        # Create all tasks
        tasks = []
        for host in hosts:
            for port in ports:
                task = asyncio.create_task(test_port(host, port))
                tasks.append(task)
        
        if context.debug:
            print(f"[DEBUG] Created {len(tasks)} async tasks with {max_concurrent} max concurrent")
        
        # Execute all tasks and collect results
        completed = 0
        total = len(tasks)
        
        for coro in asyncio.as_completed(tasks):
            host, port, is_open = await coro
            if is_open:
                open_ports[host].add(port)
            
            completed += 1
            
            # Progress indicator for large scans
            if context.verbose and completed % 1000 == 0:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                print(f"[*] Progress: {completed}/{total} ({rate:.0f} ports/sec)")
        
        # Add results
        for host in hosts:
            for port in ports:
                state = "open" if port in open_ports[host] else "closed"
                result.add_port(host, port, protocol="tcp", state=state)
        
        if context.verbose:
            total_open = sum(len(p) for p in open_ports.values())
            elapsed = time.time() - start_time
            print(f"[*] Scan completed in {elapsed:.2f}s - {total_open} open ports")
    
    async def _async_test_port(self, host: str, port: int, timeout: float) -> bool:
        """
        Async test if port is open using asyncio streams
        
        This is MUCH faster than threading because:
        - No thread overhead
        - Can handle 10,000+ concurrent connections
        - Non-blocking I/O
        
        Returns:
            True if port is open, False otherwise
        """
        try:
            # asyncio.open_connection = async socket.connect()
            # Much faster than sync socket for parallel connections
            future = asyncio.open_connection(host, port)
            
            # Wait for connection with timeout
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            
            # Port is open - close connection immediately
            writer.close()
            await writer.wait_closed()
            
            return True
            
        except asyncio.TimeoutError:
            # Timeout = port filtered or slow service
            return False
        except ConnectionRefusedError:
            # Connection refused = port closed
            return False
        except OSError:
            # Network error, host unreachable, etc.
            return False
        except Exception:
            # Any other error = treat as closed
            return False