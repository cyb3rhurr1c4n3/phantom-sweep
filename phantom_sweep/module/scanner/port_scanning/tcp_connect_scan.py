"""
TCP Connect Scanner - Ultra-fast async port scanning
Uses asyncio.open_connection() for non-blocking concurrent TCP connections
"""
import asyncio
import time
from typing import List, Optional

from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScannerBase
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports


class TCPConnectScanner(ScannerBase):
    
    @property
    def name(self) -> str:
        return "connect"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP Connect Scan (async, fast, service-compatible)"
    
    def requires_root(self) -> bool:
        return False
    
    def __init__(self, max_concurrent: int = 1000):
        self.max_concurrent = max_concurrent
        self.semaphore: Optional[asyncio.Semaphore] = None
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Entry point for TCP Connect scan"""
        targets = self._prepare_targets(context, result)
        
        if not targets:
            return
        
        if context.verbose:
            num_hosts = len(set(t[0] for t in targets))
            num_ports = len(set(t[1] for t in targets))
            print(f"[*] TCP Connect: {num_hosts} host(s) x {num_ports} port(s) = {len(targets)} connections")
        
        try:
            asyncio.run(self._async_scan(context, result, targets))
        except Exception as e:
            if context.debug:
                import traceback
                print(f"[!] Scan error: {e}")
                traceback.print_exc()
    
    def _prepare_targets(self, context: ScanContext, result: ScanResult) -> List[tuple]:
        """
        Prepare list of (host, port) tuples to scan.
        
        Reads:
        - Discovered UP hosts from result
        - Port specification from context.ports
        
        Returns:
        - List of (host, port) tuples
        """
        # Get UP hosts from discovery phase
        hosts = result.get_discovered_hosts() if result.hosts else context.targets.host
        
        if not hosts:
            if context.verbose:
                print("[*] No hosts available for port scanning")
            return []
        
        # Parse ports from context
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        
        # Apply exclude ports
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        # Create all (host, port) combinations
        targets = [(host, port) for host in hosts for port in ports]
        
        return targets
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, targets: List[tuple]) -> None:

        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Calculate timeout
        timeout = self._calculate_timeout(len(targets), context)
        
        if context.debug:
            print(f"[DEBUG] TCP timeout: {timeout}s, concurrency: {self.max_concurrent}")
        
        # Create tasks for all targets - must use create_task to actually create Task objects
        tasks = [
            asyncio.create_task(self._scan_target(target[0], target[1], timeout, context, result))
            for target in targets
        ]
        
        start_time = time.time()
        
        # Run all tasks concurrently
        if context.verbose:
            await self._run_with_progress(tasks)
        else:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        duration = time.time() - start_time
        
        # Print summary
        if context.verbose:
            open_count = result.get_open_ports_count()
            rate = len(targets) / duration if duration > 0 else 0
            print(f"[*] TCP scan complete: {open_count} open ports in {duration:.2f}s ({rate:.0f} ports/sec)")
    
    async def _scan_target(self, host: str, port: int, timeout: float, context: ScanContext, result: ScanResult) -> None:
        """Scan a single host:port combination"""
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                # Port is OPEN
                writer.close()
                await writer.wait_closed()
                result.add_port(host, port, "open", protocol="tcp")
                
            except asyncio.TimeoutError:
                # Timeout = filtered or host down
                result.add_port(host, port, "filtered", protocol="tcp")
                
            except ConnectionRefusedError:
                # Connection refused = port CLOSED
                result.add_port(host, port, "closed", protocol="tcp")
                
            except (OSError, Exception):
                # Network error = filtered
                result.add_port(host, port, "filtered", protocol="tcp")
    
    async def _run_with_progress(self, tasks: List) -> None:
        """Run tasks and show progress"""
        total = len(tasks)
        completed = 0
        print(f"[*] Progress: 0/{total} (0.0%)", end='\r')
        
        # Wait for all tasks to complete, showing progress
        for coro in asyncio.as_completed(tasks):
            await coro
            completed += 1
            if completed % max(1, total // 10) == 0 or completed == total:
                percent = (completed / total) * 100
                print(f"[*] Progress: {completed}/{total} ({percent:.1f}%)", end='\r')
        
        print()  # Newline after progress
    
    def _calculate_timeout(self, num_targets: int, context: ScanContext) -> float:
        """Calculate optimal timeout for TCP connections"""
        base = getattr(context.performance, 'timeout', 3.0)
        # Adaptive timeout based on scan size
        if num_targets <= 100:
            return max(1.0, base * 0.5)
        elif num_targets <= 1000:
            return max(2.0, base)
        else:
            return max(3.0, base * 1.5)

