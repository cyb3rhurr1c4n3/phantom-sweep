"""
TCP Connect Port Scanner
"""
import asyncio
import socket
import time
from typing import List, Tuple
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base.scanner_base import ScannerBase


class TCPConnectScanner(ScannerBase):
    """
    TCP Connect Port Scanner.
    Uses standard socket connect() - no root required.
    Uses async architecture for concurrent scanning.
    """
    
    def name(self) -> str:
        return "tcp_connect_scan"
    
    def requires_root(self) -> bool:
        return False  # Uses standard sockets, no root needed
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform TCP Connect port scanning using async concurrent connections.
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
            print(f"[*] Starting TCP Connect scan on {len(hosts_to_scan)} hosts, {len(ports)} ports...")
        
        # Run async scan
        asyncio.run(self._async_scan(context, result, hosts_to_scan, ports))
    
    async def _async_scan(self, context: ScanContext, result: ScanResult,
                         hosts: list, ports: list):
        """
        Async scan with concurrent connection attempts.
        Optimized to process in batches for better performance.
        """
        # Create semaphore to limit concurrent connections
        max_concurrent = context.performance.thread
        semaphore = asyncio.Semaphore(max_concurrent)
        
        # Create tasks for all host:port combinations
        # Process in batches to avoid creating too many tasks at once
        batch_size = max_concurrent * 10
        all_tasks = []
        for host in hosts:
            for port in ports:
                all_tasks.append((host, port))
        
        # Process in batches
        for i in range(0, len(all_tasks), batch_size):
            batch = all_tasks[i:i + batch_size]
            tasks = [
                asyncio.create_task(
                    self._scan_port(context, result, host, port, semaphore)
                )
                for host, port in batch
            ]
            # Wait for batch to complete before starting next batch
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _scan_port(self, context: ScanContext, result: ScanResult,
                        host: str, port: int, semaphore: asyncio.Semaphore):
        """
        Scan a single port using TCP connect.
        """
        async with semaphore:
            try:
                # Resolve hostname
                ip = socket.gethostbyname(host)
                
                # Create socket and attempt connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(context.performance.timeout)
                
                # Use asyncio to make connect() non-blocking
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(sock.connect, (ip, port)),
                        timeout=context.performance.timeout
                    )
                    
                    # Connection successful = port is open
                    result.add_port(ip, port, "open", "tcp")
                    sock.close()
                    
                except (socket.timeout, ConnectionRefusedError, OSError):
                    # Connection refused = port is closed
                    result.add_port(ip, port, "closed", "tcp")
                    sock.close()
                    
                except asyncio.TimeoutError:
                    # Timeout = port is filtered
                    result.add_port(ip, port, "filtered", "tcp")
                    sock.close()
                    
            except socket.gaierror:
                if context.debug:
                    print(f"  [DEBUG-TCP-Connect] Cannot resolve {host}")
            except Exception as e:
                if context.debug:
                    print(f"  [DEBUG-TCP-Connect] Error scanning {host}:{port}: {e}")
                try:
                    result.add_port(host, port, "filtered", "tcp")
                except:
                    pass

