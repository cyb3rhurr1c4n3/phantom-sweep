"""
Demo Script - Example scripting plugin demonstrating HTTP service check
"""
import socket
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScriptingBase


class HTTPHeaderCheck(ScriptingBase):
    """
    HTTP Header Check Script - Analyzes HTTP headers of detected web services
    to identify server information and security headers.
    """
    
    @property
    def name(self) -> str:
        return "http_headers"
    
    @property
    def type(self) -> str:
        return "scripting"
    
    @property
    def description(self) -> str:
        return "Check HTTP headers for web services"
    
    def run(self, context: ScanContext, result: ScanResult) -> None:
        """
        Run HTTP header check on detected web services.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult to update with script results
        """
        if context.verbose:
            print("[*] Script: HTTP Headers Check")
        
        common_http_ports = [80, 8080, 8000, 8888, 3000, 5000, 9000]
        findings_count = 0
        
        for host_addr in result.hosts:
            host_info = result.hosts[host_addr]
            
            # Check TCP ports for HTTP services
            if host_info.tcp_ports:
                for port_num, port_info in host_info.tcp_ports.items():
                    # Check if port is open and likely to be HTTP
                    if port_info.state == 'open' and (port_num in common_http_ports or 'http' in (port_info.service or '').lower()):
                        try:
                            headers = self._get_http_headers(host_addr, port_num, context.performance.timeout)
                            
                            if headers:
                                # Store results in script results
                                if not hasattr(host_info, 'scripts'):
                                    host_info.scripts = {}
                                
                                server = headers.get('Server', 'Unknown')
                                security = self._check_security_headers(headers)
                                missing_headers = [k for k, v in security.items() if not v]
                                
                                script_key = f"http_headers_{port_num}"
                                host_info.scripts[script_key] = {
                                    'port': port_num,
                                    'server': server,
                                    'security_headers': security,
                                    'missing_security_headers': missing_headers,
                                    'headers_count': len(headers)
                                }
                                
                                findings_count += 1
                                if context.verbose:
                                    security_status = "✓" if len(missing_headers) == 0 else f"⚠ Missing {len(missing_headers)}/5"
                                    print(f"    {host_addr}:{port_num}/tcp - {server} [{security_status}]")
                        
                        except Exception as e:
                            if context.debug:
                                print(f"    [!] Error checking {host_addr}:{port_num}: {e}")
        
        if context.verbose:
            if findings_count > 0:
                print(f"    Found {findings_count} HTTP service(s)")
            else:
                print(f"    No HTTP services detected")
    
    def _get_http_headers(self, host, port, timeout=5.0) -> dict:
        """
        Retrieve HTTP headers from a server.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            
        Returns:
            Dictionary of HTTP headers
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            
            # Receive response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            
            sock.close()
            
            # Parse headers
            response_str = response.decode('utf-8', errors='ignore')
            headers = {}
            
            lines = response_str.split('\r\n')
            for line in lines[1:]:  # Skip status line
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                if line == '':  # End of headers
                    break
            
            return headers
        
        except Exception as e:
            return {}
    
    def _check_security_headers(self, headers) -> dict:
        """
        Check for common security headers.
        
        Args:
            headers: Dictionary of HTTP headers
            
        Returns:
            Dictionary with security header status (True = present, False = missing)
        """
        security_headers = {
            'HSTS': headers.get('Strict-Transport-Security') is not None,
            'X-Content-Type-Options': headers.get('X-Content-Type-Options') is not None,
            'X-Frame-Options': headers.get('X-Frame-Options') is not None,
            'CSP': headers.get('Content-Security-Policy') is not None,
            'X-XSS-Protection': headers.get('X-XSS-Protection') is not None,
        }
        return security_headers
