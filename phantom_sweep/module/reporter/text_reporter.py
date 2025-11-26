"""
Text Reporter - Human-readable text output format
"""
import sys
from typing import Optional
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ReporterBase


class TextReporter(ReporterBase):
    """
    Text Reporter - Outputs scan results in human-readable text format.
    """
    
    @property
    def name(self) -> str:
        return "text"
    
    @property
    def type(self) -> str:
        return "reporter"
    
    @property
    def description(self) -> str:
        return "Human-readable text format"
    
    def export(self, context: ScanContext, result: ScanResult, filename: Optional[str] = None) -> None:
        """
        Export scan results in text format.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult containing scan results
            filename: Optional filename to save output. If None, print to stdout.
        """
        output_lines = []
        
        # Header
        output_lines.append("=" * 70)
        output_lines.append("PhantomSweep Scan Results")
        output_lines.append("=" * 70)
        output_lines.append("")
        
        # Scan metadata
        if result.scan_start_time:
            from datetime import datetime
            start_dt = datetime.fromisoformat(result.scan_start_time)
            output_lines.append(f"Scan started: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        if result.scan_end_time:
            from datetime import datetime
            end_dt = datetime.fromisoformat(result.scan_end_time)
            output_lines.append(f"Scan ended: {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        if result.scan_duration is not None:
            duration = result.scan_duration
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            seconds = duration % 60
            if hours > 0:
                output_lines.append(f"Scan duration: {hours}h {minutes}m {seconds:.2f}s")
            elif minutes > 0:
                output_lines.append(f"Scan duration: {minutes}m {seconds:.2f}s")
            else:
                output_lines.append(f"Scan duration: {seconds:.2f}s")
        output_lines.append("")
        
        # Statistics
        result.update_statistics()
        output_lines.append("Statistics:")
        output_lines.append(f"  Total hosts: {result.total_hosts}")
        output_lines.append(f"  Up hosts: {result.up_hosts}")
        output_lines.append(f"  Total ports scanned: {result.total_ports_scanned}")
        output_lines.append(f"  Open ports: {result.open_ports}")
        output_lines.append("")
        output_lines.append("=" * 70)
        output_lines.append("")
        
        # Host details
        if not result.hosts:
            output_lines.append("No hosts found.")
        else:
            for host in sorted(result.hosts.keys()):
                host_info = result.hosts[host]
                output_lines.append(f"Host: {host}")
                output_lines.append(f"  State: {host_info.state}")
                
                # OS information
                if host_info.os:
                    os_str = f"  OS: {host_info.os}"
                    if host_info.os_accuracy:
                        os_str += f" (accuracy: {host_info.os_accuracy}%)"
                    output_lines.append(os_str)
                
                # Check if we should filter to open ports only
                open_only = context.open_only
                
                # TCP ports
                if host_info.tcp_ports:
                    tcp_ports_to_show = host_info.tcp_ports
                    if open_only:
                        tcp_ports_to_show = {p: info for p, info in host_info.tcp_ports.items() 
                                           if info.state == "open"}
                    
                    if tcp_ports_to_show:
                        output_lines.append("  TCP Ports:")
                        for port in sorted(tcp_ports_to_show.keys()):
                            port_info = tcp_ports_to_show[port]
                            port_line = f"    {port}: {port_info.state}"
                            
                            if port_info.service:
                                port_line += f" ({port_info.service}"
                                if port_info.version:
                                    port_line += f" {port_info.version}"
                                port_line += ")"
                            
                            if port_info.banner:
                                port_line += f" - Banner: {port_info.banner[:50]}"
                            
                            output_lines.append(port_line)
                
                # UDP ports
                if host_info.udp_ports:
                    udp_ports_to_show = host_info.udp_ports
                    if open_only:
                        udp_ports_to_show = {p: info for p, info in host_info.udp_ports.items() 
                                           if info.state == "open"}
                    
                    if udp_ports_to_show:
                        output_lines.append("  UDP Ports:")
                        for port in sorted(udp_ports_to_show.keys()):
                            port_info = udp_ports_to_show[port]
                            port_line = f"    {port}: {port_info.state}"
                            
                            if port_info.service:
                                port_line += f" ({port_info.service}"
                                if port_info.version:
                                    port_line += f" {port_info.version}"
                                port_line += ")"
                            
                            output_lines.append(port_line)
                
                # Script results
                if host_info.scripts:
                    output_lines.append("  Scripts:")
                    for script_name, script_result in host_info.scripts.items():
                        output_lines.append(f"    {script_name}: {script_result}")
                
                output_lines.append("")
        
        output_lines.append("=" * 70)
        
        # Write output
        output_text = "\n".join(output_lines)
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(output_text)
                if context.verbose:
                    print(f"[*] Text output saved to {filename}")
            except Exception as e:
                print(f"[!] Error writing to {filename}: {e}")
        else:
            # Print to stdout
            print(output_text)


