"""
CSV Reporter - Comma-separated values output format
"""
import csv
from typing import Optional
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ReporterBase


class CSVReporter(ReporterBase):
    """
    CSV Reporter - Outputs scan results in CSV format (spreadsheet-compatible).
    """
    
    @property
    def name(self) -> str:
        return "csv"
    
    @property
    def type(self) -> str:
        return "reporter"
    
    @property
    def description(self) -> str:
        return "CSV format (spreadsheet-compatible)"
    
    def export(self, context: ScanContext, result: ScanResult, filename: Optional[str] = None) -> None:
        """
        Export scan results in CSV format.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult containing scan results
            filename: Optional filename to save output. If None, print to stdout.
        """
        # Update statistics
        result.update_statistics()
        
        # Prepare CSV data
        csv_rows = []
        
        # Add header row
        csv_rows.append([
            "Host",
            "Host State",
            "OS",
            "OS Version",
            "OS Accuracy (%)",
            "Port",
            "Protocol",
            "Port State",
            "Service",
            "Service Version",
            "Banner"
        ])
        
        # Process each host
        if result.hosts:
            for host, host_info in result.hosts.items():
                # Combine TCP and UDP ports
                all_ports = []
                
                # Add TCP ports
                if host_info.tcp_ports:
                    for port_num, port_info in host_info.tcp_ports.items():
                        # Apply open_only filter if needed
                        if context.open_only and port_info.state != "open":
                            continue
                        all_ports.append((port_num, "tcp", port_info))
                
                # Add UDP ports
                if host_info.udp_ports:
                    for port_num, port_info in host_info.udp_ports.items():
                        # Apply open_only filter if needed
                        if context.open_only and port_info.state != "open":
                            continue
                        all_ports.append((port_num, "udp", port_info))
                
                # If no ports, add a single row for the host
                if not all_ports:
                    csv_rows.append([
                        host,
                        host_info.state,
                        host_info.os or "",
                        host_info.os_version or "",
                        host_info.os_accuracy or "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        ""
                    ])
                else:
                    # Add rows for each port
                    for idx, (port_num, protocol, port_info) in enumerate(all_ports):
                        csv_rows.append([
                            host if idx == 0 else "",  # Only show host on first port
                            host_info.state if idx == 0 else "",
                            host_info.os or "" if idx == 0 else "",
                            host_info.os_version or "" if idx == 0 else "",
                            host_info.os_accuracy or "" if idx == 0 else "",
                            port_num,
                            protocol.upper(),
                            port_info.state,
                            port_info.service or "",
                            port_info.version or "",
                            port_info.banner or ""
                        ])
        
        # Write output
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerows(csv_rows)
                if context.verbose:
                    print(f"[*] CSV output saved to {filename}")
            except Exception as e:
                print(f"[!] Error writing to {filename}: {e}")
        else:
            # Print to stdout
            for row in csv_rows:
                print(",".join(str(cell) for cell in row))
