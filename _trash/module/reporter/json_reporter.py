"""
JSON Reporter - JSON output format
"""
import json
from typing import Optional
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from _trash.reporter_base import ReporterBase


class JSONReporter(ReporterBase):
    """
    JSON Reporter - Outputs scan results in JSON format (machine-readable).
    """
    
    def name(self) -> str:
        return "json"
    
    def export(self, context: ScanContext, result: ScanResult, filename: Optional[str] = None) -> None:
        """
        Export scan results in JSON format.
        
        Args:
            context: ScanContext containing scan configuration
            result: ScanResult containing scan results
            filename: Optional filename to save output. If None, print to stdout.
        """
        # Update statistics
        result.update_statistics()
        
        # Convert to dictionary
        output_dict = result.to_dict()
        
        # Add scan configuration to metadata
        output_dict["metadata"]["scan_config"] = {
            "targets": {
                "hosts": context.targets.host[:10],  # Limit to first 10 for brevity
                "host_count": len(context.targets.host),
                "exclude_hosts": context.targets.exclude_host
            },
            "ports": {
                "port_spec": context.ports.port,
                "port_list_file": context.ports.port_list,
                "exclude_ports": context.ports.exclude_port
            },
            "pipeline": {
                "ping_tech": context.pipeline.ping_tech,
                "scan_tech": context.pipeline.scan_tech,
                "service_detection_mode": context.pipeline.service_detection_mode,
                "os_fingerprinting_mode": context.pipeline.os_fingerprinting_mode,
                "scripts": context.pipeline.script
            },
            "performance": {
                "rate": context.performance.rate,
                "thread": context.performance.thread,
                "timeout": context.performance.timeout,
                "evasion_mode": context.performance.evasion_mode
            }
        }
        
        # Convert to JSON string
        json_output = json.dumps(output_dict, indent=2, ensure_ascii=False)
        
        # Write output
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                if context.verbose:
                    print(f"[*] JSON output saved to {filename}")
            except Exception as e:
                print(f"[!] Error writing to {filename}: {e}")
        else:
            # Print to stdout
            print(json_output)


