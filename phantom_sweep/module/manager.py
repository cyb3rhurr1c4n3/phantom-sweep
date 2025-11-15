"""
Manager - Orchestrates the scan pipeline
"""
from datetime import datetime
from typing import Optional

from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult, HostInfo, PortInfo


class Manager:
    """
    Manages the scan pipeline execution.
    Coordinates between different modules (scanner, analyzer, reporter, scripting).
    - scanner: module for Host discovery and Port Scanning
    - analyzer: module for Service & Version Detection and OS Fingerprinting
    - reporter: module for output format (only console, text file, csv file, nmap-xml file, json file)  
    - scripting: module for exploit or other script
    """
    
    def __init__(self):
        self.result: Optional[ScanResult] = None
    
    def run_scan(self, context: ScanContext) -> ScanResult:
        """
        Execute the complete scan pipeline based on the context.
        
        Args:
            context: ScanContext containing scan configuration
            
        Returns:
            ScanResult containing all scan results
        """
        # Initialize result
        self.result = ScanResult()
        self.result.scan_start_time = datetime.now().isoformat()
        
        try:
            # Step 1: Host Discovery (if enabled)
            if context.pipeline.ping_tech != "none":
                self._run_host_discovery(context)
            
            # Step 2: Port Scanning
            self._run_port_scanning(context)
            
            # Step 3: Service Detection (if enabled)
            if context.pipeline.service_detection_mode != "off":
                self._run_service_detection(context)
            
            # Step 4: OS Fingerprinting (if enabled)
            if context.pipeline.os_fingerprinting_mode != "off":
                self._run_os_fingerprinting(context)
            
            # Step 5: Scripts (if specified)
            if context.extensions.script:
                self._run_scripts(context)
            
            # Update statistics
            self.result.update_statistics()
            
        finally:
            self.result.scan_end_time = datetime.now().isoformat()
            if self.result.scan_start_time and self.result.scan_end_time:
                start = datetime.fromisoformat(self.result.scan_start_time)
                end = datetime.fromisoformat(self.result.scan_end_time)
                self.result.scan_duration = (end - start).total_seconds()
        
        return self.result
    
    def _run_host_discovery(self, context: ScanContext):
        """Run host discovery phase"""
        # TODO: Implement host discovery
        # For now, assume all targets are up
        for host in context.targets.host:
            self.result.add_host(host, state="up")
        
        if context.verbose:
            print(f"[*] Host discovery completed: {len(context.targets.host)} hosts")
    
    def _run_port_scanning(self, context: ScanContext):
        """Run port scanning phase"""
        # TODO: Implement port scanning
        # This will be implemented by scanner modules
        if context.verbose:
            print(f"[*] Port scanning phase (tech: {context.pipeline.scan_tech})")
    
    def _run_service_detection(self, context: ScanContext):
        """Run service detection phase"""
        # TODO: Implement service detection
        # This will be implemented by analyzer modules
        if context.verbose:
            print(f"[*] Service detection phase (mode: {context.pipeline.service_detection_mode})")
    
    def _run_os_fingerprinting(self, context: ScanContext):
        """Run OS fingerprinting phase"""
        # TODO: Implement OS fingerprinting
        # This will be implemented by analyzer modules
        if context.verbose:
            print(f"[*] OS fingerprinting phase (mode: {context.pipeline.os_fingerprinting_mode})")
    
    def _run_scripts(self, context: ScanContext):
        """Run extension scripts"""
        # TODO: Implement script execution
        # This will be implemented by scripting modules
        if context.verbose:
            print(f"[*] Running scripts: {', '.join(context.extensions.script)}")

