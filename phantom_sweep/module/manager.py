"""
Manager - Orchestrates the scan pipeline
"""
from datetime import datetime
from typing import Optional
import os

from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult, HostInfo, PortInfo
from phantom_sweep.module.scanner import HOST_DISCOVERY_SCANNERS, PORT_SCANNING_SCANNERS
from phantom_sweep.module.analyzer import SERVICE_DETECTION_ANALYZERS, OS_FINGERPRINTING_ANALYZERS
from phantom_sweep.module.scripting import SCRIPTS
from phantom_sweep.module.reporter import REPORTERS


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
            if context.pipeline.script:
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
        ping_tech = context.pipeline.ping_tech
        
        # Get the appropriate scanner
        scanner_class = HOST_DISCOVERY_SCANNERS.get(ping_tech)
        if not scanner_class:
            if context.verbose:
                print(f"[!] Unknown ping tech: {ping_tech}, assuming all hosts are up")
            # Fallback: assume all hosts are up
            for host in context.targets.host:
                self.result.add_host(host, state="up")
            return
        
        # Check root requirement
        if scanner_class().requires_root():
            if context.verbose:
                print(f"[!] {ping_tech} discovery requires root privileges. Assuming all hosts are up.")
            for host in context.targets.host:
                self.result.add_host(host, state="up")
            return
        
        # Create and run scanner
        scanner = scanner_class()
        try:
            scanner.scan(context, self.result)
            if context.verbose:
                up_count = sum(1 for h in self.result.hosts.values() if h.state == "up")
                print(f"[*] Host discovery completed: {up_count}/{len(context.targets.host)} hosts up")
        except Exception as e:
            if context.debug:
                import traceback
                traceback.print_exc()
            if context.verbose:
                print(f"[!] Error during host discovery: {e}")
            # Fallback: assume all hosts are up
            for host in context.targets.host:
                if host not in self.result.hosts:
                    self.result.add_host(host, state="up")
    
    def _run_port_scanning(self, context: ScanContext):
        """Run port scanning phase"""
        scan_tech = context.pipeline.scan_tech
        print(f"[DEBUG] {scan_tech}")
        # Map scan_tech to scanner name
        tech_map = {
            "connect": "connect",
            "stealth": "stealth",
            "udp": "udp"
        }
        
        scanner_name = tech_map.get(scan_tech, "connect")
        print(f"[DEBUG] IN RA SCANNER NAME {scanner_name}")
        scanner_class = PORT_SCANNING_SCANNERS.get(scanner_name)
        print(f"[DEBUG] IN RA SCAN CLASS {scanner_class}")
        
        if not scanner_class:
            if context.verbose:
                print(f"[!] Unknown scan tech: {scan_tech}, using TCP Connect scan")
            scanner_class = PORT_SCANNING_SCANNERS.get("connect")
        
        # # Check root requirement
        # if scanner_class().requires_root() :
        #     if context.verbose:
        #         print(f"[!] {scan_tech} scan requires root privileges. Falling back to TCP Connect scan.")
        #     scanner_class = PORT_SCANNING_SCANNERS.get("connect")
        
        # Create and run scanner
        scanner = scanner_class()
        print(f"[DEBUG] IN RA SCANNER {scanner}")
        try:
            scanner.scan(context, self.result)
            if context.verbose:
                open_ports = sum(
                    len([p for p in h.tcp_ports.values() if p.state == "open"]) +
                    len([p for p in h.udp_ports.values() if p.state == "open"])
                    for h in self.result.hosts.values()
                )
                print(f"[*] Port scanning completed: {open_ports} open ports found")
        except Exception as e:
            if context.debug:
                import traceback
                traceback.print_exc()
            if context.verbose:
                print(f"[!] Error during port scanning: {e}")
    
    def _run_service_detection(self, context: ScanContext):
        """Run service detection phase"""
        mode = context.pipeline.service_detection_mode
        
        # Get the appropriate analyzer
        analyzer_class = SERVICE_DETECTION_ANALYZERS.get(mode)
        if not analyzer_class:
            if context.verbose:
                print(f"[!] Unknown service detection mode: {mode}, skipping service detection")
            return
        
        # Create and run analyzer
        analyzer = analyzer_class()
        try:
            analyzer.analyze(context, self.result)
            if context.verbose:
                print(f"[*] Service detection completed (mode: {mode})")
        except Exception as e:
            if context.debug:
                import traceback
                traceback.print_exc()
            if context.verbose:
                print(f"[!] Error during service detection: {e}")
    
    def _run_os_fingerprinting(self, context: ScanContext):
        """Run OS fingerprinting phase"""
        mode = context.pipeline.os_fingerprinting_mode
        
        # Get the appropriate analyzer
        analyzer_class = OS_FINGERPRINTING_ANALYZERS.get(mode)
        if not analyzer_class:
            if context.verbose:
                print(f"[!] Unknown OS fingerprinting mode: {mode}, skipping OS fingerprinting")
            return
        
        # Create and run analyzer
        analyzer = analyzer_class()
        try:
            analyzer.analyze(context, self.result)
            if context.verbose:
                print(f"[*] OS fingerprinting completed (mode: {mode})")
        except Exception as e:
            if context.debug:
                import traceback
                traceback.print_exc()
            if context.verbose:
                print(f"[!] Error during OS fingerprinting: {e}")
    
    def _run_scripts(self, context: ScanContext):
        """Run extension scripts"""
        script_names = context.pipeline.script
        
        # Handle "all" script option
        if "all" in script_names:
            script_names = list(SCRIPTS.keys())
        
        for script_name in script_names:
            script_class = SCRIPTS.get(script_name)
            if not script_class:
                if context.verbose:
                    print(f"[!] Unknown script: {script_name}, skipping")
                continue
            
            # Create and run script
            script = script_class()
            try:
                script.run(context, self.result)
                if context.verbose:
                    print(f"[*] Script '{script_name}' completed")
            except Exception as e:
                if context.debug:
                    import traceback
                    traceback.print_exc()
                if context.verbose:
                    print(f"[!] Error running script '{script_name}': {e}")
    
    def generate_output(self, context: ScanContext, result: ScanResult) -> None:
        """
        Generate output in specified formats using reporter modules.
        
        Args:
            context: ScanContext containing output configuration
            result: ScanResult containing scan results
        """
        output_formats = context.output.output_format.split(',')
        base_filename = context.output.output_filename
        
        for fmt in output_formats:
            fmt = fmt.strip().lower()
            
            # Skip "none" format
            if fmt == "none":
                continue
            
            # Get the appropriate reporter
            reporter_class = REPORTERS.get(fmt)
            if not reporter_class:
                if context.verbose:
                    print(f"[!] Unknown output format: {fmt}, skipping")
                continue
            
            # Determine filename
            if base_filename:
                # If base filename provided, append extension
                if fmt == "json":
                    filename = f"{base_filename}.json"
                elif fmt == "xml":
                    filename = f"{base_filename}.xml"
                elif fmt == "text":
                    filename = f"{base_filename}.txt"
                elif fmt == "csv":
                    filename = f"{base_filename}.csv"
                else:
                    filename = f"{base_filename}.{fmt}"
            else:
                filename = None  # Print to console
            
            # Create and run reporter
            reporter = reporter_class()
            try:
                reporter.export(context, result, filename)
                if context.verbose and filename:
                    print(f"[*] Output saved to {filename} ({fmt} format)")
            except Exception as e:
                if context.debug:
                    import traceback
                    traceback.print_exc()
                if context.verbose:
                    print(f"[!] Error generating {fmt} output: {e}")

