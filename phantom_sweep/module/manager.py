"""
Manager - Orchestrates the scan pipeline
"""
from datetime import datetime
from typing import Optional

from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module.analyzer import SERVICE_DETECTION_ANALYZERS, OS_FINGERPRINTING_ANALYZERS

import importlib
import pkgutil
import inspect
from phantom_sweep.module._base import ScannerBase, ScriptingBase, ReporterBase
import phantom_sweep.module.scanner.host_discovery as host_discovery_module
import phantom_sweep.module.scanner.port_scanning as port_scanning_module
import phantom_sweep.module.scripting as scripting_module
import phantom_sweep.module.reporter as reporter_module

class Manager:

    def __init__(self):
        self.host_discovery_plugins = {}
        self.port_scan_plugins = {}
        self.scripting_plugins = {}
        self.reporter_plugins = {}
        self.result: Optional[ScanResult] = None
    
    # ================= Plugin Loading ================= #

    def load_plugins(self):
        """Quét thư mục module/scanner, module/scripting, module/reporter và nạp tất cả các class kế thừa ScannerBase, ScriptingBase, ReporterBase"""
        
        # Load host discovery scanners
        for _, module_name, _ in pkgutil.iter_modules(host_discovery_module.__path__):
            module = importlib.import_module(f"phantom_sweep.module.scanner.host_discovery.{module_name}")
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, ScannerBase) and obj is not ScannerBase:
                    self.host_discovery_plugins[name] = obj
        
        # Load port scanning scanners
        for _, module_name, _ in pkgutil.iter_modules(port_scanning_module.__path__):
            module = importlib.import_module(f"phantom_sweep.module.scanner.port_scanning.{module_name}")
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, ScannerBase) and obj is not ScannerBase:
                    self.port_scan_plugins[name] = obj
        
        # Load scripting modules
        for _, module_name, _ in pkgutil.iter_modules(scripting_module.__path__):
            module = importlib.import_module(f"phantom_sweep.module.scripting.{module_name}")
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, ScriptingBase) and obj is not ScriptingBase:
                    self.scripting_plugins[name] = obj
        
        # Load reporter modules
        for _, module_name, _ in pkgutil.iter_modules(reporter_module.__path__):
            module = importlib.import_module(f"phantom_sweep.module.reporter.{module_name}")
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, ReporterBase) and obj is not ReporterBase:
                    self.reporter_plugins[name] = obj
        
    def get_discovery_choices(self):
        """Get available host discovery choices using plugin name property"""
        choices = []
        if getattr(self, "host_discovery_plugins", None):
            for plugin_class in self.host_discovery_plugins.values():
                instance = plugin_class()
                choices.append(instance.name)
        choices = sorted(set(choices))  # Remove duplicates and sort
        if "none" not in choices:
            choices.append("none")
        return choices

    def get_scanning_choices(self):
        """Get available port scanning choices using plugin name property"""
        choices = []
        if getattr(self, "port_scan_plugins", None):
            for plugin_class in self.port_scan_plugins.values():
                instance = plugin_class()
                choices.append(instance.name)
        choices = sorted(set(choices))  # Remove duplicates and sort
        if "none" not in choices:
            choices.append("none")
        return choices
    
    def get_reporter_choices(self):
        """Get available reporter output format choices"""
        choices = []
        if getattr(self, "reporter_plugins", None):
            for plugin_class in self.reporter_plugins.values():
                instance = plugin_class()
                choices.append(instance.name)
        choices = sorted(set(choices))  # Remove duplicates and sort
        if "none" not in choices:
            choices.append("none")
        return choices
    
    def get_script_choices(self):
        """Get available script choices"""
        choices = []
        if getattr(self, "scripting_plugins", None):
            for plugin_class in self.scripting_plugins.values():
                instance = plugin_class()
                choices.append(instance.name)
        choices = sorted(set(choices))
        if "all" not in choices:
            choices.append("all")  # Allow running all scripts
        return choices

    def generate_help_text(self, plugin_dict):
        text = ""
        for cls in plugin_dict.values():
            instance = cls()
            text += f"\n            - {instance.name}: {instance.description}"
        return text
    
    # ================= Plugin Utilities ================= #

    def get_discovery_plugin_by_name(self, plugin_name):
        """Get host discovery plugin class by its name property"""
        if plugin_name == "none":
            return None
        
        for plugin_class in self.host_discovery_plugins.values():
            instance = plugin_class()
            if instance.name == plugin_name:
                return plugin_class
        
        return None
    
    def get_scanning_plugin_by_name(self, plugin_name):
        """Get port scanning plugin class by its name property"""
        if plugin_name == "none":
            return None
        
        for plugin_class in self.port_scan_plugins.values():
            instance = plugin_class()
            if instance.name == plugin_name:
                return plugin_class
        
        return None

    def get_reporter_plugin_by_name(self, plugin_name):
        """Get reporter plugin class by its name property"""
        if plugin_name == "none":
            return None
        
        for plugin_class in self.reporter_plugins.values():
            instance = plugin_class()
            if instance.name == plugin_name:
                return plugin_class
        
        return None
    
    def get_script_plugin_by_name(self, plugin_name):
        """Get scripting plugin class by its name property"""
        for plugin_class in self.scripting_plugins.values():
            instance = plugin_class()
            if instance.name == plugin_name:
                return plugin_class
        
        return None

    # ================= Scan Pipeline ================= #

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
            
            # Step 2: Port Scanning (if enabled)
            if context.pipeline.scan_tech != "none":
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
        
        # Get the appropriate scanner using helper method
        scanner_class = self.get_discovery_plugin_by_name(ping_tech)
        if not scanner_class:
            if context.verbose:
                print(f"[!] Unknown ping tech: {ping_tech}, assuming all hosts are up")
            for host in context.targets.host:
                self.result.add_host(host, state="up")
            return
        
        # Create and run scanner
        scanner_instance = scanner_class()
        try:
            if context.verbose:
                print(f"[*] Running host discovery with {ping_tech}...")
            scanner_instance.scan(context, self.result)
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
        
        # Get the appropriate scanner using helper method
        scanner_class = self.get_scanning_plugin_by_name(scan_tech)
        
        if not scanner_class:
            if context.verbose:
                print(f"[!] Unknown scan tech: {scan_tech}, skipping port scanning")
            return
        
        # Create and run scanner
        scanner_instance = scanner_class()
        try:
            if context.verbose:
                print(f"[*] Running port scanning with {scan_tech}...")
            scanner_instance.scan(context, self.result)
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
            script_names = list(self.scripting_plugins.keys())
        
        for script_name in script_names:
            # Find the script plugin by name
            script_class = None
            for plugin_class in self.scripting_plugins.values():
                instance = plugin_class()
                if instance.name == script_name:
                    script_class = plugin_class
                    break
            
            if not script_class:
                if context.verbose:
                    print(f"[!] Unknown script: {script_name}, skipping")
                continue
            
            # Create and run script
            try:
                script = script_class()
                if context.verbose:
                    print(f"[*] Running script: {script_name}...")
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
        print("Generating Output...")
        output_formats = context.output.output_format.split(',')
        base_filename = context.output.output_filename
        
        for fmt in output_formats:
            fmt = fmt.strip().lower()
            
            # Skip "none" format
            if fmt == "none":
                continue
            
            # Find reporter by name
            reporter_class = None
            for plugin_class in self.reporter_plugins.values():
                instance = plugin_class()
                if instance.name == fmt:
                    reporter_class = plugin_class
                    break
            
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
                filename = None  # Print to console (reporter will handle this)
            
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

        print("Output Generation Completed.")

