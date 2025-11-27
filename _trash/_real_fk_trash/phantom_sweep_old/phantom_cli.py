"""
PhantomSweep CLI - New CLI interface with plugin-based architecture
"""
import argparse
import ipaddress
import sys
import os

from typing import List
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.phantom_plugin_manager import PhantomPluginManager
from phantom_sweep.core.port_parser import parse_port_spec, parse_exclude_ports

try:
    import pyfiglet
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Error: Missing required packages. Install with:")
    print("pip install pyfiglet colorama")
    sys.exit(1)

class PhantomCLI:
    """PhantomSweep CLI Interface"""

    VERSION = "2.0.0"
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog="phantom",
            description="PhantomSweep - Advanced network scanning tool",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.args = None
        self.plugin_manager = PhantomPluginManager()
    
    def print_banner(self):
        """Display ASCII banner"""
        try:
            ascii_banner = pyfiglet.figlet_format("PhantomSweep", font="slant")
            print(Fore.CYAN + ascii_banner + Style.RESET_ALL)
        except:
            print("=" * 60)
            print(" " * 15 + "PhantomSweep")
            print("=" * 60)
        
        print(f"{Fore.YELLOW}A fast, lightweight, scalable and smart network scanning tool{Style.RESET_ALL}")
        print(f"Version: {self.VERSION}\n")
        
        # print(Fore.RED + "[!] Legal Disclaimer:" + Style.RESET_ALL)
        # print("    Usage of PhantomSweep for attacking targets without prior mutual consent is illegal.")
        # print("    It is the end user's responsibility to comply with all applicable laws.")
        # print("    Developers assume no liability for misuse or damage caused by this tool.\n")
    
    def build_parser(self):
        """Build argument parser with all options"""
        parser = self.parser
        
        # Help and Version
        parser.add_argument(
            "-v", "--version",
            action="version",
            version=f"PhantomSweep {self.VERSION}",
            help="Show program's version number"
        )
        
        # Target Specification
        target_group = parser.add_argument_group('Target Specification')
        target_group.add_argument(
            "--host",
            nargs="+",
            metavar="TARGET",
            help="IP address(es), range, CIDR block, or domain (e.g., 192.168.1.1, 192.168.1.0/24)"
        )
        target_group.add_argument(
            "--input-file",
            metavar="FILE",
            help="Read targets from file (one per line)"
        )
        target_group.add_argument(
            "--exclude-ip",
            nargs="+",
            metavar="TARGET",
            help="Exclude IP(s) or range(s) from scan"
        )
        
        # Port Specification
        port_group = parser.add_argument_group('Port Specification')
        port_group.add_argument(
            "--port",
            metavar="PORTS",
            default="top_100",
            help="Port specification: top_100 (default), top_1000, all, 80,443, 1-1000, or combinations"
        )
        port_group.add_argument(
            "--exclude-port",
            metavar="PORTS",
            help="Exclude ports from scan (e.g., 22,23 or 1-100)"
        )
        
        # Scan Pipeline
        scan_group = parser.add_argument_group('Scan Pipeline')
        scan_group.add_argument(
            "--ping-tech",
            choices=["icmp", "tcp", "arp", "none"],
            default="icmp",
            help="Host discovery technique (default: icmp)"
        )
        scan_group.add_argument(
            "--scan-tech",
            choices=["connect", "stealth", "udp"],
            default="connect",
            help="Port scanning technique (default: connect)"
        )
        scan_group.add_argument(
            "--service-detection-mode",
            choices=["ai", "normal", "off"],
            default="ai",
            help="Service detection mode (default: ai)"
        )
        scan_group.add_argument(
            "--os-fingerprinting-mode",
            choices=["ai", "normal", "off"],
            default="ai",
            help="OS fingerprinting mode (default: ai)"
        )
        
        # Performance and Evasion
        perf_group = parser.add_argument_group('Performance and Evasion')
        perf_group.add_argument(
            "--rate",
            choices=["stealthy", "balanced", "fast", "insane"],
            default="balanced",
            help="Scan rate (default: balanced)"
        )
        perf_group.add_argument(
            "--threads",
            type=int,
            default=10,
            help="Number of concurrent threads (default: 10)"
        )
        perf_group.add_argument(
            "--timeout",
            type=float,
            default=1.0,
            help="Timeout in seconds (default: 1.0)"
        )
        perf_group.add_argument(
            "--evasion",
            nargs="+",
            choices=["randomize", "fragment", "decoy", "spoof"],
            help="Evasion techniques (can combine multiple)"
        )
        
        # Extension & Output
        ext_group = parser.add_argument_group('Extension & Output')
        ext_group.add_argument(
            "--script",
            nargs="+",
            metavar="SCRIPT",
            help="Run one or more scripts (e.g., ftp_anon http_risky)"
        )
        ext_group.add_argument(
            "--output",
            default="text",
            help="Output format: text (default), json, xml, csv, or comma-separated"
        )
        ext_group.add_argument(
            "--output-file",
            metavar="FILE",
            help="Output file name (if not specified, results printed to console)"
        )
        
        # Plugin Management
        plugin_group = parser.add_argument_group('Plugin Management')
        plugin_group.add_argument(
            "--list-plugins",
            action="store_true",
            help="List all available plugins"
        )
        plugin_group.add_argument(
            "--plugin-info",
            metavar="PLUGIN",
            help="Show information about a specific plugin"
        )
        plugin_group.add_argument(
            "--list-scripts",
            action="store_true",
            help="List all available scripts"
        )
        plugin_group.add_argument(
            "--script-info",
            metavar="SCRIPT",
            help="Show information about a specific script"
        )
        
        # Misc
        misc_group = parser.add_argument_group('Miscellaneous')
        misc_group.add_argument(
            "--verbose",
            action="store_true",
            help="Increase verbosity"
        )
        misc_group.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug mode"
        )
    
    def validate_args(self, args):
        """Validate parsed arguments"""
        # Check that either --host or --input-file is provided
        if not args.host and not args.input_file and not args.list_plugins and not args.list_scripts and not args.plugin_info and not args.script_info:
            print(f"{Fore.RED}[!] Error: No targets specified. Provide --host or --input-file{Style.RESET_ALL}")
            return False
        
        # Validate input file exists if provided
        if args.input_file and not os.path.isfile(args.input_file):
            print(f"{Fore.RED}[!] Error: Input file '{args.input_file}' does not exist{Style.RESET_ALL}")
            return False
        
        # Validate thread count
        if args.threads <= 0:
            print(f"{Fore.RED}[!] Error: Thread count must be positive{Style.RESET_ALL}")
            return False
        
        # Validate timeout
        if args.timeout <= 0:
            print(f"{Fore.RED}[!] Error: Timeout must be positive{Style.RESET_ALL}")
            return False
        
        return True
    
    def build_targets(self, targets: List[str]) -> List[str]:
        """Build target list from various formats"""
        result = []
        for target in targets:
            if '/' in target:
                # CIDR
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    result.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    result.append(target)
            elif '-' in target and target.count('.') == 3:
                # IP range like 192.168.1.1-100
                parts = target.split('.')
                if '-' in parts[-1]:
                    base = '.'.join(parts[:-1])
                    start, end = map(int, parts[-1].split('-'))
                    for i in range(start, end + 1):
                        result.append(f"{base}.{i}")
                else:
                    result.append(target)
            else:
                result.append(target)
        return result
    
    def build_context(self, args) -> ScanContext:
        """Convert CLI args to ScanContext"""
        # Load targets
        targets = args.host or []
        if args.input_file:
            try:
                with open(args.input_file, 'r') as f:
                    targets.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading input file: {e}{Style.RESET_ALL}")
                sys.exit(1)
        
        targets = list(set([t for t in targets if t]))
        targets = self.build_targets(targets)
        
        # Parse port specification
        port_spec = args.port
        if port_spec == "all":
            scan_all_ports = True
            fast_scan = False
            ports = None
        elif port_spec in ["top_100", "top_1000"]:
            scan_all_ports = False
            fast_scan = True
            ports = None
        else:
            scan_all_ports = False
            fast_scan = False
            ports = port_spec
        
        # Map scan_tech to scan_type
        scan_type_map = {
            "connect": "tcp_connect",
            "stealth": "syn_scan",
            "udp": "udp_scan"
        }
        scan_type = scan_type_map.get(args.scan_tech, "tcp_connect")
        
        # Map service_detection_mode
        service_version = args.service_detection_mode != "off"
        
        # Map os_fingerprinting_mode
        os_detection = args.os_fingerprinting_mode != "off"
        
        # Map rate to timing (simplified mapping)
        rate_to_timing = {
            "stealthy": 0,
            "balanced": 3,
            "fast": 4,
            "insane": 5
        }
        timing = rate_to_timing.get(args.rate, 3)
        
        return ScanContext(
            targets=targets,
            scan_type=scan_type,
            ports=ports,
            scan_all_ports=scan_all_ports,
            fast_scan=fast_scan,
            service_version=service_version,
            os_detection=os_detection,
            timing=timing,
            threads=args.threads,
            timeout=args.timeout,
            output_normal=None,
            output_xml=None,
            output_json=None,
            output_html=None,
            show_open_only=False,
            verbose=args.verbose,
            debug=args.debug,
            exclude=args.exclude_ip,
            input_list=args.input_file,
            ping_tech=args.ping_tech,
            scan_tech=args.scan_tech,
            service_detection_mode=args.service_detection_mode,
            os_fingerprinting_mode=args.os_fingerprinting_mode,
            rate=args.rate,
            exclude_ports=args.exclude_port,
            output=args.output,
            output_file=args.output_file,
            scripts=args.script,
            evasion=args.evasion
        )
    
    def list_plugins(self):
        """List all available plugins"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}AVAILABLE PLUGINS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        for category, plugins in self.plugin_manager.list_plugins().items():
            if not plugins:
                continue
            print(f"{Fore.YELLOW}{category.upper()}:{Style.RESET_ALL}")
            for name, plugin in plugins.items():
                metadata = plugin.metadata()
                print(f"  {Fore.GREEN}{name:<20}{Style.RESET_ALL} - {metadata.get('display_name', name)}")
                if metadata.get('description'):
                    print(f"    {metadata['description']}")
            print()
    
    def show_plugin_info(self, plugin_name: str):
        """Show information about a specific plugin"""
        # Try to find plugin in any category
        found = False
        for category in ["ping_tech", "scan_tech", "analyze", "scripts", "output"]:
            plugin = self.plugin_manager.get_plugin(category, plugin_name)
            if plugin:
                found = True
                metadata = plugin.metadata()
                print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}PLUGIN INFORMATION{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
                print(f"{Fore.YELLOW}Name:{Style.RESET_ALL} {metadata.get('name', 'N/A')}")
                print(f"{Fore.YELLOW}Display Name:{Style.RESET_ALL} {metadata.get('display_name', 'N/A')}")
                print(f"{Fore.YELLOW}Category:{Style.RESET_ALL} {category}")
                print(f"{Fore.YELLOW}Description:{Style.RESET_ALL} {metadata.get('description', 'N/A')}")
                print(f"{Fore.YELLOW}Requires Root:{Style.RESET_ALL} {metadata.get('requires_root', False)}")
                if metadata.get('aliases'):
                    print(f"{Fore.YELLOW}Aliases:{Style.RESET_ALL} {', '.join(metadata['aliases'])}")
                break
        
        if not found:
            print(f"{Fore.RED}[!] Plugin '{plugin_name}' not found{Style.RESET_ALL}")
            sys.exit(1)
    
    def run_scan(self, context: ScanContext, args):
        """Run the scan pipeline"""
        # Run ping/host discovery
        ping_plugin = self.plugin_manager.get_plugin("ping_tech", context.ping_tech)
        if ping_plugin:
            ping_plugin.run(context, args)
        
        # Run port scan
        scan_plugin = self.plugin_manager.get_plugin("scan_tech", context.scan_tech)
        if scan_plugin:
            scan_plugin.run(context, args)
        
        # Run analysis
        if context.service_detection_mode != "off":
            service_plugin = self.plugin_manager.get_plugin("analyze", "service_detection")
            if service_plugin:
                service_plugin.run(context, args)
        
        if context.os_fingerprinting_mode != "off":
            os_plugin = self.plugin_manager.get_plugin("analyze", "os_fingerprinting")
            if os_plugin:
                os_plugin.run(context, args)
        
        # Run scripts if specified
        if context.scripts:
            for script_name in context.scripts:
                script_plugin = self.plugin_manager.get_plugin("scripts", script_name)
                if script_plugin:
                    script_plugin.run(context, args)
        
        # Generate output
        output_formats = context.output.split(',')
        for fmt in output_formats:
            fmt = fmt.strip()
            output_plugin = self.plugin_manager.get_plugin("output", fmt)
            if output_plugin:
                output_plugin.run(context, args)
    
    def print_results(self, context: ScanContext):
        """Print results to console if no output file specified"""
        if context.output_file:
            return  # Results are saved to file
        
        print(f"\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN RESULTS{Style.RESET_ALL}\n")
        
        tcp_results = context.get_data("scan_results") or {}
        udp_results = context.get_data("scan_results_udp") or {}
        all_targets = set(tcp_results.keys()) | set(udp_results.keys())
        
        if not all_targets:
            print(f"{Fore.YELLOW}No targets found.{Style.RESET_ALL}")
            return
        
        for target in sorted(all_targets):
            print(f"{Fore.CYAN}Target: {target}{Style.RESET_ALL}")
            
            if target in tcp_results:
                ports = tcp_results[target].get("ports", {})
                if ports:
                    print(f"  TCP Ports:")
                    for port, details in sorted(ports.items()):
                        state = details.get("state", "unknown")
                        service = details.get("service", "")
                        print(f"    {port}: {state}" + (f" ({service})" if service else ""))
            
            if target in udp_results:
                ports = udp_results[target].get("ports", {})
                if ports:
                    print(f"  UDP Ports:")
                    for port, details in sorted(ports.items()):
                        state = details.get("state", "unknown")
                        service = details.get("service", "")
                        print(f"    {port}: {state}" + (f" ({service})" if service else ""))
            print()
        
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
    
    def run(self):
        """Main execution method"""
        self.build_parser()
        self.args = self.parser.parse_args()
        
        # Handle plugin listing
        if self.args.list_plugins:
            self.list_plugins()
            return 0
        
        if self.args.plugin_info:
            self.show_plugin_info(self.args.plugin_info)
            return 0
        
        if self.args.list_scripts:
            scripts = self.plugin_manager.get_plugins_by_category("scripts")
            print(f"\n{Fore.CYAN}Available Scripts:{Style.RESET_ALL}")
            for name, plugin in scripts.items():
                metadata = plugin.metadata()
                print(f"  {Fore.GREEN}{name}{Style.RESET_ALL} - {metadata.get('display_name', name)}")
            return 0
        
        if self.args.script_info:
            self.show_plugin_info(self.args.script_info)
            return 0
        
        # Show banner
        self.print_banner()
        
        # Validate arguments
        if not self.validate_args(self.args):
            return 1
        
        # Build context
        context = self.build_context(self.args)
        
        # Display configuration
        if context.verbose or context.debug:
            print(f"\n{Fore.CYAN}Configuration:{Style.RESET_ALL}")
            print(f"  Targets: {len(context.targets)} target(s)")
            print(f"  Ping Tech: {context.ping_tech}")
            print(f"  Scan Tech: {context.scan_tech}")
            port_desc = "all" if context.scan_all_ports else ("top_100" if context.fast_scan else (context.ports or "default"))
            print(f"  Ports: {port_desc}")
            print(f"  Rate: {context.rate}")
            print(f"  Threads: {context.threads}")
            print()
        
        # Run scan
        try:
            self.run_scan(context, self.args)
            self.print_results(context)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            return 130
        except Exception as e:
            print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
            if context.debug:
                import traceback
                traceback.print_exc()
            return 1
        
        return 0


def main():
    """Entry point"""
    cli = PhantomCLI()
    try:
        sys.exit(cli.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()

