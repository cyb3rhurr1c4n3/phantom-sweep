"""
PhantomSweep CLI
"""
import argparse
import ipaddress
import sys
import os
from typing import List
from argparse import SUPPRESS

from phantom_sweep.core.scan_context import (
    ScanContext, TargetConfig, PortConfig, PipelineConfig,
    PerformanceAndEvasionConfig, OutputConfig
)
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_targets, parse_exclude_hosts
from phantom_sweep.module.manager import Manager

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

    VERSION = "1.0.0"
    
    # Essential functionfunction
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog="phantom",
            description="PhantomSweep - A fast, lightweight and scalable network security scanner",
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False
        )
        self.args = None
        self.manager = Manager()
    
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
        print(f"Version: {self.VERSION}")
        print("Author : Group 10")
        print("Inspired by Nmap & Masscan\n")
        
        print(Fore.RED + "[!] Legal Disclaimer:" + Style.RESET_ALL)
        print("    Usage of PhantomSweep for attacking targets without prior mutual consent is illegal.")
        print("    It is the end user's responsibility to comply with all applicable laws.")
        print("    Developers assume no liability for misuse or damage caused by this tool.\n")

    def build_parser(self):
        """Build argument parser with all options"""
        parser = self.parser

        # Help and Version
        general_group = parser.add_argument_group(
            ':#################### GENERAL ####################',
            'Some general options'
        )
        general_group.add_argument(
            "--version",
            action="version",
            version=f"PhantomSweep {self.VERSION}",
            help="Show program's version number and exit"
        )
        general_group.add_argument(
            '--help', 
            action='help', 
            help="Show this help message and exit"
        )
        general_group.add_argument(
            "--example",
            action="store_true",
            help="Show detailed examples"
        )
        
        # Target Specification
        target_group = parser.add_argument_group(
            ':#################### TARGET SPECIFICATION ####################',
            'Specify targets to scan. At least one target source is required.'
        )
        target_group.add_argument(
            "host",
            nargs="*",
            metavar="HOST",
            help="""Target host(s) to scan. Can be:
            - Single IP: 192.168.1.1
            - Multiple IPs: 192.168.1.1 192.168.1.2
            - IP range: 192.168.1.1-100 or 192.168.1.1-192.168.1.100
            - CIDR block: 192.168.1.0/24
            - Domain name: scanme.nmap.org"""
        )
        target_group.add_argument(
            "--host-list",
            metavar="FILENAME",
            dest="host_list",
            help="Read targets from file (one per line). Required if HOST is not specified."
        )
        target_group.add_argument(
            "--exclude-host",
            nargs="+",
            metavar="IP",
            dest="exclude_host",
            help="Exclude IP(s) from scan. Same format as --host."
        )
        
        # Port Specification
        port_group = parser.add_argument_group(
            ':#################### PORT SPECIFICATION ####################',
            'Specify which ports to scan.'
        )
        port_group.add_argument(
            "--port",
            metavar="PORT",
            dest="port",
            default="top_100",
            help="""Port(s) to scan (default: top_100). Can be: 
            - top_100: Scan 100 most common ports
            - top_1000: Scan 1000 most common ports
            - all: Scan all 65535 ports
            - Specific: 80,443,8080
            - Range: 1-1000
            - Combined: 80,443,1000-2000"""
        )
        port_group.add_argument(
            "--port-list",
            metavar="FILENAME",
            dest="port_list",
            help="Read port from file (one per line)."
        )
        port_group.add_argument(
            "--exclude-port",
            nargs="+",
            metavar="PORT",
            dest="exclude_port",
            help="Exclude port(s) from scan. Same format as --port."
        )
        
        # Scan Pipeline
        scan_group = parser.add_argument_group(
            ':#################### SCAN PINELINE ####################',
            'Configure which technique to use, which step is enable or disable, bla bla'
        )
        scan_group.add_argument(
            "--ping-tech",
            choices=["icmp", "tcp", "arp", "none"],
            default="icmp",
            dest="ping_tech",
            help="""Host discovery technique (default: icmp):
            - icmp: ICMP echo request (ping)
            - tcp: TCP SYN/ACK ping
            - arp: ARP discovery (local network only)
            - none: Skip discovery, assume all hosts are up"""
        )
        scan_group.add_argument(
            "--scan-tech",
            choices=["connect", "stealth", "udp"],
            default="connect",
            dest="scan_tech",
            help="""Port scanning technique (default: connect):
            - connect: TCP Connect scan (no root required)
            - stealth: TCP SYN scan (requires root, faster, stealthier)
            - udp: UDP scan"""
        )
        scan_group.add_argument(
            "--service-detection-mode",
            choices=["ai", "normal", "off"],
            default="off",
            dest="service_detection_mode",
            help="""Service detection mode (default: off):
            - ai: AI-powered service and version detection
            - normal: Banner-based detection
            - off: Disable service detection"""
        )
        scan_group.add_argument(
            "--os-fingerprinting-mode",
            choices=["ai", "normal", "off"],
            default="off",
            dest="os_fingerprinting_mode",
            help="""OS fingerprinting mode (default: off):
            - ai: AI-powered OS detection
            - normal: TTL/Window size-based detection
            - off: Disable OS fingerprinting"""
        )
        scan_group.add_argument(
            "--script",
            nargs="+",
            metavar="SCRIPT",
            dest="script",
            help="Run one or more extension scripts (e.g., ftp_anon http_risky ssl_check)"
        )
        # Performance and Evasion
        perf_group = parser.add_argument_group(
            ':#################### PERFORMANCE AND EVASION ####################',
            'Control scan speed and evasion techniques.'
        )
        perf_group.add_argument(
            "--rate",
            choices=["stealthy", "balanced", "fast", "insane"],
            default="balanced",
            dest="rate",
            help="""Scan rate/timing template (default: balanced):
            - stealthy: Slow, AI-adaptive timing (evade IDS/IPS)
            - balanced: Balanced speed and accuracy (Nmap T3-like)
            - fast: Fast scan (Nmap T4-like)
            - insane: Maximum speed (Masscan-like)"""
        )
        perf_group.add_argument(
            "--thread",
            type=int,
            default=10,
            dest="thread",
            metavar="NUM",
            help="Number of concurrent thread/workers (default: 10). Higher = faster but more resource usage."
        )
        perf_group.add_argument(
            "--timeout",
            type=float,
            default=5.0,
            dest="timeout",
            metavar="SECONDS",
            help="Timeout in seconds for each probe (default: 5.0). AI may auto-adjust if --rate stealthy."
        )
        perf_group.add_argument(
    "--evasion-mode",
        nargs="+",
        choices=["randomize", "fragment", "decoy", "spoof", "ai"],  # Add "ai" option
        default=[],  # Empty list by default
        dest="evasion_mode",
        metavar="TECHNIQUE",
        help="""Evasion techniques (can combine multiple):
        - randomize: Randomize host and port order
        - fragment: Fragment packets
        - decoy: Use decoy IPs
        - spoof: Spoof source IP
        - ai: AI-powered adaptive evasion (experimental)"""
    )
        
        # Extension & Output
        ext_group = parser.add_argument_group(
            ':#################### OUTPUT FORMAT ####################',
            'Specify how your output should be format.'
        )
        ext_group.add_argument(
            "--output",
            default="none",
            dest="output_format",
            help="""Export to file format (default: none):
            - none: only print to screen
            - text: Human-readable text format
            - json: JSON format (machine-readable)
            - xml: XML format (Nmap-compatible)
            - csv: CSV format
            - Multiple: json,xml (comma-separated)
            
            """
        )
        ext_group.add_argument(
            "--output-file",
            metavar="FILENAME",
            dest="output_filename",
            help="Save output to file. If not specified, results are printed to console."
        )
        
        # Misc
        misc_group = parser.add_argument_group(':#################### MISCELLANEOUS ####################')
        misc_group.add_argument(
            "--verbose",
            action="store_true",
            dest="verbose",
            help="Increase verbosity level (show detailed progress and information)"
        )
        misc_group.add_argument(
            "--debug",
            action="store_true",
            dest="debug",
            help="Enable debug mode (show detailed error messages and stack traces)"
        )
    
    def validate_args(self, args):
        """Validate parsed arguments"""
        
        # Handle --example flag
        if args.example:
            self.print_examples()
            return False
        
        # Check that either --host or --host-list is provided
        if not args.host and not args.host_list:
            print(f"{Fore.RED}[!] Error: No targets specified. Provide HOST or --host-list{Style.RESET_ALL}")
            self.parser.print_help()
            return False
        
        # Validate input file exists if provided
        if args.host_list and not os.path.isfile(args.host_list):
            print(f"{Fore.RED}[!] Error: Input file '{args.host_list}' does not exist{Style.RESET_ALL}")
            return False
        
        # Validate thread count
        if args.thread <= 0:
            print(f"{Fore.RED}[!] Error: Thread count must be positive{Style.RESET_ALL}")
            return False
        
        # Validate timeout
        if args.timeout <= 0:
            print(f"{Fore.RED}[!] Error: Timeout must be positive{Style.RESET_ALL}")
            return False
        
        return True
    
    def build_context(self, args) -> ScanContext:
        """Convert CLI args to ScanContext with clean, structured configuration"""
        # Build target configuration
        hosts = list(args.host) if args.host else []
        if args.host_list:
            try:
                with open(args.host_list, 'r') as f:
                    hosts.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading input file: {e}{Style.RESET_ALL}")
                sys.exit(1)
        
        # Remove duplicates and expand targets (CIDR, ranges, etc.)
        hosts = list(set([h for h in hosts if h]))
        hosts = parse_targets(hosts)
        
        # Apply exclude_host if specified
        if args.exclude_host:
            exclude_host_list = list(args.exclude_host)
            hosts = parse_exclude_hosts(exclude_host_list, hosts)
        
        target_config = TargetConfig(
            host=hosts,
            host_list=args.host_list,
            exclude_host=list(args.exclude_host) if args.exclude_host else []
        )
        
        # Build port configuration
        # exclude_port can be a list from CLI (nargs="+")
        exclude_port_list = list(args.exclude_port) if args.exclude_port else None
        port_config = PortConfig(
            port=args.port,
            port_list=args.port_list,
            exclude_port=exclude_port_list
        )
        
        # Build pipeline configuration
        pipeline_config = PipelineConfig(
            ping_tech=args.ping_tech,
            scan_tech=args.scan_tech,
            service_detection_mode=args.service_detection_mode,
            os_fingerprinting_mode=args.os_fingerprinting_mode,
            script=list(args.script) if args.script else []
        )
        
        # Build performance configuration
        # Handle evasion_mode: if default "none" is set, treat as empty list
        evasion_mode = []
        if hasattr(args, 'evasion_mode') and args.evasion_mode:
        # args.evasion_mode is already a list from nargs="+"
            evasion_mode = args.evasion_mode if isinstance(args.evasion_mode, list) else [args.evasion_mode]
    
        performance_config = PerformanceAndEvasionConfig(
        rate=args.rate,
        thread=args.thread,
        timeout=args.timeout,
        evasion_mode=evasion_mode  # Now properly ['ai'] or ['randomize', 'ai']
        )
        
        # Build output configuration
        output_config = OutputConfig(
            output_format=args.output_format,
            output_filename=args.output_filename
        )
        
        # Create and return ScanContext
        context= ScanContext(
            targets=target_config,
            ports=port_config,
            pipeline=pipeline_config,
            performance=performance_config,
            output=output_config,
            verbose=args.verbose,
            debug=args.debug
        )
        if args.debug:
            print(f"[DEBUG] Evasion mode: {evasion_mode}")
        return context

    def print_examples(self):
        """Show detailed usage examples"""
        examples = f"""
{Fore.CYAN}{'='*70}{Style.RESET_ALL}
{Fore.CYAN}PHANTOMSWEEP USAGE EXAMPLES{Style.RESET_ALL}
{Fore.CYAN}{'='*70}{Style.RESET_ALL}

{Fore.YELLOW}1. Default scan (uses default options: top_100 ports, icmp ping, connect scan){Style.RESET_ALL}
   python phantom.py 192.168.1.1

{Fore.YELLOW}2. Custom network scan with specific ports and output format{Style.RESET_ALL}
   python phantom.py 192.168.1.0/24 --port 80,443 --output json --output-file results.json

{Fore.YELLOW}3. Stealth scan with AI evasion{Style.RESET_ALL}
   python phantom.py 192.168.1.0/24 --ping-tech none --scan-tech stealth --rate stealthy --evasion-mode randomize

{Fore.YELLOW}4. Full scan with all scripts and multiple output formats{Style.RESET_ALL}
   python phantom.py 192.168.1.1 --port all --script all --output json,xml

{Fore.YELLOW}5. UDP scan on specific ports{Style.RESET_ALL}
   python phantom.py 192.168.1.1 --scan-tech udp --port 53,161

{Fore.YELLOW}6. Scan with exclusions{Style.RESET_ALL}
   python phantom.py 192.168.1.0/24 --exclude-host 192.168.1.1 192.168.1.100 --port top_1000 --exclude-port 80,443

{Fore.YELLOW}7. Scan from file with service detection{Style.RESET_ALL}
   python phantom.py --host-list targets.txt --port top_100 --service-detection-mode normal

{Fore.YELLOW}8. IP range scan{Style.RESET_ALL}
   python phantom.py 192.168.1.1-192.168.1.100 --port 22,80,443

{Fore.YELLOW}9. Multiple targets with OS fingerprinting{Style.RESET_ALL}
   python phantom.py 192.168.1.1 192.168.1.2 192.168.1.3 --os-fingerprinting-mode ai

{Fore.YELLOW}10. High-speed scan{Style.RESET_ALL}
    python phantom.py 192.168.1.0/24 --rate insane --thread 100 --timeout 1.0

{Fore.CYAN}{'='*70}{Style.RESET_ALL}
"""
        print(examples)

    def display_config(self, context):
        """Display the scan configuration"""
        if context.verbose or context.debug:
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}SCAN CONFIGURATION{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
            
            print(f"{Fore.YELLOW}Targets:{Style.RESET_ALL} {', '.join(context.targets) or 'None'}")
            print(f"{Fore.YELLOW}Scan Type:{Style.RESET_ALL} {context.scan_type.upper()}")
            print(f"{Fore.YELLOW}Ports:{Style.RESET_ALL} {self._get_port_description(context)}")
            print(f"{Fore.YELLOW}Service Detection:{Style.RESET_ALL} {'Enabled' if context.service_version else 'Disabled'}")
            print(f"{Fore.YELLOW}OS Detection:{Style.RESET_ALL} {'Enabled' if context.os_detection else 'Disabled'}")
            print(f"{Fore.YELLOW}Timing Template:{Style.RESET_ALL} T{context.timing}")
            print(f"{Fore.YELLOW}Threads:{Style.RESET_ALL} {context.threads}")
            print(f"{Fore.YELLOW}Timeout:{Style.RESET_ALL} {context.timeout} seconds")
            print(f"{Fore.YELLOW}Output Files:{Style.RESET_ALL}")
            print(f"  Normal: {context.output_normal or 'None'}")
            print(f"  XML: {context.output_xml or 'None'}")
            print(f"  JSON: {context.output_json or 'None'}")
            print(f"  HTML: {context.output_html or 'None'}")
            print(f"{Fore.YELLOW}Show Open Only:{Style.RESET_ALL} {'Enabled' if context.show_open_only else 'Disabled'}")
            print(f"{Fore.YELLOW}Verbose:{Style.RESET_ALL} {'Enabled' if context.verbose else 'Disabled'}")
            print(f"{Fore.YELLOW}Debug:{Style.RESET_ALL} {'Enabled' if context.debug else 'Disabled'}")
            print(f"{Fore.YELLOW}Excluded Targets:{Style.RESET_ALL} {', '.join(context.exclude) if context.exclude else 'None'}")
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    def run_scan(self, context: ScanContext) -> ScanResult:
        """
        Run the scan pipeline using Manager.
        
        Args:
            context: ScanContext containing scan configuration
            
        Returns:
            ScanResult containing all scan results
        """
        # Use Manager to orchestrate the scan
        result = self.manager.run_scan(context)
        
        # Generate output using reporter modules (if not "none")
        if context.output.output_format != "none":
            self.manager.generate_output(context, result)
        
        return result
      
    def print_results(self, result: ScanResult, context: ScanContext):
        """Print results to console if no output file specified"""
        if context.output.output_format != 'none':
            return  # Results are saved to file by reporter modules
        
        print(f"\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN RESULTS{Style.RESET_ALL}\n")
        
        if not result.hosts:
            print(f"{Fore.YELLOW}No targets found.{Style.RESET_ALL}")
            return
        
        # Print statistics
        result.update_statistics()
        print(f"{Fore.CYAN}Statistics:{Style.RESET_ALL}")
        print(f"  Total hosts: {result.total_hosts}")
        print(f"  Up hosts: {result.up_hosts}")
        print(f"  Total ports scanned: {result.total_ports_scanned}")
        print(f"  Open ports: {result.open_ports}")
        print()
        
        # Print host details
        for host in sorted(result.hosts.keys()):
            host_info = result.hosts[host]
            print(f"{Fore.CYAN}Target: {host}{Style.RESET_ALL}")
            print(f"  State: {host_info.state}")
            
            if host_info.os:
                print(f"  OS: {host_info.os}" + 
                      (f" (accuracy: {host_info.os_accuracy}%)" if host_info.os_accuracy else ""))
            
            if host_info.tcp_ports:
                print(f"  TCP Ports:")
                for port in sorted(host_info.tcp_ports.keys()):
                    port_info = host_info.tcp_ports[port]
                    service_str = f" ({port_info.service})" if port_info.service else ""
                    version_str = f" {port_info.version}" if port_info.version else ""
                    print(f"    {port}: {port_info.state}{service_str}{version_str}")
            
            if host_info.udp_ports:
                print(f"  UDP Ports:")
                for port in sorted(host_info.udp_ports.keys()):
                    port_info = host_info.udp_ports[port]
                    service_str = f" ({port_info.service})" if port_info.service else ""
                    version_str = f" {port_info.version}" if port_info.version else ""
                    print(f"    {port}: {port_info.state}{service_str}{version_str}")
            
            if host_info.scripts:
                print(f"  Scripts:")
                for script_name, script_result in host_info.scripts.items():
                    print(f"    {script_name}: {script_result}")
            
            print()
        
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
    
    def run(self):
        """Main execution method"""
        self.build_parser()
        self.args = self.parser.parse_args()
        
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
            print(f"  Targets: {len(context.targets.host)} target(s)")
            print(f"  Ping Tech: {context.pipeline.ping_tech}")
            print(f"  Scan Tech: {context.pipeline.scan_tech}")
            print(f"  Ports: {context.ports.port}")
            print(f"  Rate: {context.performance.rate}")
            print(f"  Threads: {context.performance.thread}")
            print()
        
        # Run scan
        try:
            print(f"[DEBUG] IN RA CONTEXT {context}")
            result = self.run_scan(context)
            self.print_results(result, context)
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

