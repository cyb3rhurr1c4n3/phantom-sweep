import argparse
import sys
import os

try:
    import pyfiglet
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Error: Missing required packages. Install with:")
    print("pip install pyfiglet colorama")
    sys.exit(1)


class SkyViewCLI:
    """CLI Interface - Only handles parsing and display"""
    
    VERSION = "1.0.0"
    
    def __init__(self):
        self.parser = None
        self.args = None
        
    def print_banner(self):
        """Display ASCII banner and information"""
        try:
            ascii_banner = pyfiglet.figlet_format("SkyView", font="slant")
            print(Fore.CYAN + ascii_banner + Style.RESET_ALL)
        except:
            print("=" * 60)
            print(" " * 20 + "SkyView")
            print("=" * 60)
        
        print(f"{Fore.YELLOW}A lightweight CLI network reconnaissance tool with OS fingerprinting{Style.RESET_ALL}")
        print(f"Version: {self.VERSION}")
        print("Author : Group 10")
        print("Inspired by Nmap & Masscan - Fast, Lightweight, Extensible\n")
        
        print(Fore.RED + "[!] Legal Disclaimer:" + Style.RESET_ALL)
        print("    Usage of SkyView for attacking targets without prior mutual consent is illegal.")
        print("    It is the end user's responsibility to comply with all applicable laws.")
        print("    Developers assume no liability for misuse or damage caused by this tool.\n")
    
    def print_advanced_help(self):
        """Display advanced help information"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SKYVIEW - ADVANCED HELP{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}TARGET SPECIFICATION:{Style.RESET_ALL}")
        print("  skyview 192.168.1.1              # Single IP")
        print("  skyview 192.168.1.1-10           # IP range")
        print("  skyview 192.168.1.0/24           # CIDR block")
        print("  skyview example.com              # Domain")
        print("  skyview -iL targets.txt          # From file\n")
        
        print(f"{Fore.YELLOW}SCAN TECHNIQUES:{Style.RESET_ALL}")
        print("  -sT            # TCP Connect scan (default, no root)")
        print("  -sS            # TCP SYN scan (stealth, requires root)")
        print("  -sn            # Ping scan only (no port scan)")
        print("  -PA            # TCP ACK ping for host discovery\n")
        
        print(f"{Fore.YELLOW}PORT SPECIFICATION:{Style.RESET_ALL}")
        print("  -p 80,443                # Specific ports")
        print("  -p 1-1000                # Port range")
        print("  -p-                      # All ports (1-65535)")
        print("  -F                       # Fast scan (top 100 ports)\n")
        
        print(f"{Fore.YELLOW}SERVICE/VERSION DETECTION:{Style.RESET_ALL}")
        print("  -sV            # Probe open ports to determine service/version")
        print("  -O             # Enable OS detection\n")
        
        print(f"{Fore.YELLOW}TIMING AND PERFORMANCE:{Style.RESET_ALL}")
        print("  -T0 through -T5          # Timing templates")
        print("    -T0: Paranoid (slowest, IDS evasion)")
        print("    -T1: Sneaky")
        print("    -T2: Polite")
        print("    -T3: Normal (default)")
        print("    -T4: Aggressive")
        print("    -T5: Insane (fastest)")
        print("  --thread <num>           # Number of threads (default: 50)")
        print("  --timeout <sec>          # Timeout in seconds (default: 1)\n")
        
        print(f"{Fore.YELLOW}OUTPUT:{Style.RESET_ALL}")
        print("  -oN file.txt             # Normal output")
        print("  -oX file.xml             # XML output")
        print("  -oJ file.json            # JSON output")
        print("  -oH file.html            # HTML report")
        print("  --open                   # Show only open ports\n")
        
        print(f"{Fore.YELLOW}EXAMPLES:{Style.RESET_ALL}")
        print("  # Basic scan")
        print("  skyview -p 80,443 192.168.1.1\n")
        
        print("  # Fast scan with service detection")
        print("  skyview -F -sV 192.168.1.0/24\n")
        
        print("  # Stealth SYN scan all ports")
        print("  skyview -sS -p- 192.168.1.1\n")
        
        print("  # Aggressive scan with OS detection")
        print("  skyview -T4 -O -sV 192.168.1.1\n")
        
        print("  # Scan from file, output to JSON")
        print("  skyview -iL targets.txt -oJ results.json\n")
        
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def build_parser(self):
        """Build argument parser"""
        parser = argparse.ArgumentParser(
            description="SkyView - Lightweight Network Reconnaissance Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  skyview 192.168.1.1                      # Basic scan
  skyview -p 80,443 192.168.1.0/24        # Scan specific ports
  skyview -F -sV example.com              # Fast scan with service detection
  skyview -sS -p- 192.168.1.1             # SYN scan all ports

For more examples, use: skyview -H
            """,
            add_help=True
        )
        
        # Help and Version
        parser.add_argument(
            "-H", "--advanced-help",
            action="store_true",
            help="Show advanced help with detailed examples"
        )
        
        parser.add_argument(
            "-v", "--version",
            action="version",
            version=f"SkyView {self.VERSION}",
            help="Show program's version number"
        )
        
        # Target Specification
        target_group = parser.add_argument_group('Target Specification')
        target_group.add_argument(
            "targets",
            nargs="*",
            metavar="TARGET",
            help="IP address(es), range, CIDR block, or domain"
        )
        
        target_group.add_argument(
            "-iL", "--input-list",
            metavar="FILE",
            help="Read targets from file (one per line)"
        )
        
        target_group.add_argument(
            "--exclude",
            nargs="+",
            metavar="IP",
            help="Exclude specified IPs/ranges/CIDRs from scan"
        )
        
        # Scan Techniques
        scan_group = parser.add_argument_group('Scan Techniques')
        scan_group.add_argument(
            "-sT", "--tcp-connect",
            action="store_true",
            help="TCP Connect scan (default, no root required)"
        )
        
        scan_group.add_argument(
            "-sS", "--syn-scan",
            action="store_true",
            help="TCP SYN scan (stealth, requires root)"
        )
        
        scan_group.add_argument(
            "-sn", "--ping-scan",
            action="store_true",
            help="Ping scan only (no port scanning)"
        )
        
        scan_group.add_argument(
            "-PA", "--ack-ping",
            action="store_true",
            help="TCP ACK ping for host discovery"
        )
        
        scan_group.add_argument(
            "-sL", "--list-targets",
            action="store_true",
            help="List targets without scanning"
        )
        
        # Port Specification
        port_group = parser.add_argument_group('Port Specification')
        port_group.add_argument(
            "-p", "--ports",
            metavar="PORTS",
            help="Ports to scan (e.g., 80,443 or 1-1000)"
        )
        
        port_group.add_argument(
            "-p-", "--all-ports",
            action="store_true",
            dest="scan_all_ports",
            help="Scan all 65535 ports"
        )
        
        port_group.add_argument(
            "-F", "--fast",
            action="store_true",
            help="Fast scan (top 100 most common ports)"
        )
        
        # Service/Version Detection
        detect_group = parser.add_argument_group('Service/Version Detection')
        detect_group.add_argument(
            "-sV", "--service-version",
            action="store_true",
            help="Probe open ports to determine service/version info"
        )
        
        detect_group.add_argument(
            "-O", "--os-detection",
            action="store_true",
            help="Enable OS detection"
        )
        
        # Timing and Performance
        timing_group = parser.add_argument_group('Timing and Performance')
        
        # Timing templates (mutually exclusive)
        timing_templates = timing_group.add_mutually_exclusive_group()
        timing_templates.add_argument(
            "-T0", "--timing-paranoid",
            action="store_const", const=0, dest="timing",
            help="Paranoid (slowest, IDS evasion)"
        )
        timing_templates.add_argument(
            "-T1", "--timing-sneaky",
            action="store_const", const=1, dest="timing",
            help="Sneaky"
        )
        timing_templates.add_argument(
            "-T2", "--timing-polite",
            action="store_const", const=2, dest="timing",
            help="Polite"
        )
        timing_templates.add_argument(
            "-T3", "--timing-normal",
            action="store_const", const=3, dest="timing",
            help="Normal (default)"
        )
        timing_templates.add_argument(
            "-T4", "--timing-aggressive",
            action="store_const", const=4, dest="timing",
            help="Aggressive"
        )
        timing_templates.add_argument(
            "-T5", "--timing-insane",
            action="store_const", const=5, dest="timing",
            help="Insane (fastest)"
        )
        
        timing_group.add_argument(
            "--thread",
            type=int,
            default=50,
            metavar="NUM",
            help="Number of parallel threads (default: 50)"
        )
        
        timing_group.add_argument(
            "--timeout",
            type=float,
            default=1.0,
            metavar="SEC",
            help="Timeout in seconds (default: 1.0)"
        )
        
        # Output Options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument(
            "-oN", "--output-normal",
            metavar="FILE",
            help="Save normal output to file"
        )
        
        output_group.add_argument(
            "-oX", "--output-xml",
            metavar="FILE",
            help="Save XML output to file"
        )
        
        output_group.add_argument(
            "-oJ", "--output-json",
            metavar="FILE",
            help="Save JSON output to file"
        )
        
        output_group.add_argument(
            "-oH", "--output-html",
            metavar="FILE",
            help="Save HTML report to file"
        )
        
        output_group.add_argument(
            "--open",
            action="store_true",
            help="Show only open ports/hosts"
        )
        
        # Miscellaneous
        misc_group = parser.add_argument_group('Miscellaneous')
        misc_group.add_argument(
            "--verbose",
            action="store_true",
            help="Increase output verbosity"
        )
        
        misc_group.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug output"
        )
        
        self.parser = parser
        return parser
    
    def validate_args(self, args):
        """Validate parsed arguments"""
        return True
    
    def _is_root(self):
        """Check if running with root privileges"""
        try:
            return sys.platform != 'win32' and os.geteuid() == 0
        except AttributeError:
            return False
    
    def build_context(self, args):
        """Convert CLI args to Context object for engine"""
        return None
    
    def _get_scan_type(self, args):
        pass
    
    def display_config(self, context):
        pass
    
    def _get_port_description(self, context):
        pass
    
    def display_results(self, results):
        """Display scan results - called by engine after scan"""
        if not results:
            print(f"{Fore.YELLOW}[!] No results to display{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}[✓] Scan completed successfully{Style.RESET_ALL}")
        print(f"    Results are ready for processing by report plugins\n")
    
    def run(self):
        pass

def main():
    """Entry point"""
    cli = SkyViewCLI()
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