import argparse
import pyfiglet
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    ascii_banner = pyfiglet.figlet_format("SkyView", font="slant")
    print(Fore.CYAN + ascii_banner + Style.RESET_ALL)

    print(f"{Fore.YELLOW}A lightweight CLI network reconnaissance tool with OS fingerprinting{Style.RESET_ALL}")
    print("Version: 1.0.0")
    print("Author : Group 10")
    print("Inspired by Nmap & Masscan - Fast, Lightweight, Extensible\n")

    print(Fore.RED + "[!] Legal Disclaimer:" + Style.RESET_ALL)
    print("    Usage of SkyView for attacking targets without prior mutual consent is illegal.")
    print("    It is the end user's responsibility to comply with all applicable laws.")
    print("    Developers assume no liability for misuse or damage caused by this tool.\n")


def build_parser():
    print_banner()
    parser = argparse.ArgumentParser(
        description="SkyView - Công cụ quét mạng hạng nhẹ",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Advanced help: dùng long option chuẩn, short option 1 ký tự nếu cần
    parser.add_argument(
        "-H", "--advanced-help",
        action="store_true",
        help="Show advanced help message."
    )

    # Version (consistent với banner)
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="SkyView 1.0.0",
        help="Show program's version number."
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.advanced_help:
        print("Advanced help: (thêm hướng dẫn ở đây)")

if __name__ == "__main__":
    main()
