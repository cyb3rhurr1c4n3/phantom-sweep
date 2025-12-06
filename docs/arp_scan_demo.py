#!/usr/bin/env python3
"""
ARP Scan Demo - Ultra-fast local network host discovery

Usage:
    sudo python3 arp_scan_demo.py 192.168.1.0/24
    sudo python3 arp_scan_demo.py 10.0.0.1 10.0.0.2 10.0.0.3
"""

import sys
import asyncio
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module.scanner.host_discovery.arp_scan import ARPScanner


def demo():
    """Demonstrate ARP Scanner usage"""
    
    # Example: Scan local network
    targets = ["192.168.1.1", "192.168.1.2", "192.168.1.254"]
    
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    
    print(f"[*] ARP Scan Demo - Target: {targets}")
    print("[*] This demo requires root/sudo privileges")
    print()
    
    # Create mock context
    class MockTargets:
        def __init__(self, hosts):
            self.host = hosts
    
    class MockPerformance:
        class Timeout:
            timeout = 3.0
        timeout = Timeout()
    
    class MockContext:
        def __init__(self, hosts):
            self.targets = MockTargets(hosts)
            self.performance = MockPerformance()
            self.verbose = True
            self.debug = False
    
    # Create result object
    result = ScanResult()
    context = MockContext(targets)
    
    # Run ARP scan
    try:
        scanner = ARPScanner()
        scanner.scan(context, result)
        
        print("\n[*] Scan Results:")
        print("-" * 50)
        
        for host, state in result.hosts.items():
            print(f"  {host}: {state.get('state', 'down')}")
        
        up_count = sum(1 for h in result.hosts.values() if h.get('state') == 'up')
        print("-" * 50)
        print(f"[*] Summary: {up_count} host(s) up out of {len(targets)}")
        
    except PermissionError:
        print("[!] Error: ARP scan requires root/sudo privileges!")
        print("[!] Run with: sudo python3 arp_scan_demo.py <targets>")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    demo()
