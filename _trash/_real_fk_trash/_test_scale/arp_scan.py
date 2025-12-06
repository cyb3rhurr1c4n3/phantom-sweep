"""
ARP Scan Host Discovery - Windows-optimized with interface mapping
"""
import asyncio
import time
import platform
from typing import Set, Optional, Dict
from scapy.all import (
    Ether, ARP, AsyncSniffer, sendp, conf, 
    get_if_hwaddr, get_if_list, get_working_if, IFACES
)
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.module._base import ScannerBase

conf.verb = 0


class ARPScanner(ScannerBase):
    """ARP Discovery - Fast LAN host discovery (Windows-optimized)"""
    
    @property
    def name(self) -> str:
        return "arp"
    
    @property
    def type(self) -> str:
        return "host_discovery"
    
    @property
    def description(self) -> str:
        return "ARP Discovery (LAN only)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """Perform ARP discovery scan"""
        hosts = context.targets.host
        if not hosts:
            return
        
        print(f"[DEBUG] Targets to scan: {hosts}")
        
        if context.verbose:
            print(f"[*] Starting ARP discovery on {len(hosts)} hosts...")
        
        try:
            asyncio.run(self._async_scan(context, result, hosts))
        except Exception as e:
            print(f"[!] ARP scan EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
    
    def _get_interface_map(self) -> Dict[str, str]:
        """Map NPF device names to friendly names on Windows"""
        iface_map = {}
        
        try:
            # IFACES contains the mapping
            for iface_name, iface_obj in IFACES.items():
                # Get friendly name
                friendly = getattr(iface_obj, 'description', None) or \
                          getattr(iface_obj, 'name', None) or \
                          iface_name
                
                # Get MAC
                try:
                    mac = get_if_hwaddr(iface_name)
                except:
                    mac = "unknown"
                
                iface_map[iface_name] = {
                    'friendly': friendly,
                    'mac': mac,
                    'name': iface_name
                }
        except Exception as e:
            print(f"[DEBUG] Interface mapping error: {e}")
        
        return iface_map
    
    def _select_best_interface(self, context: ScanContext) -> Optional[str]:
        """Select the best network interface for ARP scanning"""
        print(f"[DEBUG] === INTERFACE SELECTION ===")
        
        # Get interface mapping
        iface_map = self._get_interface_map()
        
        print(f"[DEBUG] Interface mapping:")
        for npf_name, info in iface_map.items():
            print(f"[DEBUG]   {info['friendly']}")
            print(f"[DEBUG]     Device: {npf_name}")
            print(f"[DEBUG]     MAC: {info['mac']}")
        
        # Get your WiFi MAC from ipconfig (f8:fb:2f:c6:68:4f)
        target_mac = "f8:fb:2f:c6:68:4f"
        
        # Priority 1: Match exact MAC (your WiFi)
        for npf_name, info in iface_map.items():
            if info['mac'].lower() == target_mac.lower():
                print(f"[DEBUG] ✅ Found WiFi by MAC: {info['friendly']}")
                return npf_name
        
        # Priority 2: Look for WiFi/Wireless in description
        for npf_name, info in iface_map.items():
            friendly_lower = info['friendly'].lower()
            if any(keyword in friendly_lower for keyword in ['wi-fi', 'wireless', '802.11', 'wlan']):
                mac = info['mac']
                if mac != "00:00:00:00:00:00":
                    print(f"[DEBUG] ✅ Found WiFi by name: {info['friendly']} (MAC: {mac})")
                    return npf_name
        
        # Priority 3: Exclude known virtual adapters
        virtual_keywords = ['hyper-v', 'vethernet', 'virtual', 'vmware', 'virtualbox', 'loopback', 'bluetooth']
        
        for npf_name, info in iface_map.items():
            friendly_lower = info['friendly'].lower()
            mac = info['mac']
            
            # Skip virtual and zero MACs
            if mac == "00:00:00:00:00:00":
                continue
            
            if any(keyword in friendly_lower for keyword in virtual_keywords):
                print(f"[DEBUG] ⏭️  Skipping virtual adapter: {info['friendly']}")
                continue
            
            # Look for Ethernet
            if 'ethernet' in friendly_lower:
                print(f"[DEBUG] ✅ Found Ethernet: {info['friendly']} (MAC: {mac})")
                return npf_name
        
        # Priority 4: Any interface with valid MAC (not virtual)
        for npf_name, info in iface_map.items():
            mac = info['mac']
            friendly_lower = info['friendly'].lower()
            
            if mac == "00:00:00:00:00:00":
                continue
            
            # Skip Hyper-V MACs (00:15:5d:xx:xx:xx)
            if mac.startswith("00:15:5d"):
                print(f"[DEBUG] ⏭️  Skipping Hyper-V adapter: {info['friendly']}")
                continue
            
            # Skip VirtualBox MACs (0a:00:27:xx:xx:xx)
            if mac.startswith("0a:00:27"):
                print(f"[DEBUG] ⏭️  Skipping VirtualBox adapter: {info['friendly']}")
                continue
            
            if not any(keyword in friendly_lower for keyword in virtual_keywords):
                print(f"[DEBUG] ⚠️  Using fallback interface: {info['friendly']} (MAC: {mac})")
                return npf_name
        
        # Priority 5: Use get_working_if() as last resort
        try:
            working = get_working_if()
            print(f"[DEBUG] ⚠️  Using get_working_if(): {working}")
            return working
        except:
            pass
        
        print(f"[DEBUG] ❌ No suitable interface found!")
        return None
    
    async def _async_scan(self, context: ScanContext, result: ScanResult, hosts: list):
        """Fire all ARP requests with extensive debugging"""
        print(f"[DEBUG] === STARTING ARP SCAN ===")
        discovered: Set[str] = set()
        hosts_set = set(hosts)
        mac_cache = {}
        
        # Select interface
        iface = self._select_best_interface(context)
        
        if not iface:
            print(f"[!] ERROR: Could not find suitable network interface!")
            return
        
        print(f"[DEBUG] Using interface: {iface}")
        
        # Verify interface
        try:
            local_mac = get_if_hwaddr(iface)
            print(f"[DEBUG] Local MAC address: {local_mac}")
        except Exception as e:
            print(f"[!] ERROR: Cannot get MAC for interface: {e}")
            return
        
        # BPF filter
        bpf_filter = "arp and arp[6:2] == 2"
        print(f"[DEBUG] BPF filter: {bpf_filter}")
        
        # Packet handler
        packet_count = [0]
        
        def handle_packet(pkt):
            packet_count[0] += 1
            
            try:
                if pkt.haslayer(ARP):
                    psrc = pkt[ARP].psrc
                    hwsrc = pkt[ARP].hwsrc
                    
                    print(f"[DEBUG] ARP Reply: {psrc} is at {hwsrc}")
                    
                    if psrc in hosts_set:
                        if psrc not in discovered:
                            discovered.add(psrc)
                            mac_cache[psrc] = hwsrc
                            result.add_host(psrc, state="up")
                            print(f"  [+] {psrc} is up ({hwsrc})")
            except Exception as e:
                print(f"[DEBUG] Packet handler error: {e}")
        
        # Start sniffer
        print(f"[DEBUG] Starting sniffer...")
        try:
            sniffer = AsyncSniffer(
                filter=bpf_filter,
                prn=handle_packet,
                store=False,
                iface=iface
            )
            sniffer.start()
            await asyncio.sleep(0.2)
            print(f"[DEBUG] Sniffer started")
        except Exception as e:
            print(f"[!] ERROR: Failed to start sniffer: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # Build and send packets
        print(f"[DEBUG] Building packets...")
        packets = []
        for host in hosts:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=host)
            packets.append(pkt)
        
        print(f"[DEBUG] Sending {len(packets)} ARP requests...")
        for i, pkt in enumerate(packets):
            try:
                sendp(pkt, iface=iface, verbose=0)
                print(f"[DEBUG] Sent packet {i+1}/{len(packets)}")
                await asyncio.sleep(0.05)
            except Exception as e:
                print(f"[DEBUG] Send error: {e}")
        
        # Wait for responses
        print(f"[DEBUG] Waiting for responses...")
        timeout = 3.0
        start_wait = time.time()
        
        while (time.time() - start_wait) < timeout:
            await asyncio.sleep(0.3)
            print(f"[DEBUG] Discovered: {len(discovered)}/{len(hosts)} (packets received: {packet_count[0]})")
            
            if len(discovered) == len(hosts):
                break
        
        # Stop sniffer
        try:
            sniffer.stop()
        except:
            pass
        
        print(f"[DEBUG] === SCAN COMPLETE ===")
        print(f"[DEBUG] Packets received: {packet_count[0]}")
        print(f"[DEBUG] Hosts discovered: {len(discovered)}/{len(hosts)}")
        
        if context.verbose:
            print(f"[*] ARP scan completed: {len(discovered)}/{len(hosts)} hosts up")
        
        # Mark undiscovered as down
        for host in hosts:
            if host not in discovered:
                result.add_host(host, state="down")