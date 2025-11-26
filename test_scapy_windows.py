from scapy.all import *

# Select WiFi interface
target_ip = "192.168.1.106"
source_ip = "192.168.1.102"

for iface in conf.ifaces.values():
    if iface.ip and iface.ip == source_ip:
        conf.iface = iface
        print(f"✓ Using interface: {iface.name} ({iface.ip})")
        break

# === STEP 1: ARP to get target MAC ===
print(f"\n[1] Resolving MAC address for {target_ip}...")

arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
ans, unans = srp(arp_request, timeout=2, verbose=0)

if ans:
    target_mac = ans[0][1].hwsrc
    print(f"    ✓ Target MAC: {target_mac}")
else:
    print(f"    ✗ Could not resolve MAC, trying anyway...")
    target_mac = None

# === STEP 2: Get gateway MAC ===
print(f"\n[2] Resolving gateway MAC...")

# Get default gateway
gateway = conf.route.route("0.0.0.0")[2]
print(f"    Gateway IP: {gateway}")

arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway)
ans, unans = srp(arp_request, timeout=2, verbose=0)

if ans:
    gateway_mac = ans[0][1].hwsrc
    print(f"    ✓ Gateway MAC: {gateway_mac}")
else:
    print(f"    ✗ Could not resolve gateway MAC")
    gateway_mac = None

# === STEP 3: Send SYN with explicit MAC ===
print(f"\n[3] Sending SYN packet...")

if gateway_mac:
    # Build packet with Layer 2
    pkt = Ether(dst=gateway_mac) / IP(src=source_ip, dst=target_ip) / TCP(dport=80, flags='S')
    ans, unans = srp(pkt, timeout=3, verbose=1)
else:
    # Fallback to Layer 3
    pkt = IP(src=source_ip, dst=target_ip) / TCP(dport=80, flags='S')
    ans, unans = sr(pkt, timeout=3, verbose=1)

print(f"\n[4] Results:")
print(f"    Answered: {len(ans)}")
print(f"    Unanswered: {len(unans)}")

if ans:
    print("\n✓ SUCCESS!")
    ans.show()