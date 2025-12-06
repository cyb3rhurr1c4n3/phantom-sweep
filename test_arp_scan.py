import scapy.all as scapy

def arp_scan(ip_range):
    """
    Performs an ARP scan on the specified IP range and returns a list of active devices.
    """
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=ip_range)
    
    # Create an Ethernet broadcast frame
    broadcast_ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the Ethernet frame and ARP request
    arp_request_broadcast = broadcast_ether / arp_request
    
    # Send the packet and capture responses (timeout after 1 second, verbose output off)
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    
    clients = []
    for element in answered_list:
        clients.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return clients

if __name__ == "__main__":
    target_ip_range = "10.0.19.0/24" # Example: adjust to your network range
    print(f"Scanning for devices on {target_ip_range}...")
    active_devices = arp_scan(target_ip_range)
    
    if active_devices:
        print("Active devices found:")
        for device in active_devices:
            print(f"IP: {device['ip']}\tMAC: {device['mac']}")
    else:
        print("No active devices found in the specified range.")