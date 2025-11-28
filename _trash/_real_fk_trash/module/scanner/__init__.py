"""
Scanner Module - Host Discovery and Port Scanning
"""
from phantom_sweep.module.scanner.host_discovery import (
    ICMPPingScanner, TCPPingScanner, ARPScanner
)
from phantom_sweep.module.scanner.port_scanning import (
    TCPSynScanner, TCPConnectScanner, UDPScanner
)

# Scanner registry
HOST_DISCOVERY_SCANNERS = {
    "icmp": ICMPPingScanner,
    "tcp": TCPPingScanner,
    "arp": ARPScanner,
}

PORT_SCANNING_SCANNERS = {
    "stealth": TCPSynScanner,
    "connect": TCPConnectScanner,
    "udp": UDPScanner,
}

__all__ = [
    'ICMPPingScanner', 'TCPPingScanner', 'ARPScanner',
    'TCPSynScanner', 'TCPConnectScanner', 'UDPScanner',
    'HOST_DISCOVERY_SCANNERS', 'PORT_SCANNING_SCANNERS'
]

