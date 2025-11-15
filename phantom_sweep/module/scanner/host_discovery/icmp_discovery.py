import socket
from typing import Dict, List
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.module._base import ScannerBase
from scapy.all import *

class ICMPPing(ScannerBase):
    def __init__(self):
        if os.getuid() != 0:
            raise PermissionError("Quét TCP bằng scapy (SYN Scan) yêu cầu quyền root (sudo).")
    def _parse_port(self, context: ScanContext)-> List[int]:
        ports=set()
        if context.scan_all_ports:
            return list(range(1,65536))
        if context.fast_scan:
            return Fast_Scan_Port
        if context.ports:
            parts=context.ports.split(',')
            for part in parts:
                if '-' in part:
                    start,end=map(int,part.split('-'))
                    if 0<start <=end <=65535:
                        ports.update(range(start,end+1))
                else:
                    port=int(part)
                    if 0< port<=65535:
                        ports.add(port)
            return sorted(list(ports))
        return [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
    def scan(self,target:str, context : ScanContext)->Dict[str,any]:
        try:
            ip_target=socket.gethostbyname(target)
        except socket.gaierror:
            return {"error": f"Không thể phân giải tên miền: {target}"}
        
        packet=IP(dst=ip_target)/ ICMP()

        ans,unans=sr(packet,timeout=context.timeout,verbose=0,retry=1)
        
        host_state="down"

        if ans:
            if ans.haslayer(ICMP) and ans.getlayer(ICMP).type==0:
                host_state="up"
        return {"state":host_state}
