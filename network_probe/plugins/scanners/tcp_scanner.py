
from typing import Dict, List
from network_probe.core.context import ScanContext
from network_probe.plugins.base import BaseScanner
import os
from dotenv import load_dotenv
import socket


Fast_Scan_Port=[7, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 1025, 1026, 1027, 1028, 1029, 1030,
    113, 199, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    902, 1080, 1099, 123, 137, 138, 161, 162, 177, 1720, 2000, 2049, 2121,
    2717, 3000, 3128, 3478, 3702, 49152, 49153, 49154, 49155, 49156, 49157,
    500, 5060, 5222, 5223, 5228, 5357, 5432, 5631, 5666, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8081, 8888, 9100, 9999, 10000, 32768, 49158,
    49159, 49160, 49161, 49162, 49163]

class TCPScanner(BaseScanner):
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
        return [20,21,22,80,443]
    def scan(self, target: str,context: ScanContext) -> Dict[str,any]:
        ports_scan=self._parse_port(context)
        result={}
        for port in ports_scan:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(context.timeout)
            try:
                result_code=s.connect_ex((target,port))
                if result_code==0:
                    result[port]={"state":"open","service":"unknown"}
            except socket.gaierror:
                return {"error": f"Không thể phân giải tên miền: {target}"}
            except socket.error as e:
                if context.debug:
                    print(f"    [DEBUG-TCPScanner] Lỗi socket khi quét cổng {port}: {e}")
            finally:
                s.close()
            final={"ports":result}
        return final