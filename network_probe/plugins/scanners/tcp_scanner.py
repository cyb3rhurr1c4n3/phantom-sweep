
from typing import Dict, List
from network_probe.core.context import ScanContext
from network_probe.plugins.base import BaseScanner
from network_probe.plugins.scanners.syn_scanner import Fast_Scan_Port


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
            socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            socket.settimeout(context.timeout)
            try:
                result_code=socket.connect_ex((target,port))
                if result_code==0:
                    result[port]={"Status":"Open","Service":"Unknow"}
            except socket.gaierror:
                return {"error": f"Không thể phân giải tên miền: {target}"}
            except socket.error as e:
                if context.debug:
                    print(f"    [DEBUG-TCPScanner] Lỗi socket khi quét cổng {port}: {e}")
            finally:
                socket.close()
        return result