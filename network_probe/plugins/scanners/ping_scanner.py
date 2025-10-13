import subprocess
from typing import Dict
from network_probe.core.context import ScanContext
from network_probe.plugins.base import BaseScanner
import sys

class PingScaner(BaseScanner):
    def scan(self, target: str, context: ScanContext) ->Dict[str,any]:
        try:
            if sys.platform.startswith('win'):
                timeout_ms=str(int(context.timeout*1000))
                conmand=['ping','-n','1','-w',timeout_ms,target]
            else:
                timeout_s=str(int(context.timeout))
                conmand=['ping','-c','1','-w',timeout_s,target]

            result=subprocess.run(
                conmand,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True
            )
            if result.returncode==0:
                return {"state":"Up"}
            else:
                return {"state":"Down"}
        except FileNotFoundError:
            return {"error": "Lệnh 'ping' không tồn tại trên hệ thống."}
        except Exception as e:
            return {"error": f"Lỗi không xác định khi ping: {str(e)}"}