import asyncio
import sys
from typing import List, Dict, Union
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BaseScanner


class PingScannerAsync(BaseScanner):
    def __init__(self, concurrency: int = 500):
        """
        Args:
            concurrency: Số lượng ping đồng thời (mặc định 500 cho scan nhanh)
        """
        self.concurrency = concurrency
        self.sem = None

    async def _ping_one(self, target: str, timeout: float) -> Dict[str, str]:
        """
        Ping một target với timeout được chỉ định.
        
        Args:
            target: IP hoặc hostname cần ping
            timeout: Thời gian timeout (giây)
            
        Returns:
            Dict chứa state hoặc error message
        """
        # Giới hạn timeout tối đa để scan nhanh hơn
        timeout = min(timeout, 0.5)  # Tối đa 500ms
        
        # Xây dựng command dựa trên platform
        if sys.platform.startswith('win'):
            timeout_ms = max(100, int(timeout * 1000))  # Tối thiểu 100ms
            cmd = ['ping', '-n', '1', '-w', str(timeout_ms), target]
        else:
            # Linux/Unix: -W timeout in seconds
            timeout_sec = 1  # Linux ping tối thiểu 1 giây
            cmd = ['ping', '-c', '1', '-W', str(timeout_sec), target]

        try:
            # Khởi tạo semaphore nếu chưa có
            if self.sem is None:
                self.sem = asyncio.Semaphore(self.concurrency)
            
            async with self.sem:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                try:
                    # Timeout thực tế ngắn hơn timeout của ping command
                    await asyncio.wait_for(proc.communicate(), timeout=timeout + 0.1)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    await proc.wait()
                    return {"state": "Down", "reason": "timeout"}
                
                if proc.returncode == 0:
                    return {"state": "Up"}
                else:
                    return {"state": "Down", "reason": f"exit_code_{proc.returncode}"}
                    
        except FileNotFoundError:
            return {"state": "Error", "error": "ping command not found"}
        except PermissionError:
            return {"state": "Error", "error": "permission denied"}
        except Exception as e:
            return {"state": "Error", "error": str(e)}

    def scan(self, targets: Union[str, List[str]], context: ScanContext) -> Dict[str, any]:
        """
        Scan một hoặc nhiều targets.
        
        Args:
            targets: Một target (str) hoặc list targets (List[str])
            context: ScanContext chứa cấu hình
            
        Returns:
            - Nếu targets là str: Dict kết quả cho target đó
            - Nếu targets là list: Dict mapping target -> kết quả
        """
        # Normalize input: chuyển string thành list 1 phần tử
        if isinstance(targets, str):
            # Single target - trả về kết quả trực tiếp
            return asyncio.run(self._scan_single(targets, context))
        elif isinstance(targets, list):
            # Multiple targets - trả về dict
            return asyncio.run(self._scan_all(targets, context))
        else:
            return {"state": "Error", "error": f"Invalid targets type: {type(targets)}"}

    async def _scan_single(self, target: str, context: ScanContext) -> Dict[str, any]:
        """Scan một target duy nhất."""
        if not target or not target.strip():
            return {"state": "Error", "error": "target cannot be empty"}
        
        # Timeout mặc định ngắn cho scan nhanh
        timeout = float(getattr(context, 'timeout', 0.3))
        return await self._ping_one(target.strip(), timeout)

    async def _scan_all(self, targets: List[str], context: ScanContext) -> Dict[str, Dict[str, str]]:
        """
        Scan nhiều targets với concurrency control.
        
        Args:
            targets: List targets (phải là list thật, không phải string!)
            context: Scan context
            
        Returns:
            Dict kết quả scan
        """
        # CRITICAL: Kiểm tra targets có phải là list thật không
        if not isinstance(targets, list):
            # Nếu là string, trả về lỗi rõ ràng
            return {
                "ERROR": {
                    "state": "Error",
                    "error": f"_scan_all expects list, got {type(targets).__name__}: {targets}"
                }
            }
        
        if not targets:
            return {}
        
        # Timeout mặc định ngắn cho scan nhanh (300ms)
        timeout = float(getattr(context, 'timeout', 0.3))
        
        # Tạo tasks cho tất cả targets
        tasks = [self._ping_one(str(target).strip(), timeout) for target in targets]
        
        # Chạy tất cả tasks đồng thời với error handling
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Xử lý kết quả và exceptions
        output = {}
        for target, result in zip(targets, results):
            if isinstance(result, Exception):
                output[str(target)] = {
                    "state": "Error", 
                    "error": f"Unexpected error: {str(result)}"
                }
            else:
                output[str(target)] = result
        
        return output


# Utility functions
async def ping_host(host: str, timeout: float = 1.0) -> Dict[str, any]:
    """
    Ping một host duy nhất.
    
    Args:
        host: IP hoặc hostname
        timeout: Timeout (giây)
        
    Returns:
        Dict kết quả ping
        
    Example:
        result = await ping_host('8.8.8.8', timeout=2.0)
        # → {'state': 'Up'}
    """
    from types import SimpleNamespace
    
    scanner = PingScannerAsync()
    context = SimpleNamespace(timeout=timeout)
    return await scanner._scan_single(host, context)


async def ping_hosts(hosts: List[str], timeout: float = 1.0, concurrency: int = 100) -> Dict[str, Dict[str, any]]:
    """
    Ping nhiều hosts đồng thời.
    
    Args:
        hosts: List IP/hostname
        timeout: Timeout cho mỗi ping (giây)
        concurrency: Số ping đồng thời tối đa
        
    Returns:
        Dict kết quả ping
        
    Example:
        results = await ping_hosts(['8.8.8.8', 'google.com'], timeout=2.0)
        # → {'8.8.8.8': {'state': 'Up'}, 'google.com': {'state': 'Up'}}
    """
    from types import SimpleNamespace
    
    scanner = PingScannerAsync(concurrency=concurrency)
    context = SimpleNamespace(timeout=timeout)
    return await scanner._scan_all(hosts, context)