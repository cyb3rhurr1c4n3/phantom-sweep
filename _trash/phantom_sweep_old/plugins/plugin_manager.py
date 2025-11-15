from argparse import ArgumentParser
import importlib
import inspect
import os
import traceback
from typing import Dict, List
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType



class PluginManager():
    def __init__(self, plugin_dir: str="phantom_sweep/plugins"):

        self.plugin_dir=plugin_dir
        self.plugin_str="phantom_sweep.plugins"
        self.plugins: Dict[PluginType, List[BasePlugin]] ={
            PluginType.Scan:[],
            PluginType.Analyze:[],
            PluginType.Output:[]
        }

        self._load_plugins()

    def _load_plugins(self):
        print("[+] Đang load các plugin...")
        for root, _, files in os.walk(self.plugin_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    module_path = os.path.join(root, file)
                    
                    # === SỬA LỖI TẠI ĐÂY ===
                    # 1. Tạo tên module chính xác
                    # Biến "network_probe/plugins\scanners/plugin.py"
                    # thành "network_probe.plugins.scanners.plugin"
                    
                    # Tên module phải bắt đầu từ thư mục gốc của project,
                    # không phải từ đường dẫn đầy đủ
                    
                    # Thay thế cả hai loại dấu gạch chéo
                    module_name_temp = module_path.replace(os.sep, '.')
                    module_name = module_name_temp.replace('/', '.')

                    # BUG: lỡ bên trong plugin name có thêm 1 dấu chấm (http_robots.txt.py) thì sao
                    
                    # Bỏ đuôi .py
                    module_name = module_name[:-3]
                    # =========================

                    # 2. Bỏ qua các file worker (như tcp_scanner.py)
                    # Chỉ tải các file có chữ "plugin" trong tên
                    if "plugin" not in file:
                         # print(f"    [DEBUG] Bỏ qua file worker: {file}")
                         continue

                    print(f"    [DEBUG] Đang thử tải plugin: {module_name}")
                    
                    try:
                        # 3. Import module
                        module = importlib.import_module(module_name)
                        
                        # 4. Tìm các lớp (class) bên trong module
                        for name, obj in inspect.getmembers(module):
                            if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                                plugin_instance = obj()
                                plugin_type = plugin_instance.plugin_type()
                                self.plugins[plugin_type].append(plugin_instance)
                                print(f"    [SUCCESS] Đã tải thành công: {plugin_instance.name()}")
                                
                    except ModuleNotFoundError as e:
                        print(f"    [ERROR] Lỗi không tìm thấy module khi tải {module_name}: {e}")
                        print("    Vui lòng kiểm tra xem bạn đã 'pip install' thư viện bị thiếu chưa (ví dụ: scapy)?")
                        print(traceback.format_exc())
                    except Exception as e:
                        print(f"    [ERROR] Lỗi nghiêm trọng khi tải {module_name}: {e}")
                        print("    Vui lòng kiểm tra lỗi cú pháp (SyntaxError) hoặc lỗi import trong file.")
                        print(traceback.format_exc())

    def register_cli(self,parser: ArgumentParser):
        for plugin_list in self.plugins.values():
                for plugin in plugin_list:
                    plugin.register_cli(parser)


    def run_pipline(self,context: ScanContext, args):

        print("[*] Chạy scan...")
        for plugin in self.plugins[PluginType.Scan]:
            plugin.run(context,args)
        print("[*] Chạy analyze...")
        for plugin in self.plugins[PluginType.Analyze]:
            plugin.run(context, args)
        print("[*] Xử lý output...")
        for plugin in self.plugins[PluginType.Output]:
            plugin.run(context, args)
        return context.get_data("scan_results")

class ScanManager():
    pass


   
        