from argparse import ArgumentParser
import importlib
import inspect
import os
from typing import Dict, List
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType



class PluginManager():
    def __init__(self, plugin_dir: str="network_probe/plugins"):

        self.plugin_dir=plugin_dir

        self.plugins: Dict[PluginType, List[BasePlugin]] ={
            PluginType.Scan:[],
            PluginType.Analyze:[],
            PluginType.Ouput:[]
        }

        self._load_plugins()

    def _load_plugins(self):
        print("[+] Đang load các plugin...")
        for root,_,files in os.walk(self.plugin_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    module_path=os.path.join(root,file)

                    module_name=module_path.replace(os.sep,'.')[:-3]

                    try:
                        module = importlib.import_module(module_name)
                        for obj in inspect.getmember(module):
                            if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                                plugin_instance=obj()
                                plugin_type=plugin_instance.plugin_type()
                                self.plugins[plugin_type].append(plugin_instance)

                    except  Exception as e:
                        print(f"[ERROR] Không thể tải được plugin, lỗi: {e}")

    def register_cli(self,parser: ArgumentParser):
        for plugin_list in self.plugins.values():
                for plugin in plugin_list:
                    plugin.register_cli(parser)


    def run_pipline(self,context: ScanContext, args):
        print("[*] Chạy scan...")
        for plugin in self.plugins[PluginType.Scan]:
            pass
        print("[*] Chạy analyze...")
        for plugin in self.plugins[PluginType.Analyze]:
            pass
        print("[*] Xử lý output...")
        for plugin in self.plugins[PluginType.Ouput]:
            pass

        return context.get_data("scan_results")




   
        