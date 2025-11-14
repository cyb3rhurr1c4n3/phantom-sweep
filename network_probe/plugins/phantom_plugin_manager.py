"""
Phantom Plugin Manager - Discovers and loads plugins from plugins/ directory
"""
import importlib
import inspect
import os
import traceback
from typing import Dict, List, Optional
from network_probe.plugins.base_plugin import BasePlugin
from network_probe.plugins.plugin_types import PluginType


class PhantomPluginManager:
    """Plugin manager that discovers plugins from plugins/ directory structure"""
    
    # Map category to plugin type
    CATEGORY_TO_TYPE = {
        "ping_tech": PluginType.Scan,
        "scan_tech": PluginType.Scan,
        "analyze": PluginType.Analyze,
        "scripts": PluginType.Analyze,  # Scripts are also analysis plugins
        "output": PluginType.Output
    }
    
    def __init__(self, plugin_base_dir: str = "plugins"):
        self.plugin_base_dir = plugin_base_dir
        self.plugins: Dict[str, Dict[str, BasePlugin]] = {
            "ping_tech": {},
            "scan_tech": {},
            "analyze": {},
            "scripts": {},
            "output": {}
        }
        self._load_plugins()
    
    def _load_plugins(self):
        """Load all plugins from plugins/ directory"""
        print("[+] Đang load các plugin từ plugins/...")
        
        if not os.path.exists(self.plugin_base_dir):
            print(f"    [WARNING] Thư mục {self.plugin_base_dir} không tồn tại.")
            return
        
        # Walk through each category directory
        for category in self.plugins.keys():
            category_dir = os.path.join(self.plugin_base_dir, category)
            if not os.path.exists(category_dir):
                continue
            
            # Load plugins from this category
            for file in os.listdir(category_dir):
                if not file.endswith("_plugin.py"):
                    continue
                
                module_name = f"{self.plugin_base_dir}.{category}.{file[:-3]}"
                
                try:
                    module = importlib.import_module(module_name)
                    
                    # Find plugin classes
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, BasePlugin) and 
                            obj is not BasePlugin):
                            
                            plugin_instance = obj()
                            metadata = plugin_instance.metadata()
                            plugin_name = metadata.get("name", plugin_instance.name())
                            
                            self.plugins[category][plugin_name] = plugin_instance
                            print(f"    [SUCCESS] Đã tải plugin: {category}/{plugin_name}")
                            
                except Exception as e:
                    print(f"    [ERROR] Lỗi khi tải {module_name}: {e}")
                    if os.getenv("DEBUG"):
                        print(traceback.format_exc())
    
    def get_plugin(self, category: str, name: str) -> Optional[BasePlugin]:
        """Get a plugin by category and name"""
        return self.plugins.get(category, {}).get(name)
    
    def get_plugins_by_category(self, category: str) -> Dict[str, BasePlugin]:
        """Get all plugins in a category"""
        return self.plugins.get(category, {})
    
    def list_plugins(self, category: Optional[str] = None) -> Dict[str, Dict[str, BasePlugin]]:
        """List all plugins, optionally filtered by category"""
        if category:
            return {category: self.plugins.get(category, {})}
        return self.plugins
    
    def get_plugin_info(self, category: str, name: str) -> Optional[Dict]:
        """Get metadata for a plugin"""
        plugin = self.get_plugin(category, name)
        if plugin:
            return plugin.metadata()
        return None

