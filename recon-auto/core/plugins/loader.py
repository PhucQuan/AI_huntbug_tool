import os
import importlib
import inspect
from rich.console import Console
from .base import BasePlugin

console = Console()

class PluginLoader:
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = {}

    def load_all(self) -> dict:
        """Auto-discovers and registers plugins."""
        if not os.path.exists(self.plugin_dir):
            console.print(f"[!] Plugin directory {self.plugin_dir} not found.")
            return self.plugins

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and filename != "__init__.py":
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(f"{self.plugin_dir}.{module_name}")
                    for name, obj in inspect.getmembers(module):
                        if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj != BasePlugin:
                            instance = obj()
                            self.plugins[instance.name] = instance
                            console.print(f"[✓] Loaded plugin: {instance.name} v{instance.version}")
                except Exception as e:
                    console.print(f"[!] Error loading plugin {module_name}: {e}")
        return self.plugins

    def load_by_stage(self, stage: str) -> list:
        """Fetch plugins tailored for a specific stage."""
        return [p for p in self.plugins.values() if p.stage == stage]

    def get_plugin(self, name: str):
        """Fetch a specific plugin by name."""
        return self.plugins.get(name)
