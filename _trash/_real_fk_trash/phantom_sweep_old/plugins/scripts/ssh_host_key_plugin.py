from argparse import ArgumentParser
import importlib
import inspect
import os
from typing import Dict, List
from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BasePlugin
from phantom_sweep.plugins.plugin_types import PluginType
import paramiko
import socket

class SshHostKey(BasePlugin):
    def name(self):
        return "ssh-host-key"
    
    def plugin_type(self):
        return PluginType.Analyze
    
    def register_cli(self, parse: ArgumentParser):
        return super().register_cli(parse)
    
    def _get_host_key(self, target: str, port: int = 22) -> Dict[str, any]:
        result = {}
        try:
            # https://stackoverflow.com/questions/31387466/get-host-key-of-an-ssh-server-in-base-64
            sock = socket.socket()
            sock.connect((target, port))
            trans = paramiko.transport.Transport(sock)
            trans.start_client()
            k = trans.get_remote_server_key()
            result['ssh-host-key'] = {}
            result['ssh-host-key']['name']          = k.name or ''
            result['ssh-host-key']['algorithm']     = k.algorithm_name or ''
            result['ssh-host-key']['bits']          = k.get_bits() or 0
            result['ssh-host-key']['fingerprint']   = k.get_fingerprint() or ''
            result['ssh-host-key']['host-key']      = k.get_base64() or ''

        except Exception as e:
            result['ssh-host-key']['error']         = f'Exception occurred: {str(e)}'
        return result
        
        

    def run(self, context: ScanContext, args):
        return super().run(context, args)
    