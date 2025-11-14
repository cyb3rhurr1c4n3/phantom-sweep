import asyncio
import random
import socket
from typing import Dict, List, Tuple

from scapy.layers.inet import ICMP, IP, TCP

from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BaseScanner
from network_probe.plugins.scanners.async_raw_engine import (
    AsyncRawTransceiver,
    ProbeSpec,
    derive_listen_window,
    derive_rate_limit,
)

Fast_Scan_Port=[7, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3268, 3269, 3389, 5900, 8080, 8443, 1025, 1026, 1027, 1028, 1029, 1030,
    113, 199, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    902, 1080, 1099, 123, 137, 138, 161, 162, 177, 1720, 2000, 2049, 2121,
    2717, 3000, 3128, 3478, 3702, 49152, 49153, 49154, 49155, 49156, 49157,
    500, 5060, 5222, 5223, 5228, 5357, 5432, 5631, 5666, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8081, 8888, 9100, 9999, 10000, 32768, 49158,
    49159, 49160, 49161, 49162, 49163]

class SynScanner(BaseScanner):
    def __init__(self) -> None:
        self._rand = random.SystemRandom()

    def scan(self, targets: List[str], context: ScanContext, args=None) -> Dict[str,any]:
        ports = self._parse_port(context)
        resolved, errors = self._resolve_targets(targets)
        results: Dict[str, Dict[str, any]] = {t: {"ports": {}, "ip": ip} for t, ip in resolved}
        results.update(errors)
        if not resolved or not ports:
            return results
        asyncio.run(self._run_syn(resolved, ports, results, context))
        return results

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

    def _resolve_targets(
        self, targets: List[str]
    ) -> Tuple[List[Tuple[str, str]], Dict[str, Dict[str, any]]]:
        resolved: List[Tuple[str, str]] = []
        errors: Dict[str, Dict[str, any]] = {}
        for target in targets:
            try:
                ip_addr = socket.gethostbyname(target)
            except socket.gaierror:
                errors[target] = {"error": f"Không thể phân giải tên miền: {target}", "ports": {}}
                continue
            resolved.append((target, ip_addr))
        return resolved, errors

    async def _run_syn(
        self,
        resolved: List[Tuple[str, str]],
        ports: List[int],
        results: Dict[str, Dict[str, any]],
        context: ScanContext,
    ) -> None:
        rate = derive_rate_limit(context.timing)
        listener = derive_listen_window(context.timeout)
        engine = AsyncRawTransceiver(rate_limit=rate, listen_window=listener)

        probes: List[ProbeSpec] = []
        metadata: Dict[Tuple[str, int], Dict[str, any]] = {}
        observed_ports = set()

        for target, ip_addr in resolved:
            for port in ports:
                sport = self._random_port()
                key = (ip_addr, sport)
                while key in metadata:
                    sport = self._random_port()
                    key = (ip_addr, sport)
                packet = IP(dst=ip_addr)/TCP(dport=port, sport=sport, flags="S")
                metadata[key] = {
                    "target": target,
                    "port": port,
                    "ip": ip_addr,
                }
                probes.append(ProbeSpec(packet=packet, key=key))

        def handle(pkt, trx: AsyncRawTransceiver):
            if pkt.haslayer(TCP):
                src_ip = pkt[IP].src
                key = (src_ip, pkt[TCP].dport)
                meta = metadata.get(key)
                if not meta:
                    return
                latency = trx.pop_latency(key)
                if latency is None:
                    return
                flags = pkt[TCP].flags
                state = None
                reason = None
                if flags & 0x12 == 0x12:
                    state = "open"
                    reason = "syn-ack"
                elif flags & 0x04:
                    state = "closed"
                    reason = "rst"
                else:
                    state = "unknown"
                    reason = f"flags-{int(flags)}"
                if state:
                    target = meta["target"]
                    port = meta["port"]
                    observed_ports.add((target, port))
                    results[target]["ports"][port] = {
                        "state": state,
                        "service": "unknown",
                        "reason": reason,
                        "ttl": pkt[IP].ttl,
                        "window": pkt[TCP].window,
                        "latency_ms": round(latency * 1000, 2),
                    }
                return

            if pkt.haslayer(ICMP):
                layer = pkt[ICMP]
                if layer.type != 3:
                    return
                inner = layer.payload
                if not inner or not inner.haslayer(IP) or not inner.haslayer(TCP):
                    return
                ip_layer = inner[IP]
                tcp_layer = inner[TCP]
                key = (ip_layer.dst, tcp_layer.sport)
                meta = metadata.get(key)
                if not meta:
                    return
                latency = trx.pop_latency(key)
                if latency is None:
                    return
                target = meta["target"]
                port = meta["port"]
                observed_ports.add((target, port))
                results[target]["ports"][port] = {
                    "state": "filtered",
                    "service": "unknown",
                    "reason": f"icmp-code-{layer.code}",
                    "ttl": pkt[IP].ttl,
                    "window": None,
                    "latency_ms": round(latency * 1000, 2),
                }

        await engine.sweep(
            probes,
            handle,
            bpf_filter="tcp or icmp",
            listen_window=listener,
        )

        for key, meta in metadata.items():
            target = meta["target"]
            port = meta["port"]
            if (target, port) in observed_ports:
                continue
            if port not in results[target]["ports"]:
                results[target]["ports"][port] = {
                    "state": "filtered",
                    "service": "unknown",
                    "reason": "no-response",
                    "ttl": None,
                    "window": None,
                    "latency_ms": None,
                }

    def _random_port(self) -> int:
        return self._rand.randint(1024, 65535)