import asyncio
import random
import socket
from typing import Dict, List, Tuple

from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import send

from phantom_sweep.core.context import ScanContext
from phantom_sweep.plugins.base_plugin import BaseScanner
from phantom_sweep.plugins.scanners.async_raw_engine import (
    AsyncRawTransceiver,
    ProbeSpec,
    derive_listen_window,
    derive_rate_limit,
)

from phantom_sweep.core.constants import FAST_SCAN_PORTS

class TCPScanner(BaseScanner):
    def __init__(self) -> None:
        self._rand = random.SystemRandom()

    def scan(self, targets: List[str], context: ScanContext, args=None) -> Dict[str,any]:
        ports = self._parse_port(context)
        resolved, errors = self._resolve_targets(targets)
        results: Dict[str, Dict[str, any]] = {t: {"ports": {}, "ip": ip} for t, ip in resolved}
        results.update(errors)
        if not resolved or not ports:
            return results
        asyncio.run(self._run_connect(resolved, ports, results, context))
        return results

    def _parse_port(self, context: ScanContext)-> List[int]:
        ports=set()
        if context.scan_all_ports:
            return list(range(1,65536))
        if context.fast_scan:
            return FAST_SCAN_PORTS
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
                errors[target] = {"error": f"Không thể phân giải tên miền {target}", "ports": {}}
                continue
            resolved.append((target, ip_addr))
        return resolved, errors

    async def _run_connect(
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
        observed = set()

        for target, ip_addr in resolved:
            for port in ports:
                sport = self._random_port()
                key = (ip_addr, sport)
                while key in metadata:
                    sport = self._random_port()
                    key = (ip_addr, sport)
                seq = self._rand.getrandbits(32)
                packet = IP(dst=ip_addr) / TCP(dport=port, sport=sport, flags="S", seq=seq)
                metadata[key] = {
                    "target": target,
                    "port": port,
                    "ip": ip_addr,
                    "sport": sport,
                    "seq": seq,
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
                target = meta["target"]
                port = meta["port"]
                ttl = pkt[IP].ttl
                window = pkt[TCP].window
                if flags & 0x12 == 0x12:
                    observed.add((target, port))
                    self._complete_handshake(meta, pkt)
                    results[target]["ports"][port] = {
                        "state": "open",
                        "service": "unknown",
                        "reason": "3-way-handshake",
                        "ttl": ttl,
                        "window": window,
                        "latency_ms": round(latency * 1000, 2),
                    }
                elif flags & 0x04:
                    observed.add((target, port))
                    results[target]["ports"][port] = {
                        "state": "closed",
                        "service": "unknown",
                        "reason": "rst",
                        "ttl": ttl,
                        "window": window,
                        "latency_ms": round(latency * 1000, 2),
                    }
                return

            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                if icmp.type != 3:
                    return
                inner = icmp.payload
                if not inner or not inner.haslayer(IP) or not inner.haslayer(TCP):
                    return
                key = (inner[IP].dst, inner[TCP].sport)
                meta = metadata.get(key)
                if not meta:
                    return
                latency = trx.pop_latency(key)
                if latency is None:
                    return
                target = meta["target"]
                port = meta["port"]
                observed.add((target, port))
                results[target]["ports"][port] = {
                    "state": "filtered",
                    "service": "unknown",
                    "reason": f"icmp-code-{icmp.code}",
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

        for meta in metadata.values():
            target = meta["target"]
            port = meta["port"]
            if (target, port) in observed:
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

    def _complete_handshake(self, meta: Dict[str, any], packet) -> None:
        ack_seq = packet[TCP].seq + 1
        local_seq = (meta["seq"] + 1) & 0xFFFFFFFF
        ip_dst = meta["ip"]
        sport = meta["sport"]
        dport = meta["port"]
        ack_pkt = IP(dst=ip_dst) / TCP(
            sport=sport,
            dport=dport,
            flags="A",
            seq=local_seq,
            ack=ack_seq,
        )
        rst_pkt = IP(dst=ip_dst) / TCP(
            sport=sport,
            dport=dport,
            flags="R",
            seq=local_seq,
            ack=ack_seq,
        )
        send(ack_pkt, verbose=0)
        send(rst_pkt, verbose=0)

    def _random_port(self) -> int:
        return self._rand.randint(1024, 65535)
