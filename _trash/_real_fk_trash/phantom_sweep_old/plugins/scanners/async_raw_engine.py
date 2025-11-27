import asyncio
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Iterable, Optional, Set, Tuple

from scapy.config import conf
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer, send, sendp


@dataclass
class ProbeSpec:
    packet: Packet
    key: Tuple
    use_layer2: bool = False


class AsyncRawTransceiver:
    """
    Helper that mimics Masscan's sender/receiver workflow.
    Sender: blasts crafted packets with rate limiting.
    Receiver: background AsyncSniffer feeding packets to the supplied handler.
    """

    def __init__(
        self,
        rate_limit: int = 2000,
        listen_window: float = 1.0,
        iface: Optional[str] = None,
    ) -> None:
        self.rate_limit = max(1, rate_limit)
        self.listen_window = max(0.1, listen_window)
        self.iface = iface or conf.iface
        self._pending: Dict[Tuple, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    async def sweep(
        self,
        probes: Iterable[ProbeSpec],
        handler: Callable[[Packet, "AsyncRawTransceiver"], None],
        bpf_filter: Optional[str] = None,
        listen_window: Optional[float] = None,
    ) -> None:
        window = listen_window if listen_window is not None else self.listen_window
        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=bpf_filter,
            store=False,
            prn=lambda pkt: handler(pkt, self),
        )
        sniffer.start()
        try:
            await self._send_loop(probes)
            await asyncio.sleep(window)
        finally:
            try:
                sniffer.stop()
            finally:
                sniffer.join()

    async def _send_loop(self, probes: Iterable[ProbeSpec]) -> None:
        interval = 1.0 / self.rate_limit
        for probe in probes:
            self._record_send(probe.key)
            if probe.use_layer2:
                sendp(probe.packet, verbose=0, iface=self.iface)
            else:
                send(probe.packet, verbose=0, iface=self.iface)
            await asyncio.sleep(interval)

    def _record_send(self, key: Tuple) -> None:
        with self._lock:
            self._pending[key].append(time.perf_counter())

    def pop_latency(self, key: Tuple) -> Optional[float]:
        with self._lock:
            queue = self._pending.get(key)
            if not queue:
                return None
            sent_at = queue.popleft()
        return time.perf_counter() - sent_at

    def pending_keys(self) -> Set[Tuple]:
        with self._lock:
            return {key for key, queue in self._pending.items() if queue}


def derive_rate_limit(timing: int) -> int:
    mapping = {
        0: 50,
        1: 150,
        2: 500,
        3: 2000,
        4: 8000,
        5: 20000,
    }
    return mapping.get(timing, 2000)


def derive_listen_window(timeout: float) -> float:
    return max(0.5, timeout * 1.5)

