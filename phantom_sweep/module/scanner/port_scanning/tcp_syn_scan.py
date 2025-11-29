"""
TCP SYN Scan (Stealth) - Ultra-fast stateless port scanning
Fire all SYN packets at max rate, match responses by sequence number
"""
import asyncio
import time
from typing import Set, Tuple, Dict
from scapy.all import IP, TCP, AsyncSniffer, send, conf
from phantom_sweep.core.scan_context import ScanContext
from phantom_sweep.core.scan_result import ScanResult
from phantom_sweep.core.parsers import parse_port_spec, parse_exclude_ports
from phantom_sweep.module._base import ScannerBase

conf.verb = 0


class TCPSynScanner(ScannerBase):
    """TCP SYN Scan (Stealth) - Masscan-style ultra-fast scanning"""
    
    @property
    def name(self) -> str:
        return "stealth"
    
    @property
    def type(self) -> str:
        return "port_scanning"
    
    @property
    def description(self) -> str:
        return "TCP SYN Scan (stealth scan, ultra-fast)"
    
    def requires_root(self) -> bool:
        return True
    
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        """
        Perform TCP SYN scan on discovered hosts
        
        Reads:
        - result.get_discovered_hosts() - UP hosts from host discovery
        - context.ports - port configuration
        
        Writes:
        - result.hosts[host].tcp_ports[port].state
        """
        # Get UP hosts from host discovery phase
        up_hosts = result.get_discovered_hosts()
        if not up_hosts:
            if context.verbose:
                print("[*] No up hosts to scan")
            return
        
        # Parse ports
        ports = parse_port_spec(context.ports.port, context.ports.port_list)
        if context.ports.exclude_port:
            ports = parse_exclude_ports(context.ports.exclude_port, ports)
        
        if context.verbose:
            print(f"[*] Starting TCP SYN (Stealth) scan on {len(up_hosts)} hosts ({len(ports)} ports)...")
        
        try:
            asyncio.run(self._super_fast(context, result, up_hosts, ports))
        except Exception as e:
            if context.debug:
                print(f"[!] TCP SYN scan error: {e}")
    
    async def _super_fast(self, context: ScanContext, result: ScanResult, hosts: list , ports: list):
        open_ports : Dict[str,set[int]]={h: set() for h in hosts}
        seq_map={}

        bpf_filter="tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-rst) !=0"

        def handle_packet(pkt):
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                ack=pkt[TCP].ack
                if ack in seq_map:
                    host , port=seq_map[ack]
                    flags=pkt[TCP].flags

                    if flags==0x12:
                        open_ports[host].add(port)
                        del seq_map[ack]
                    elif flags & 0x4 ==0x4:
                        del seq_map[ack]
        sniffer= AsyncSniffer(filter=bpf_filter,prn=handle_packet,store=False)
        sniffer.start()
        await asyncio.sleep(0.05)

        start = time.time()
        seq = 0x10000
        packets = []


        for host in hosts:
            for port in ports:
                pkt=IP(dst=host)/TCP(dport=port,flags='S',seq=seq)
                packets.append(pkt)
                seq_map[seq+1]=(host,port)
                seq+=1

        BATCH_SIZE=1000
        for i in range(0,len(packets),BATCH_SIZE):
            batch=packets[i:i+BATCH_SIZE]
            send(batch,verbose=0,inter=0)
            await asyncio.sleep(0.001)

        send_time = time.time() - start
        
        sniffer.stop()
        
        # Add results
        for host in hosts:
            for port in ports:
                state = "open" if port in open_ports[host] else "closed"
                result.add_port(host, port, protocol="tcp", state=state)
        
        if context.verbose:
            total_open = sum(len(p) for p in open_ports.values())
            print(f"[*] Scan completed in {time.time()-start:.2f}s - {total_open} open ports")

