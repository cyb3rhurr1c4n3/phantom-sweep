from argparse import ArgumentParser
from typing import Dict
from network_probe.core.context import ScanContext
from network_probe.plugins.base_plugin import BasePlugin, BaseReport
from network_probe.plugins.plugin_types import PluginType


class NormalOutputPlugin(BasePlugin):
    def name(self)->str:
        return "output_normal"
    def register_cli(self, parse:ArgumentParser):
        output_group=parse.add_mutually_exclusive_group()
        output_group.add_argument(
            '-oN',
            action="store_true",
            help="Xuất output dưới dạng text"
        )

    def plugin_type(self)->PluginType:
        return PluginType.Output
    def run(self,context : ScanContext, args):
        if not args.output_normal:
            return
        filename = context.output_normal
        
        try:
            print(f"[*] Đang tạo báo cáo text tại: {filename}")
            
            # Lấy dữ liệu từ context
            tcp_results = context.get_data("scan_results") or {}
            udp_results = context.get_data("scan_results_udp") or {}
            
            # Lấy tất cả các target đã quét
            all_targets = set(tcp_results.keys()) | set(udp_results.keys())

            if not all_targets and context.scan_type == "ping_scan" and tcp_results:
                # Xử lý riêng cho ping scan
                report_content = self._generate_ping_scan_report(tcp_results)
            else:
                # Xử lý cho các loại scan khác
                report_content = self._generate_port_scan_report(context, all_targets, tcp_results, udp_results)

            # Ghi vào file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
                
            print(f"    [SUCCESS] Đã lưu báo cáo text thành công vào: {filename}")

        except Exception as e:
            print(f"    [ERROR] Lỗi khi lưu file báo cáo text {filename}: {e}")

    def _generate_ping_scan_report(self, tcp_results: dict) -> str:
        """Tạo báo cáo text đơn giản cho Ping Scan (-sn)."""
        report_lines = ["Kết quả Ping Scan:\n"]
        if not tcp_results:
            report_lines.append("Không tìm thấy host nào đang hoạt động.")
            return "\n".join(report_lines)

        for target, data in tcp_results.items():
            state = data.get("state", "down")
            if state == "up":
                report_lines.append(f"Host {target} is up")
        
        return "\n".join(report_lines)

    def _generate_port_scan_report(self, context: ScanContext, all_targets: set, tcp_results: dict, udp_results: dict) -> str:
        """Tạo báo cáo text chi tiết cho các scan cổng (TCP, UDP)."""
        
        report_lines = ["KẾT QUẢ QUÉT:\n"]
        
        if not all_targets:
            report_lines.append("Không tìm thấy mục tiêu nào.")
            return "\n".join(report_lines)

        show_service = context.service_version

        for target in sorted(list(all_targets)):
            report_lines.append("="*70)
            report_lines.append(f"Scan report for {target}")
            
            target_has_open_ports = False

            # === Xử lý TCP ===
            if target in tcp_results:
                tcp_data = tcp_results[target]
                if "error" in tcp_data:
                    report_lines.append(f"  Lỗi quét TCP: {tcp_data['error']}")
                
                ports_data = tcp_data.get("ports", {})
                if ports_data:
                    target_has_open_ports = True
                    report_lines.extend(self._format_port_table("TCP", ports_data, show_service))

            # === Xử lý UDP ===
            if target in udp_results:
                udp_data = udp_results[target]
                if "error" in udp_data:
                    report_lines.append(f"  Lỗi quét UDP: {udp_data['error']}")

                ports_data = udp_data.get("ports", {})
                if ports_data:
                    if target_has_open_ports: # Thêm dòng trống nếu cả TCP và UDP đều có
                        report_lines.append("")
                    
                    target_has_open_ports = True
                    report_lines.extend(self._format_port_table("UDP", ports_data, show_service))
            
            # === Xử lý OS ===
            if context.os_detection:
                os_guess = tcp_results.get(target, {}).get("os", None) 
                if os_guess:
                    report_lines.append(f"\n  OS Guess: {os_guess}")

            if not target_has_open_ports and context.scan_type != "ping_scan":
                report_lines.append(f"  Host is up, but no open ports/services were found.")

            report_lines.append("\n") # Dòng trống giữa các target

        return "\n".join(report_lines)

    def _format_port_table(self, protocol: str, ports_data: dict, show_service: bool) -> list:
        """
        Hàm trợ giúp: Định dạng bảng cổng (TCP hoặc UDP) thành danh sách các dòng text.
        (Đây là phiên bản không màu của hàm _print_port_table trong SkyViewCLI)
        """
        lines = []
        
        # Xây dựng tiêu đề động
        header = f"  {'PORT':<12} {'STATE':<15}"
        line = f"  {'----':<12} {'-----':<15}"
        
        if show_service:
            header += f" {'SERVICE':<20}"
            line += f" {'-------':<20}"
            
        lines.append(header)
        lines.append(line)

        # Lặp qua các cổng và in
        for port, details in sorted(ports_data.items()):
            state = details.get("state", "unknown")
            service = details.get("service", "unknown")
            port_str = f"{port}/{protocol.lower()}"
                
            row = f"  {port_str:<12} {state:<15}"
            
            if show_service:
                row += f" {service:<20}"
                
            lines.append(row)
            
        return lines