# network_probe/plugins/analysis/probe_parser.py
import re
from typing import List
from .probe_db_types import ServiceProbe, MatchRule

# Regex để phân tích một dòng 'Probe'
# Ví dụ: Probe TCP NULL q||
probe_line_re = re.compile(r"^Probe (\S+) (\S+) (.*)$")

# Regex để phân tích một dòng 'match'
# Ví dụ: match ssh m|^SSH-2\.0-([^\s]+)| p/OpenSSH/ v/$1/
match_line_re = re.compile(
    # 1:match 2:service 3:delim 4:pattern 5:delim 6:flags 7:info
    r"^(match|softmatch) ([^ ]+) m(.)(.*)\3([is]*) ([pvioh]/.*)$"
)

# Regex để phân tích thông tin phiên bản
# Ví dụ: p/OpenSSH/ v/$1/ i/protocol $2/
version_info_re = re.compile(r"([pvioh])/(.*?)(?<!\\)/")

def _parse_nmap_regex(pattern_str: str, flags_str: str) -> re.Pattern:
    """ Chuyển đổi regex của Nmap (dạng bytes) sang regex của Python """
    flags = 0
    if "i" in flags_str:
        flags |= re.IGNORECASE
    if "s" in flags_str:
        flags |= re.DOTALL
    
    try:
        # Chuyển đổi chuỗi (string) đại diện cho bytes (ví dụ: '\x01')
        pattern_bytes = pattern_str.encode('latin-1').decode('unicode-escape').encode('latin-1')
    except Exception:
        # Trả về một regex không bao giờ khớp
        # === SỬA LỖI Ở ĐÂY ===
        return re.compile(b"NEVER_MATCH_THIS_INVALID_PATTERN", 0)

    try:
        # Biên dịch regex đã chuyển đổi
        return re.compile(pattern_bytes, flags)
    except re.error as e:
        # Lỗi! (ví dụ: unterminated set)
        # print(f"Cảnh báo: Bỏ qua regex không hợp lệ: {e}")
        # Trả về một regex không bao giờ khớp
        # === SỬA LỖI Ở ĐÂY ===
        return re.compile(b"NEVER_MATCH_THIS_INVALID_PATTERN", 0)

def _parse_version_info(info_str: str) -> dict:
    """ Phân tích chuỗi 'p/...' thành một dictionary """
    info = {}
    for match in version_info_re.finditer(info_str):
        key = match.group(1) # 'p', 'v', 'i', v.v.
        value = match.group(2)
        info[key] = value
    return info

def load_probe_database(filepath: str) -> List[ServiceProbe]:
    """
    Hàm chính: Đọc và phân tích file nmap-service-probes.
    """
    probes = []
    current_probe = None

    with open(filepath, 'r', encoding='latin-1') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue # Bỏ qua dòng trống hoặc comment

            # 1. Bắt đầu một probe mới
            if line.startswith("Probe "):
                if current_probe:
                    probes.append(current_probe)
                
                match = probe_line_re.match(line)
                if not match:
                    continue # Lỗi cú pháp probe
                
                proto, name, probe_str = match.groups()
                
                # 'q||' -> ''
                probe_str = probe_str[2:-1] 
                probe_bytes = probe_str.encode('latin-1').decode('unicode-escape').encode('latin-1')
                
                current_probe = ServiceProbe(
                    protocol=proto, 
                    name=name, 
                    probe_string=probe_bytes
                )
                continue

            # 2. Phân tích các dòng 'match'
            match_match = match_line_re.match(line)
            if match_match and current_probe:
                match_type, service, delim, pattern, flags, info = match_match.groups()
                
                rule = MatchRule(
                    service_name=service,
                    pattern=_parse_nmap_regex(pattern, flags),
                    version_info=_parse_version_info(info),
                    is_softmatch=(match_type == "softmatch")
                )
                current_probe.matches.append(rule)
                continue

            # 3. Phân tích các tham số khác
            if line.startswith("totalwaitms ") and current_probe:
                current_probe.totalwaitms = int(line.split()[1])
            
            if line.startswith("ports ") and current_probe:
                ports_str = line.split()[1]
                for p in ports_str.split(','):
                    if '-' in p:
                        start, end = map(int, p.split('-'))
                        current_probe.ports.update(range(start, end + 1))
                    else:
                        current_probe.ports.add(int(p))
            
            # (Thêm logic cho Exclude, tcpwrappedms, v.v. ở đây)

        # Đừng quên probe cuối cùng
        if current_probe:
            probes.append(current_probe)
            
    print(f"[+] Đã tải và phân tích {len(probes)} probe từ CSDL.")
    return probes