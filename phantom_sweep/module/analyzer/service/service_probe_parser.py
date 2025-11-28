"""
Service Probe Database Parser
Parses Nmap-style service-probes database for service detection
"""
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class ServiceMatch:
    """Represents a service match pattern"""
    service_name: str
    pattern: bytes
    version_info: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Compile regex pattern"""
        try:
            self.compiled_pattern = re.compile(self.pattern, re.DOTALL | re.IGNORECASE)
        except:
            self.compiled_pattern = None


@dataclass
class ServiceProbe:
    """Represents a service probe"""
    protocol: str  # TCP or UDP
    probe_name: str
    probe_string: bytes
    matches: List[ServiceMatch] = field(default_factory=list)
    softmatches: List[ServiceMatch] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    ssl_ports: List[int] = field(default_factory=list)
    totalwaitms: int = 5000
    tcpwrappedms: int = 3000
    rarity: int = 1


class ServiceProbeParser:
    """Parser for Nmap service-probes database"""
    
    def __init__(self):
        self.probes: List[ServiceProbe] = []
        self.probe_by_name: Dict[str, ServiceProbe] = {}
        
    def parse_file(self, filepath: str) -> None:
        """Parse service-probes database file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.parse_content(content)
        except Exception as e:
            print(f"[!] Error parsing service probes file: {e}")
    
    def parse_content(self, content: str) -> None:
        """Parse service-probes database content"""
        lines = content.split('\n')
        current_probe = None
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse Probe directive
            if line.startswith('Probe '):
                if current_probe:
                    self.probes.append(current_probe)
                    self.probe_by_name[current_probe.probe_name] = current_probe
                current_probe = self._parse_probe_line(line)
            
            # Parse match directive
            elif line.startswith('match ') and current_probe:
                match = self._parse_match_line(line)
                if match:
                    current_probe.matches.append(match)
            
            # Parse softmatch directive
            elif line.startswith('softmatch ') and current_probe:
                match = self._parse_match_line(line, is_softmatch=True)
                if match:
                    current_probe.softmatches.append(match)
            
            # Parse ports directive
            elif line.startswith('ports ') and current_probe:
                ports = self._parse_ports_line(line)
                current_probe.ports.extend(ports)
            
            # Parse sslports directive
            elif line.startswith('sslports ') and current_probe:
                ports = self._parse_ports_line(line)
                current_probe.ssl_ports.extend(ports)
            
            # Parse totalwaitms directive
            elif line.startswith('totalwaitms ') and current_probe:
                try:
                    current_probe.totalwaitms = int(line.split()[1])
                except:
                    pass
            
            # Parse tcpwrappedms directive
            elif line.startswith('tcpwrappedms ') and current_probe:
                try:
                    current_probe.tcpwrappedms = int(line.split()[1])
                except:
                    pass
            
            # Parse rarity directive
            elif line.startswith('rarity ') and current_probe:
                try:
                    current_probe.rarity = int(line.split()[1])
                except:
                    pass
        
        # Add last probe
        if current_probe:
            self.probes.append(current_probe)
            self.probe_by_name[current_probe.probe_name] = current_probe
    
    def _parse_probe_line(self, line: str) -> Optional[ServiceProbe]:
        """Parse Probe directive line"""
        # Format: Probe <protocol> <probename> <probestring>
        try:
            parts = line.split(None, 2)
            if len(parts) < 3:
                return None
            
            protocol = parts[1]
            rest = parts[2]
            
            # Extract probe name and probe string
            # Format: probename q|probestring|
            match = re.match(r'(\w+)\s+q\|([^|]*)\|', rest)
            if match:
                probe_name = match.group(1)
                probe_string_escaped = match.group(2)
                probe_string = self._unescape_string(probe_string_escaped)
                
                return ServiceProbe(
                    protocol=protocol,
                    probe_name=probe_name,
                    probe_string=probe_string
                )
        except Exception as e:
            pass
        
        return None
    
    def _parse_match_line(self, line: str, is_softmatch: bool = False) -> Optional[ServiceMatch]:
        """Parse match or softmatch directive line"""
        # Format: match <servicename> <pattern> [<versioninfo>]
        try:
            prefix = 'softmatch ' if is_softmatch else 'match '
            line = line[len(prefix):]
            
            # Extract service name
            parts = line.split(None, 1)
            if len(parts) < 2:
                return None
            
            service_name = parts[0]
            rest = parts[1]
            
            # Extract pattern (format: m|pattern|flags)
            pattern_match = re.match(r'm\|([^|]*)\|(\w*)', rest)
            if not pattern_match:
                return None
            
            pattern_str = pattern_match.group(1)
            flags = pattern_match.group(2)
            
            # Convert pattern to bytes
            pattern_bytes = self._unescape_pattern(pattern_str)
            
            # Parse version info
            version_info = self._parse_version_info(rest[pattern_match.end():])
            
            return ServiceMatch(
                service_name=service_name,
                pattern=pattern_bytes,
                version_info=version_info
            )
        except Exception as e:
            pass
        
        return None
    
    def _parse_ports_line(self, line: str) -> List[int]:
        """Parse ports or sslports directive"""
        try:
            parts = line.split(None, 1)
            if len(parts) < 2:
                return []
            
            port_str = parts[1]
            ports = []
            
            for part in port_str.split(','):
                part = part.strip()
                if '-' in part:
                    # Range
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    # Single port
                    ports.append(int(part))
            
            return ports
        except:
            return []
    
    def _parse_version_info(self, info_str: str) -> Dict[str, str]:
        """Parse version info fields (p/product/ v/version/ i/info/ etc.)"""
        version_info = {}
        
        # Pattern: field_type/field_value/
        pattern = r'([pvihodcpe])/((?:[^/]|\\/)*)/'
        matches = re.finditer(pattern, info_str)
        
        field_map = {
            'p': 'product',
            'v': 'version',
            'i': 'info',
            'h': 'hostname',
            'o': 'os',
            'd': 'device_type',
            'cpe': 'cpe'
        }
        
        for match in matches:
            field_type = match.group(1)
            field_value = match.group(2)
            
            # Unescape the value
            field_value = field_value.replace('\\/', '/')
            
            key = field_map.get(field_type, field_type)
            version_info[key] = field_value
        
        return version_info
    
    def _unescape_string(self, s: str) -> bytes:
        """Unescape probe string (handle \\r, \\n, \\x00, etc.)"""
        result = []
        i = 0
        while i < len(s):
            if s[i] == '\\' and i + 1 < len(s):
                next_char = s[i + 1]
                if next_char == 'r':
                    result.append(ord('\r'))
                    i += 2
                elif next_char == 'n':
                    result.append(ord('\n'))
                    i += 2
                elif next_char == 't':
                    result.append(ord('\t'))
                    i += 2
                elif next_char == '0':
                    result.append(0)
                    i += 2
                elif next_char == 'x' and i + 3 < len(s):
                    # Hex escape: \xNN
                    try:
                        hex_value = int(s[i+2:i+4], 16)
                        result.append(hex_value)
                        i += 4
                    except:
                        result.append(ord(s[i]))
                        i += 1
                elif next_char == '\\':
                    result.append(ord('\\'))
                    i += 2
                else:
                    result.append(ord(next_char))
                    i += 2
            else:
                result.append(ord(s[i]))
                i += 1
        
        return bytes(result)
    
    def _unescape_pattern(self, s: str) -> bytes:
        """Unescape regex pattern for matching"""
        return self._unescape_string(s)
    
    def get_probes_for_port(self, port: int, protocol: str = "TCP") -> List[ServiceProbe]:
        """Get applicable probes for a specific port"""
        applicable_probes = []
        
        for probe in self.probes:
            if probe.protocol.upper() != protocol.upper():
                continue
            
            # Check if port is in probe's port list (or if no port list specified)
            if not probe.ports or port in probe.ports:
                applicable_probes.append(probe)
        
        # Sort by rarity (lower rarity = more common = try first)
        applicable_probes.sort(key=lambda p: p.rarity)
        
        return applicable_probes
    
    def match_response(self, response: bytes, probes: List[ServiceProbe]) -> Optional[Tuple[str, Dict[str, str], int]]:
        """
        Match response against probe patterns
        
        Returns:
            Tuple of (service_name, version_info, confidence) or None
        """
        # Try exact matches first
        for probe in probes:
            for match in probe.matches:
                if match.compiled_pattern and match.compiled_pattern.search(response):
                    # Extract version info with capture groups
                    version_info = self._extract_version_info(
                        match.compiled_pattern,
                        response,
                        match.version_info
                    )
                    return (match.service_name, version_info, 100)
        
        # Try soft matches
        for probe in probes:
            for match in probe.softmatches:
                if match.compiled_pattern and match.compiled_pattern.search(response):
                    version_info = self._extract_version_info(
                        match.compiled_pattern,
                        response,
                        match.version_info
                    )
                    return (match.service_name, version_info, 70)
        
        return None
    
    def _extract_version_info(
        self, compiled_pattern: re.Pattern, response: bytes, version_template: Dict[str, str]
    ) -> Dict[str, str]:
        """Extract version information using regex capture groups"""
        result = {}
        match_obj = compiled_pattern.search(response)
        
        if not match_obj:
            return version_template.copy()
        
        groups = match_obj.groups()
        
        # Substitute $1, $2, etc. in version template
        for key, template_value in version_template.items():
            value = template_value
            for i, group in enumerate(groups, 1):
                if group:
                    try:
                        group_str = group.decode('utf-8', errors='ignore')
                        value = value.replace(f'${i}', group_str)
                    except:
                        pass
            result[key] = value
        
        return result


# Singleton instance
_parser_instance = None

def get_service_probe_parser() -> ServiceProbeParser:
    """Get singleton parser instance"""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = ServiceProbeParser()
    return _parser_instance