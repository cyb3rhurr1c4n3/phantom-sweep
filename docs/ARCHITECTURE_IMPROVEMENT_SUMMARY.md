# ScanContext Architecture - Implementation Guide

## Problem Solved

**Before**: Logic truyền dữ liệu giữa phases chưa rõ ràng:

```python
# ❌ Cách cũ (Anti-pattern)
context._result = self.result  # Hack - cộng thuộc tính tạm vào context
if hasattr(context, '_result'):
    result = context._result   # Check lại - chẳng được gì
```

**After**: Unified architecture qua `ScanContext.result`:

```python
# ✅ Cách mới (Proper Design)
context.result = scan_result   # Manager gán result vào context lần đầu
# Tất cả modules đều nhìn context.result mà không cần check/hack gì
```

## Core Architecture

### 1. ScanContext Structure

**File**: `phantom_sweep/core/scan_context.py`

```python
@dataclass
class ScanContext:
    # ========== INPUT CONFIGURATION ==========
    targets: TargetConfig               # What to scan (hosts, excludes)
    ports: PortConfig                   # Which ports (ranges, excludes)
    pipeline: PipelineConfig            # Techniques (ping_tech, scan_tech, etc)
    performance: PerformanceConfig      # Speed/stealth (rate, threads, timeout)
    output: OutputConfig                # Output format (json, xml, etc)

    # ========== PIPELINE STATE ==========
    result: Optional[ScanResult] = None # ← Unified access to all phases

    # ========== HELPER METHODS ==========
    def get_discovered_hosts() -> List[str]      # Get UP hosts from result
    def get_alive_hosts_count() -> int           # Count UP hosts
    def get_open_ports_count() -> int            # Count open ports

    # ========== GLOBAL FLAGS ==========
    verbose: bool = False
    debug: bool = False
    open_only: bool = True
```

### 2. Pipeline Execution in Manager

**File**: `phantom_sweep/module/manager.py`

```python
def run_scan(self, context: ScanContext) -> ScanResult:
    # 1. Initialize result
    self.result = ScanResult()
    context.result = self.result  # ← Attach result to context

    # 2. All phases use context.result directly
    self._run_host_discovery(context)      # Reads targets, writes result
    self._run_port_scanning(context)       # Reads result hosts, writes ports
    self._run_service_detection(context)   # Reads open ports, writes services
    self._run_os_fingerprinting(context)   # Reads ports, writes OS
    self._run_scripts(context)             # Reads result, writes scripts

    return context.result
```

### 3. Module Implementation Pattern

All scanner/analyzer modules follow this pattern:

```python
class MyScanner(ScannerBase):
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        # Note: result == context.result (same object)

        # Read data from previous phases
        if context.result:  # or result (same thing)
            up_hosts = context.get_discovered_hosts()
        else:
            up_hosts = context.targets.host

        # Process
        for host in up_hosts:
            for port in ports:
                state = perform_scan(host, port)
                context.result.add_port(host, port, state)
```

## Implementation Details

### Phase 1: Host Discovery

```python
# Manager initialization
context.result = ScanResult()  # Empty result

# Discovery phase
# - Reads: context.targets.host (all targets)
# - Writes: context.result.add_host(host, state="up")
# Result: context.result has hosts with state "up" or "down"
```

Example:

```python
def scan(self, context, result):
    for host in context.targets.host:
        if ping_response(host):
            context.result.add_host(host, state="up")
        else:
            context.result.add_host(host, state="down")
```

### Phase 2: Port Scanning

```python
# Port scanning phase uses context helper
up_hosts = context.get_discovered_hosts()  # Gets hosts with state="up"

# Scans only UP hosts
for host in up_hosts:
    for port in ports:
        state = tcp_connect(host, port)
        context.result.add_port(host, port, state)
```

### Phase 3: Service Detection

```python
# Service detection phase
for host, host_info in context.result.hosts.items():
    for port, port_info in host_info.tcp_ports.items():
        if port_info.state == "open":
            service = detect_service(host, port)
            port_info.service = service
```

### Phase 4-5: OS Fingerprinting & Scripts

Similar pattern - read from `context.result`, process, write back.

## Key Methods in ScanContext

### `get_discovered_hosts() -> List[str]`

Returns list of UP hosts from host discovery phase.

```python
# Instead of manually filtering:
# up_hosts = [h for h in context.result.hosts.keys()
#             if context.result.hosts[h].state == "up"]

# Just use:
up_hosts = context.get_discovered_hosts()
```

### `get_alive_hosts_count() -> int`

Count of discovered UP hosts.

```python
count = context.get_alive_hosts_count()
```

### `get_open_ports_count() -> int`

Count of discovered open ports.

```python
count = context.get_open_ports_count()
```

## Updates Made

### 1. ScanContext Enhancement

-   Added `result: Optional[ScanResult]` field
-   Added helper methods for common operations
-   Clear separation of config vs. state

### 2. Manager Updates

-   `context.result = self.result` in `run_scan()`
-   All phase methods use `context.result` consistently
-   Removed `context._result` hack

### 3. Port Scanner Updates

-   `tcp_connect_scan.py`: Uses `context.get_discovered_hosts()`
-   `tcp_syn_scan.py`: Uses `context.get_discovered_hosts()`
-   `udp_scan.py`: Uses `context.get_discovered_hosts()`
-   All cleanly read from `context.result`

### 4. Documentation

-   Created `docs/PIPELINE_ARCHITECTURE.md` with full design docs

## Benefits

1. **Clear Data Flow**: All data flows through `context.result`
2. **No Magic**: No temporary attributes or hacks
3. **Type Safe**: `context.result` is properly typed
4. **Convenient**: Helper methods like `get_discovered_hosts()`
5. **Extensible**: Easy to add new phases
6. **Testable**: Easy to mock context and verify behavior
7. **Self-Documenting**: Module signature clearly shows what it does

## Migration Checklist

For existing custom plugins:

-   [ ] Change `context.targets.host` to `context.get_discovered_hosts()` in port scanners
-   [ ] Change `context._result` to `context.result`
-   [ ] Add comments about what phase reads/writes
-   [ ] Test that data flows through properly

## Example: Adding New Plugin

```python
# my_analyzer.py
class VulnAnalyzer(AnalyzerBase):
    @property
    def name(self):
        return "vuln_check"

    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        """Check for known vulnerabilities"""
        # Read: open ports from result
        for host, host_info in context.result.hosts.items():
            for port, port_info in host_info.tcp_ports.items():
                if port_info.state == "open":
                    vuln = check_vulnerabilities(host, port, port_info.service)
                    if not host_info.scripts:
                        host_info.scripts = {}
                    host_info.scripts["vulnerabilities"] = vuln

# manager.py - Add to run_scan()
def _run_vulnerability_analysis(self, context):
    analyzer = VulnAnalyzer()
    analyzer.analyze(context, context.result)
```

Done! The architecture is now clean, unified, and extensible.
