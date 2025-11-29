# PhantomSweep Pipeline Architecture

## Overview

The scan pipeline follows a **unified context-based architecture** where all modules (scanners, analyzers, reporters, scripts) communicate through a single `ScanContext` object.

## Architecture Principles

### 1. **Unified Data Flow Through ScanContext**

```
┌─────────────────────────────────────────────┐
│         ScanContext (Pipeline State)        │
├─────────────────────────────────────────────┤
│  • Input Config:                            │
│    - targets, ports, techniques             │
│    - performance, evasion, output config    │
│                                             │
│  • Pipeline Result:                         │
│    - context.result: ScanResult             │
│    - Populated progressively by each phase  │
│                                             │
│  • Helper Methods:                          │
│    - get_discovered_hosts()                 │
│    - get_alive_hosts_count()                │
│    - get_open_ports_count()                 │
└─────────────────────────────────────────────┘
```

### 2. **Pipeline Execution Flow**

```
Manager.run_scan(context)
├─ Initialize: context.result = ScanResult()
│
├─ Phase 1: Host Discovery
│  ├─ Read: context.targets.host
│  ├─ Process: ping_tech scanner
│  └─ Write: context.result.hosts[host].state = "up"/"down"
│
├─ Phase 2: Port Scanning
│  ├─ Read: context.result.hosts (only "up" hosts)
│  ├─ Read: context.ports configuration
│  ├─ Process: scan_tech scanner
│  └─ Write: context.result.hosts[host].tcp_ports[port].state
│
├─ Phase 3: Service Detection
│  ├─ Read: context.result.hosts[host].tcp_ports (open ports)
│  ├─ Process: service_detection_mode analyzer
│  └─ Write: context.result.hosts[host].tcp_ports[port].service
│
├─ Phase 4: OS Fingerprinting
│  ├─ Read: context.result.hosts[host]
│  ├─ Process: os_fingerprinting_mode analyzer
│  └─ Write: context.result.hosts[host].os
│
├─ Phase 5: Scripts
│  ├─ Read: context.result
│  ├─ Process: each script plugin
│  └─ Write: context.result.hosts[host].scripts
│
└─ Finalize: Update statistics, return context.result
```

## Key Components

### ScanContext

**File**: `phantom_sweep/core/scan_context.py`

```python
@dataclass
class ScanContext:
    # Input Configuration
    targets: TargetConfig              # What to scan
    ports: PortConfig                  # Which ports
    pipeline: PipelineConfig           # Techniques to use
    performance: PerformanceConfig     # Speed/stealth settings
    output: OutputConfig               # Output format

    # Pipeline State
    result: Optional[ScanResult] = None  # ← Unified data flow

    # Helper methods
    def get_discovered_hosts() -> List[str]     # Get UP hosts
    def get_alive_hosts_count() -> int          # Count UP hosts
    def get_open_ports_count() -> int           # Count open ports
```

**Key Principle**: `context.result` is the single source of truth for all pipeline phases.

### ScanResult

**File**: `phantom_sweep/core/scan_result.py`

```python
@dataclass
class ScanResult:
    hosts: Dict[str, HostInfo]  # Results by host

    # Each HostInfo contains:
    # - host: str
    # - state: str ("up", "down", "unknown")
    # - os: Optional[str]
    # - tcp_ports: Dict[int, PortInfo]
    # - udp_ports: Dict[int, PortInfo]
    # - scripts: Dict[str, Any]
```

### Module Interface

All scanner/analyzer modules implement the same interface:

```python
class ScannerBase(ABC):
    def scan(self, context: ScanContext, result: ScanResult) -> None:
        # IMPORTANT: result IS context.result
        # So you can also use: context.result
        pass

class AnalyzerBase(ABC):
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        # IMPORTANT: result IS context.result
        pass
```

**Note**: The `result` parameter in module methods is always `context.result`. This provides both explicit data flow and convenient direct access.

## Implementation Examples

### Example 1: Port Scanner Using Discovered Hosts

```python
# In scanner.scan(context, result):

# Method 1: Using context helper (recommended)
up_hosts = context.get_discovered_hosts()

# Method 2: Accessing context.result directly
up_hosts = [h for h in context.result.hosts.keys()
            if context.result.hosts[h].state == "up"]

# Scan and write results back
for host in up_hosts:
    for port in ports:
        state = perform_scan(host, port)
        context.result.add_port(host, port, state)
```

### Example 2: Service Detection Using Open Ports

```python
# In analyzer.analyze(context, result):

# Get open ports from previous phase
for host, host_info in context.result.hosts.items():
    for port, port_info in host_info.tcp_ports.items():
        if port_info.state == "open":
            service = detect_service(host, port)
            port_info.service = service
```

### Example 3: Script Accessing All Results

```python
# In script.run(context, result):

# Access complete scan results
for host, host_info in context.result.hosts.items():
    for port, port_info in host_info.tcp_ports.items():
        if port_info.state == "open":
            custom_check(host, port, port_info.service)
```

## Migration from Old Pattern

### ❌ Old Pattern (Anti-pattern)

```python
# Using temporary context attributes
context._result = result  # ← Hack!

# Scanner accessing it
if hasattr(context, '_result'):
    result = context._result
```

### ✅ New Pattern (Recommended)

```python
# Manager properly sets context.result
context.result = scan_result

# Scanner accesses it naturally
up_hosts = context.get_discovered_hosts()
# or
up_hosts = [h for h in context.result.hosts.keys()
            if context.result.hosts[h].state == "up"]
```

## Benefits of This Architecture

1. **Unified Data Flow**: All modules read/write through `context.result`
2. **Clear Dependencies**: Easy to see what each phase reads/writes
3. **Helper Methods**: `context.get_discovered_hosts()` etc. provide convenient access
4. **Type Safety**: `context.result` is properly typed as `ScanResult`
5. **No Hacks**: No temporary attributes, no special handling needed
6. **Extensible**: New plugins automatically get access to full pipeline state
7. **Testable**: Easy to mock context and verify data flow

## Adding New Phases

To add a new analysis phase:

1. Create analyzer class extending `AnalyzerBase`
2. Read from `context.result`
3. Write results to `context.result`
4. Register in `Manager._run_*` method
5. Add to pipeline config in `ScanContext`

Example:

```python
# new_analyzer.py
class VulnerabilityAnalyzer(AnalyzerBase):
    def analyze(self, context: ScanContext, result: ScanResult) -> None:
        # Read: open ports from result
        # Process: check for vulnerabilities
        # Write: store in result.hosts[host].scripts["vuln"]
        pass

# manager.py
def _run_vulnerability_analysis(self, context: ScanContext):
    analyzer = VulnerabilityAnalyzer()
    analyzer.analyze(context, context.result)
```

## Summary

-   **ScanContext** = Configuration + Pipeline State
-   **ScanResult** = Data container (attached to context)
-   **Modules** = Read/write through context.result
-   **Manager** = Orchestrates pipeline, maintains context
-   **No Hacks** = Clean, unified architecture
