# Dynamic Network Scanner

A dynamic, async network scanner designed for **authorized** inventories and security diagnostics.

## Why this scanner is different

This app scans in an adaptive way:

1. **Discovery-first pipeline**: It probes hosts with configurable discovery ports to identify live targets quickly.
2. **Dynamic prioritization**: It scans responsive hosts first (using measured discovery latency), reducing time-to-first-results.
3. **Built-in utility outputs**: Reverse DNS enrichment, optional banner grabbing, and risk scoring are included in one run.
4. **Export-ready reports**: JSON and CSV output formats are supported for downstream workflows.

## Features

- CIDR, hostname, and single-IP targets
- Async host and port concurrency controls
- Configurable host discovery ports
- Optional banner grabbing
- Exposure/risk scoring heuristics
- JSON and CSV report exports

## Usage

```bash
python3 dynamic_network_scanner/scanner.py 192.168.1.0/24 --banners --json-out report.json --csv-out report.csv
```

### More examples

```bash
# Single host with focused ports
python3 dynamic_network_scanner/scanner.py 10.0.0.15 --ports 22,80,443,3389

# Hostname target with tighter timeout
python3 dynamic_network_scanner/scanner.py myserver.internal --timeout 0.5 --port-concurrency 128
```

## Safety

Use this tool only on networks and systems you own or have explicit permission to assess.
