#!/usr/bin/env python3
"""Dynamic Network Scanner

A high-signal network scanner for inventory and diagnostics on networks you own
or have explicit permission to assess.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

DEFAULT_DISCOVERY_PORTS = (22, 53, 80, 443)
DEFAULT_SCAN_PORTS = "21-23,53,80,110,123,135,139,143,443,445,587,993,995,1433,1521,1723,2049,2375,3306,3389,5432,5900,6379,8080,8443"


@dataclass(slots=True)
class PortResult:
    port: int
    state: str
    latency_ms: float
    banner: str = ""


@dataclass(slots=True)
class HostResult:
    host: str
    discovery_latency_ms: float
    dns_name: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    closed_ports: int = 0
    filtered_ports: int = 0
    risk_score: int = 0
    risk_notes: list[str] = field(default_factory=list)


def parse_ports(spec: str) -> list[int]:
    """Parse comma-separated ports and ranges into sorted unique list."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                raise ValueError(f"Invalid range: {chunk}")
            for port in range(start, end + 1):
                _validate_port(port)
                ports.add(port)
        else:
            port = int(chunk)
            _validate_port(port)
            ports.add(port)

    if not ports:
        raise ValueError("At least one port must be provided")
    return sorted(ports)


def _validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(f"Invalid port {port}: must be 1-65535")


def expand_targets(target: str, max_hosts: int) -> list[str]:
    """Expand a target expression into hosts.

    Supported forms:
      * CIDR: 192.168.1.0/24
      * IP address: 10.0.0.4
      * Hostname: scanme.local
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        if len(hosts) > max_hosts:
            raise ValueError(
                f"Target expands to {len(hosts)} hosts, over --max-hosts={max_hosts}"
            )
        return hosts
    except ValueError:
        pass

    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        return [socket.gethostbyname(target)]


async def probe_host(host: str, ports: Iterable[int], timeout: float) -> tuple[bool, float]:
    """Determine host reachability via short TCP probes.

    Treats connection-refused as host-up because the target stack responded.
    """
    start = time.perf_counter()
    for port in ports:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            elapsed = (time.perf_counter() - start) * 1000
            return True, elapsed
        except ConnectionRefusedError:
            elapsed = (time.perf_counter() - start) * 1000
            return True, elapsed
        except (asyncio.TimeoutError, OSError):
            continue
    elapsed = (time.perf_counter() - start) * 1000
    return False, elapsed


async def scan_port(host: str, port: int, timeout: float, grab_banners: bool) -> PortResult:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        latency_ms = (time.perf_counter() - start) * 1000
        banner = ""
        if grab_banners:
            try:
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(128), timeout=0.6)
                banner = data.decode("utf-8", "ignore").strip()
            except (asyncio.TimeoutError, OSError):
                banner = ""
        writer.close()
        await writer.wait_closed()
        return PortResult(port=port, state="open", latency_ms=latency_ms, banner=banner)
    except ConnectionRefusedError:
        latency_ms = (time.perf_counter() - start) * 1000
        return PortResult(port=port, state="closed", latency_ms=latency_ms)
    except (asyncio.TimeoutError, OSError):
        latency_ms = (time.perf_counter() - start) * 1000
        return PortResult(port=port, state="filtered", latency_ms=latency_ms)


def assess_risk(open_ports: list[int]) -> tuple[int, list[str]]:
    score = 0
    notes: list[str] = []

    rules = [
        ({21, 23, 445, 3389, 5900, 2375}, 30, "Potentially high-risk remote/admin surface exposed."),
        ({1433, 1521, 3306, 5432, 6379}, 25, "Database services visible; verify segmentation and authentication."),
        ({80, 8080, 8443, 443}, 10, "Web services visible; ensure patching and TLS hygiene."),
        ({53}, 10, "DNS exposed; confirm recursion policy and access restrictions."),
    ]

    opened = set(open_ports)
    for covered, points, message in rules:
        if opened.intersection(covered):
            score += points
            notes.append(message)

    if len(open_ports) >= 20:
        score += 20
        notes.append("Large exposed service surface detected.")

    return min(score, 100), notes


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float,
    concurrency: int,
    grab_banners: bool,
    discovery_latency_ms: float,
) -> HostResult:
    sem = asyncio.Semaphore(concurrency)

    async def _job(port: int) -> PortResult:
        async with sem:
            return await scan_port(host, port, timeout=timeout, grab_banners=grab_banners)

    results = await asyncio.gather(*(_job(port) for port in ports))

    open_ports = [result for result in results if result.state == "open"]
    closed = sum(result.state == "closed" for result in results)
    filtered = sum(result.state == "filtered" for result in results)

    try:
        dns_name, _, _ = socket.gethostbyaddr(host)
    except OSError:
        dns_name = ""

    risk_score, risk_notes = assess_risk([p.port for p in open_ports])

    return HostResult(
        host=host,
        discovery_latency_ms=round(discovery_latency_ms, 2),
        dns_name=dns_name,
        open_ports=sorted(open_ports, key=lambda p: p.port),
        closed_ports=closed,
        filtered_ports=filtered,
        risk_score=risk_score,
        risk_notes=risk_notes,
    )


async def run_scan(args: argparse.Namespace) -> list[HostResult]:
    targets = expand_targets(args.target, args.max_hosts)
    discovery_ports = parse_ports(args.discovery_ports)
    scan_ports = parse_ports(args.ports)

    discovered: list[tuple[str, float]] = []
    for host in targets:
        alive, latency = await probe_host(host, discovery_ports, timeout=args.timeout)
        if alive:
            discovered.append((host, latency))

    # Dynamic sequencing: scan most responsive hosts first.
    discovered.sort(key=lambda item: item[1])

    if not discovered:
        return []

    host_sem = asyncio.Semaphore(args.host_concurrency)

    async def _scan_job(host: str, latency: float) -> HostResult:
        async with host_sem:
            return await scan_host(
                host,
                scan_ports,
                timeout=args.timeout,
                concurrency=args.port_concurrency,
                grab_banners=args.banners,
                discovery_latency_ms=latency,
            )

    jobs = [_scan_job(host, latency) for host, latency in discovered]
    return await asyncio.gather(*jobs)


def render_console(results: list[HostResult]) -> None:
    if not results:
        print("No reachable hosts discovered.")
        return

    print(f"Discovered {len(results)} reachable hosts\n")
    for host in results:
        header = f"{host.host}"
        if host.dns_name:
            header += f" ({host.dns_name})"
        print(header)
        print(f"  Discovery latency: {host.discovery_latency_ms:.2f} ms")
        print(f"  Open ports: {len(host.open_ports)} | Closed: {host.closed_ports} | Filtered: {host.filtered_ports}")
        if host.open_ports:
            for port in host.open_ports:
                banner_suffix = f" | banner: {port.banner}" if port.banner else ""
                print(f"    - {port.port}/tcp open ({port.latency_ms:.2f} ms){banner_suffix}")
        print(f"  Risk score: {host.risk_score}/100")
        for note in host.risk_notes:
            print(f"    * {note}")
        print()


def write_json(results: list[HostResult], path: Path) -> None:
    payload = []
    for host in results:
        item = asdict(host)
        item["open_ports"] = [asdict(port) for port in host.open_ports]
        payload.append(item)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(results: list[HostResult], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "host",
                "dns_name",
                "port",
                "state",
                "latency_ms",
                "banner",
                "risk_score",
            ]
        )
        for host in results:
            if not host.open_ports:
                writer.writerow([host.host, host.dns_name, "", "", "", "", host.risk_score])
                continue
            for port in host.open_ports:
                writer.writerow(
                    [
                        host.host,
                        host.dns_name,
                        port.port,
                        port.state,
                        f"{port.latency_ms:.2f}",
                        port.banner,
                        host.risk_score,
                    ]
                )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Dynamic network scanner with host-adaptive ordering, banner collection, "
            "and risk scoring. Use only on authorized networks."
        )
    )
    parser.add_argument("target", help="CIDR, IP, or hostname")
    parser.add_argument("--ports", default=DEFAULT_SCAN_PORTS, help="Ports to scan (e.g. 22,80,8000-8100)")
    parser.add_argument("--discovery-ports", default="22,80,443", help="Ports used for host discovery")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout per connection in seconds")
    parser.add_argument("--max-hosts", type=int, default=1024, help="Maximum hosts allowed after expansion")
    parser.add_argument("--host-concurrency", type=int, default=128, help="Concurrent host scans")
    parser.add_argument("--port-concurrency", type=int, default=256, help="Concurrent port probes per host")
    parser.add_argument("--banners", action="store_true", help="Attempt lightweight banner grabbing on open ports")
    parser.add_argument("--json-out", type=Path, help="Write JSON report to path")
    parser.add_argument("--csv-out", type=Path, help="Write CSV report to path")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    results = asyncio.run(run_scan(args))
    render_console(results)

    if args.json_out:
        write_json(results, args.json_out)
        print(f"JSON report written to {args.json_out}")

    if args.csv_out:
        write_csv(results, args.csv_out)
        print(f"CSV report written to {args.csv_out}")


if __name__ == "__main__":
    main()
