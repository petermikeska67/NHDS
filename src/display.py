"""Utilities for rendering scan results."""

from __future__ import annotations

from typing import Optional

from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

from .scanner import DeviceRecord, ScanResult


def _status_emoji(device: DeviceRecord) -> str:
    return "🟢" if device.online else "🔴"


def _format_latency(latency: Optional[float]) -> str:
    if latency is None:
        return "—"
    if latency >= 100:
        return f"{latency:.0f} ms"
    return f"{latency:.1f} ms"


def build_table(result: ScanResult) -> Table:
    """Build a rich table for the scan result."""
    table = Table(title=f"Network scan {result.network}", title_style="bold")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="magenta")
    table.add_column("MAC", style="yellow")
    table.add_column("Vendor", style="green")
    table.add_column("Latency", justify="right")
    table.add_column("Status", style="bold")

    for device in result.devices:
        hostname = device.hostname or "—"
        mac = device.mac or "—"
        vendor = device.vendor or "Unknown"
        latency = _format_latency(device.latency_ms)
        status = f"{_status_emoji(device)} {'Online' if device.online else 'Offline'}"
        table.add_row(device.ip, hostname, mac, vendor, latency, status)

    return table


def build_summary(result: ScanResult) -> Text:
    """Create a summary line with counts and duration."""
    online = sum(1 for device in result.devices if device.online)
    total = len(result.devices)
    summary = Text()
    summary.append(f"Hosts scanned: {total} • ")
    summary.append(f"Online: {online} • ")
    summary.append(f"Duration: {result.duration_s:.2f}s • ")
    summary.append(f"Started: {result.started_at.isoformat()}Z")
    return summary


def build_renderable(result: ScanResult) -> Group:
    """Return a composite renderable suitable for standard or live output."""
    return Group(build_table(result), build_summary(result))


def print_scan(result: ScanResult, console: Optional[Console] = None) -> None:
    """Print the scan results using the provided console."""
    console = console or Console()
    console.print(build_renderable(result))
