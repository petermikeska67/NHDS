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
    table.add_column("Name", style="white")
    table.add_column("Hostname", style="magenta")
    table.add_column("MAC", style="yellow")
    table.add_column("Vendor", style="green")
    table.add_column("Latency", justify="right")
    table.add_column("Status", style="bold")
    table.add_column("Tags", style="white")

    for device in result.devices:
        display_name = device.alias_name or device.hostname or "—"
        hostname = device.hostname or "—"
        mac = device.mac or "—"
        vendor = device.vendor or "Unknown"
        latency = _format_latency(device.latency_ms)
        status = f"{_status_emoji(device)} {'Online' if device.online else 'Offline'}"
        tags = list(device.tags)
        if device.is_new:
            tags.append("🆕 New")
        tags_display = ", ".join(tags) if tags else "—"
        table.add_row(device.ip, display_name, hostname, mac, vendor, latency, status, tags_display)

    return table


def build_summary(result: ScanResult) -> Text:
    """Create a summary line with counts and duration."""
    online = sum(1 for device in result.devices if device.online)
    total = len(result.devices)
    history_info = result.diagnostics.get("history", {})
    new_count = len(history_info.get("new_devices", []))
    missing_count = len(history_info.get("missing_devices", []))
    summary = Text()
    summary.append(f"Hosts scanned: {total} • ")
    summary.append(f"Online: {online} • ")
    summary.append(f"New: {new_count} • ")
    if missing_count:
        summary.append(f"Missing: {missing_count} • ")
    summary.append(f"Duration: {result.duration_s:.2f}s • ")
    summary.append(f"Started: {result.started_at.isoformat()}Z")
    return summary


def build_diagnostics(result: ScanResult) -> Text:
    """Provide diagnostics about the scan run."""
    diag = result.diagnostics
    text = Text(style="dim")
    arp_method = diag.get("arp_method", "unknown")
    arp_entries = diag.get("arp_entries", 0)
    system_added = diag.get("system_arp_added", 0)
    system_total = diag.get("system_arp_entries", 0)
    vendor_on = "On" if diag.get("vendor_remote_enabled", True) else "Off"
    vendor_stats = diag.get("vendor_stats", {})
    cache_hits = vendor_stats.get("cache_hits", 0)
    remote_calls = vendor_stats.get("api_calls", 0)
    remote_failures = vendor_stats.get("api_failures", 0)
    text.append(
        f"ARP: {arp_method} (entries: {arp_entries}; system: {system_added}/{system_total}) • "
    )
    text.append(f"Vendor API: {vendor_on} (cache hits: {cache_hits}, remote calls: {remote_calls}, failures: {remote_failures})")
    history_info = diag.get("history", {})
    previous_ts = history_info.get("previous_started_at")
    if previous_ts:
        text.append(f" • Compared to: {previous_ts}")
    return text


def build_renderable(result: ScanResult) -> Group:
    """Return a composite renderable suitable for standard or live output."""
    return Group(build_table(result), build_summary(result), build_diagnostics(result))


def print_scan(result: ScanResult, console: Optional[Console] = None) -> None:
    """Print the scan results using the provided console."""
    console = console or Console()
    console.print(build_renderable(result))
