"""Core network scanning logic for the MVP."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import config, utils


@dataclass(slots=True)
class DeviceRecord:
    """Represents a single device discovered on the network."""

    ip: str
    hostname: Optional[str]
    mac: Optional[str]
    vendor: Optional[str]
    latency_ms: Optional[float]
    online: bool
    is_new: bool = False
    alias_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "latency_ms": self.latency_ms,
            "online": self.online,
            "is_new": self.is_new,
            "alias_name": self.alias_name,
            "tags": self.tags,
        }


@dataclass(slots=True)
class ScanResult:
    """Details about a network scan run."""

    network: ipaddress.IPv4Network
    started_at: datetime
    duration_s: float
    devices: List[DeviceRecord]
    diagnostics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network": str(self.network),
            "started_at": self.started_at.isoformat() + "Z",
            "duration_s": self.duration_s,
            "devices": [device.to_dict() for device in self.devices],
            "diagnostics": self.diagnostics,
        }


def default_vendor_file() -> Path:
    """Return the bundled vendor lookup table path."""
    return Path(__file__).resolve().parent.parent / "data" / "mac_vendors.json"


async def _probe_ip(
    ip: str,
    vendor_map,
    ping_timeout: float,
    mac_lookup: Dict[str, str],
    *,
    enable_vendor_remote: bool,
    vendor_force_refresh: bool,
) -> Optional[DeviceRecord]:
    """Probe a single IP address and build a device record if reachable."""
    pre_mac = mac_lookup.get(ip)
    latency = await utils.run_in_executor(utils.ping_host, ip, ping_timeout)
    reachable = latency is not None or pre_mac is not None
    if not reachable:
        return None

    hostname = await utils.run_in_executor(utils.resolve_hostname, ip)
    mac = pre_mac or await utils.run_in_executor(utils.get_mac_address, ip)
    if mac and not pre_mac:
        mac_lookup[ip] = mac
    vendor = utils.lookup_vendor(
        mac,
        vendor_map,
        enable_remote=enable_vendor_remote,
        force_remote=vendor_force_refresh,
    )
    alias = config.match_alias(ip, mac)
    alias_name = alias.name if alias else None
    tags = alias.tags if alias else []

    return DeviceRecord(
        ip=ip,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        latency_ms=latency,
        online=latency is not None or mac is not None,
        alias_name=alias_name,
        tags=tags,
    )


async def scan_network(
    network: ipaddress.IPv4Network,
    *,
    concurrency: int = 64,
    ping_timeout: float = 1.0,
    vendor_map_path: Optional[Path] = None,
    vendor_remote: bool = True,
    vendor_force_refresh: bool = False,
    arp_timeout: float = 2.0,
) -> ScanResult:
    """
    Scan the provided network and return structured results.

    Args:
        network: The IPv4 network to scan.
        concurrency: Maximum number of concurrent probes.
        ping_timeout: Ping timeout per host in seconds.
        vendor_map_path: Optional path to a MAC vendor map JSON file.
        vendor_remote: Allow remote vendor lookups via macvendorlookup.com.
        vendor_force_refresh: Force refreshing vendor data even when cached locally.
        arp_timeout: Timeout (seconds) for ARP discovery via scapy.
    """
    vendor_map = utils.load_vendor_map(vendor_map_path or default_vendor_file())
    if vendor_force_refresh:
        utils.clear_vendor_cache()
    utils.reset_vendor_stats()

    arp_result = utils.arp_scan(network, timeout=arp_timeout)
    mac_lookup: Dict[str, str] = dict(arp_result.mapping)

    system_arp_table = utils.read_system_arp_table()
    system_arp_added = 0
    for ip, mac in system_arp_table.items():
        try:
            if ipaddress.ip_address(ip) in network:
                if ip not in mac_lookup:
                    mac_lookup[ip] = mac
                    system_arp_added += 1
        except ValueError:
            continue

    started_at = datetime.utcnow()
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def worker(ip: str) -> Optional[DeviceRecord]:
        async with semaphore:
            return await _probe_ip(
                ip,
                vendor_map,
                ping_timeout,
                mac_lookup,
                enable_vendor_remote=vendor_remote,
                vendor_force_refresh=vendor_force_refresh,
            )

    candidate_hosts = set(utils.iter_hosts(network))
    candidate_hosts.update(mac_lookup.keys())

    tasks = [asyncio.create_task(worker(ip)) for ip in candidate_hosts]
    devices: List[DeviceRecord] = []
    for task in asyncio.as_completed(tasks):
        try:
            record = await task
        except Exception:
            continue
        if record is None:
            continue
        devices.append(record)

    devices.sort(key=lambda item: tuple(int(part) for part in item.ip.split(".")))

    duration = (datetime.utcnow() - started_at).total_seconds()
    diagnostics = {
        "arp_method": arp_result.method,
        "arp_error": arp_result.error,
        "arp_entries": len(arp_result.mapping),
        "system_arp_entries": len(system_arp_table),
        "system_arp_added": system_arp_added,
        "candidate_hosts": len(candidate_hosts),
        "vendor_remote_enabled": vendor_remote,
        "vendor_force_refresh": vendor_force_refresh,
        "vendor_stats": utils.get_vendor_stats(),
    }
    return ScanResult(
        network=network,
        started_at=started_at,
        duration_s=duration,
        devices=devices,
        diagnostics=diagnostics,
    )


def parse_targets(cidr: Optional[str]) -> ipaddress.IPv4Network:
    """Return an IPv4Network for the provided CIDR or detect a default range."""
    return utils.detect_network(cidr)


def host_iterator(network: ipaddress.IPv4Network) -> Iterable[str]:
    """Wrapper to expose host iteration outside this module."""
    return utils.iter_hosts(network)
