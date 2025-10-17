"""Core network scanning logic for the MVP."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import utils


@dataclass(slots=True)
class DeviceRecord:
    """Represents a single device discovered on the network."""

    ip: str
    hostname: Optional[str]
    mac: Optional[str]
    vendor: Optional[str]
    latency_ms: Optional[float]
    online: bool


@dataclass(slots=True)
class ScanResult:
    """Details about a network scan run."""

    network: ipaddress.IPv4Network
    started_at: datetime
    duration_s: float
    devices: List[DeviceRecord]


def default_vendor_file() -> Path:
    """Return the bundled vendor lookup table path."""
    return Path(__file__).resolve().parent.parent / "data" / "mac_vendors.json"


async def _probe_ip(
    ip: str,
    vendor_map,
    ping_timeout: float,
    mac_lookup: Dict[str, str],
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
    vendor = utils.lookup_vendor(mac, vendor_map)

    return DeviceRecord(
        ip=ip,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        latency_ms=latency,
        online=latency is not None or mac is not None,
    )


async def scan_network(
    network: ipaddress.IPv4Network,
    *,
    concurrency: int = 64,
    ping_timeout: float = 1.0,
    vendor_map_path: Optional[Path] = None,
) -> ScanResult:
    """
    Scan the provided network and return structured results.

    Args:
        network: The IPv4 network to scan.
        concurrency: Maximum number of concurrent probes.
        ping_timeout: Ping timeout per host in seconds.
        vendor_map_path: Optional path to a MAC vendor map JSON file.
    """
    vendor_map = utils.load_vendor_map(vendor_map_path or default_vendor_file())
    mac_lookup = utils.arp_scan(network)
    for ip, mac in utils.read_system_arp_table().items():
        try:
            if ipaddress.ip_address(ip) in network:
                mac_lookup[ip] = mac
        except ValueError:
            continue

    started_at = datetime.utcnow()
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def worker(ip: str) -> Optional[DeviceRecord]:
        async with semaphore:
            return await _probe_ip(ip, vendor_map, ping_timeout, mac_lookup)

    candidate_hosts = set(mac_lookup.keys())
    if not candidate_hosts:
        candidate_hosts.update(utils.iter_hosts(network))

    host_iterable = list(candidate_hosts)

    tasks = [asyncio.create_task(worker(ip)) for ip in host_iterable]
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
    return ScanResult(
        network=network,
        started_at=started_at,
        duration_s=duration,
        devices=devices,
    )


def parse_targets(cidr: Optional[str]) -> ipaddress.IPv4Network:
    """Return an IPv4Network for the provided CIDR or detect a default range."""
    return utils.detect_network(cidr)


def host_iterator(network: ipaddress.IPv4Network) -> Iterable[str]:
    """Wrapper to expose host iteration outside this module."""
    return utils.iter_hosts(network)
