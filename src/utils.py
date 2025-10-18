"""Utility helpers for the network health scanner MVP."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from ping3 import ping
import requests

# Ensure ping3 raises exceptions for better error handling.
try:
    import ping3

    ping3.EXCEPTIONS = True
except Exception:
    # Fallback is harmless; ping3 will simply return None on errors.
    pass

try:  # Optional import; ARP scanning is best-effort.
    from scapy.all import ARP, Ether, srp  # type: ignore
except Exception:  # pragma: no cover - scapy may not be installed or usable.
    ARP = Ether = srp = None


DEFAULT_NETMASK = 24
MAC_VENDOR_API = "https://www.macvendorlookup.com/api/v2/{mac}"
_VENDOR_CACHE: Dict[str, Optional[str]] = {}
_REQUEST_SESSION = requests.Session()
_VENDOR_STATS: Dict[str, int] = {
    "local_hits": 0,
    "cache_hits": 0,
    "api_calls": 0,
    "api_failures": 0,
    "remote_disabled": 0,
}


def get_local_ip() -> str:
    """Return the best-effort local IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def detect_network(cidr: Optional[str] = None) -> ipaddress.IPv4Network:
    """Derive the target IPv4 network, defaulting to a /24 anchored at the local IP."""
    if cidr:
        return ipaddress.ip_network(cidr, strict=False)
    local_ip = get_local_ip()
    return ipaddress.ip_network(f"{local_ip}/{DEFAULT_NETMASK}", strict=False)


def iter_hosts(network: ipaddress.IPv4Network) -> Iterable[str]:
    """Yield all usable host IPs for the provided network."""
    for host in network.hosts():
        yield str(host)


def ping_host(ip: str, timeout: float = 1.0) -> Optional[float]:
    """
    Ping the given IP address.

    Returns latency in milliseconds when successful, otherwise None.
    """
    try:
        latency_seconds = ping(ip, timeout=timeout, unit="ms")  # type: ignore[arg-type]
        if latency_seconds is None:
            return None
        return float(latency_seconds)
    except Exception:
        return None


def resolve_hostname(ip: str) -> Optional[str]:
    """Resolve the reverse DNS hostname, if available."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, TimeoutError):
        return None


def _run_arp(ip: str) -> Optional[str]:
    """Run the platform-specific ARP command and return its output."""
    system = platform.system().lower()
    if system == "windows":
        command = ["arp", "-a", ip]
    else:
        command = ["arp", "-n", ip]
    try:
        output = subprocess.check_output(
            command, stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return output


MAC_REGEX = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.IGNORECASE)
ARP_UNIX_REGEX = re.compile(
    r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>[0-9a-f:-]{11,17})",
    re.IGNORECASE,
)
ARP_WINDOWS_REGEX = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-f-]{11,17})\s+\w+",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ArpScanResult:
    """Details about an ARP scan attempt."""

    mapping: Dict[str, str]
    method: str
    error: Optional[str] = None


def clear_vendor_cache() -> None:
    """Clear the in-memory vendor cache."""
    _VENDOR_CACHE.clear()


def reset_vendor_stats() -> None:
    """Reset vendor lookup instrumentation."""
    for key in list(_VENDOR_STATS.keys()):
        _VENDOR_STATS[key] = 0


def get_vendor_stats() -> Dict[str, int]:
    """Return a snapshot of vendor lookup statistics."""
    return dict(_VENDOR_STATS)


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Return a canonical MAC representation (AA:BB:CC:DD:EE:FF)."""
    if not mac:
        return None
    mac = mac.strip().upper().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6:
        return None
    return ":".join(part.zfill(2) for part in parts)


def read_system_arp_table() -> Dict[str, str]:
    """Parse the system ARP table and return an IP→MAC mapping."""
    system = platform.system().lower()
    if system == "windows":
        command = ["arp", "-a"]
    else:
        command = ["arp", "-an"]

    try:
        output = subprocess.check_output(
            command, stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}

    table: Dict[str, str] = {}
    for line in output.splitlines():
        match = ARP_UNIX_REGEX.search(line) or ARP_WINDOWS_REGEX.search(line)
        if not match:
            continue
        ip = match.group("ip")
        mac = normalize_mac(match.group("mac"))
        if ip and mac:
            table[ip] = mac
    return table


def get_mac_address(ip: str) -> Optional[str]:
    """Return the MAC address for the given IP if available in the ARP cache."""
    output = _run_arp(ip)
    if output:
        match = MAC_REGEX.search(output)
        if match:
            return normalize_mac(match.group(1))
    # Fallback to table snapshot.
    return read_system_arp_table().get(ip)


def load_vendor_map(path: Path) -> Dict[str, str]:
    """Load a prefix-to-vendor mapping."""
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    return {prefix.upper(): vendor for prefix, vendor in data.items()}


def fetch_vendor_from_api(canonical_mac: str) -> Optional[str]:
    """Query the external API for vendor details."""
    _VENDOR_STATS["api_calls"] += 1
    try:
        response = _REQUEST_SESSION.get(
            MAC_VENDOR_API.format(mac=canonical_mac), timeout=5
        )
    except requests.RequestException:
        _VENDOR_STATS["api_failures"] += 1
        return None
    if response.status_code != 200:
        _VENDOR_STATS["api_failures"] += 1
        return None
    try:
        payload = response.json()
    except ValueError:
        _VENDOR_STATS["api_failures"] += 1
        return None

    vendor_name: Optional[str] = None
    if isinstance(payload, list) and payload:
        vendor_name = payload[0].get("company") or payload[0].get("vendor")
    elif isinstance(payload, dict):
        vendor_name = payload.get("company") or payload.get("vendor")

    if vendor_name:
        vendor_name = vendor_name.strip()
    if vendor_name:
        return vendor_name

    _VENDOR_STATS["api_failures"] += 1
    return None


def lookup_vendor(
    mac: Optional[str],
    vendor_map: Dict[str, str],
    *,
    enable_remote: bool = True,
    force_remote: bool = False,
) -> Optional[str]:
    """Infer the vendor name from a MAC address, using local data then optional remote API."""
    canonical = normalize_mac(mac)
    if not canonical:
        return None
    prefix = canonical[:8]

    vendor = vendor_map.get(prefix)
    if vendor:
        _VENDOR_STATS["local_hits"] += 1
        if not force_remote or not enable_remote:
            return vendor
        remote_vendor = fetch_vendor_from_api(canonical)
        if remote_vendor:
            vendor_map[prefix] = remote_vendor
            _VENDOR_CACHE[prefix] = remote_vendor
            return remote_vendor
        return vendor

    if not force_remote and prefix in _VENDOR_CACHE:
        _VENDOR_STATS["cache_hits"] += 1
        return _VENDOR_CACHE[prefix]

    if not enable_remote:
        _VENDOR_STATS["remote_disabled"] += 1
        return None

    vendor = fetch_vendor_from_api(canonical)
    _VENDOR_CACHE[prefix] = vendor
    if vendor:
        vendor_map[prefix] = vendor
    return vendor


def arp_scan(network: ipaddress.IPv4Network, timeout: float = 2.0) -> ArpScanResult:
    """Perform a best-effort ARP scan and return IP→MAC mapping."""
    if ARP is None or Ether is None or srp is None:
        return ArpScanResult({}, "scapy_unavailable", "scapy is not installed")
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            timeout=timeout,
            verbose=False,
        )
    except PermissionError:
        return ArpScanResult({}, "scapy_permission_error", "insufficient permissions for raw sockets")
    except Exception as exc:  # noqa: BLE001
        return ArpScanResult({}, "scapy_failed", str(exc))

    mapping: Dict[str, str] = {}
    for _, response in answered:
        ip = getattr(response, "psrc", None)
        mac = normalize_mac(getattr(response, "hwsrc", None))
        if ip and mac:
            mapping[ip] = mac
    method = "scapy_success" if mapping else "scapy_no_response"
    return ArpScanResult(mapping, method)


async def run_in_executor(func, *args):
    """Lightweight helper to offload blocking work into the default executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)
