"""Utility helpers for the network health scanner MVP."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Dict, Iterable, Optional

from ping3 import ping

# Ensure ping3 raises exceptions for better error handling.
try:
    import ping3

    ping3.EXCEPTIONS = True
except Exception:
    # Fallback is harmless; ping3 will simply return None on errors.
    pass


DEFAULT_NETMASK = 24


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


def get_mac_address(ip: str) -> Optional[str]:
    """Return the MAC address for the given IP if available in the ARP cache."""
    output = _run_arp(ip)
    if not output:
        return None
    match = MAC_REGEX.search(output)
    if match:
        return match.group(1).upper()
    return None


def load_vendor_map(path: Path) -> Dict[str, str]:
    """Load a prefix-to-vendor mapping."""
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    return {prefix.upper(): vendor for prefix, vendor in data.items()}


def lookup_vendor(mac: Optional[str], vendor_map: Dict[str, str]) -> Optional[str]:
    """Infer the vendor name from a MAC address."""
    if not mac:
        return None
    prefix = mac.upper()[0:8]
    return vendor_map.get(prefix)


async def run_in_executor(func, *args):
    """Lightweight helper to offload blocking work into the default executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)
