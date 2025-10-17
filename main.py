

from __future__ import annotations

import argparse
import asyncio
import json
import signal
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console
from rich.live import Live

from src import display, scanner


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover devices on your local network and assess their health."
    )
    parser.add_argument(
        "--cidr",
        help="Target IPv4 CIDR (defaults to autodetected /24). Example: 192.168.1.0/24",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=64,
        help="Maximum number of concurrent probes (default: 64).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Ping timeout per host in seconds (default: 1.0).",
    )
    parser.add_argument(
        "--vendor-file",
        type=Path,
        help="Optional custom MAC vendor mapping JSON file.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        help="Optional refresh interval in seconds. When provided, the scan reruns continuously.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output scan results as JSON (disables live refresh).",
    )
    return parser.parse_args()


def _result_to_dict(result: scanner.ScanResult) -> Dict[str, Any]:
    return {
        "network": str(result.network),
        "started_at": result.started_at.isoformat() + "Z",
        "duration_s": result.duration_s,
        "devices": [
            {
                "ip": device.ip,
                "hostname": device.hostname,
                "mac": device.mac,
                "vendor": device.vendor,
                "latency_ms": device.latency_ms,
                "online": device.online,
            }
            for device in result.devices
        ],
    }


async def run_once(
    cidr: Optional[str],
    concurrency: int,
    timeout: float,
    vendor_file: Optional[Path],
) -> scanner.ScanResult:
    network = scanner.parse_targets(cidr)
    vendor_path = vendor_file.expanduser() if vendor_file else None
    return await scanner.scan_network(
        network,
        concurrency=concurrency,
        ping_timeout=timeout,
        vendor_map_path=vendor_path,
    )


async def run_refresh(
    cidr: Optional[str],
    concurrency: int,
    timeout: float,
    vendor_file: Optional[Path],
    interval: float,
    console: Console,
) -> None:
    vendor_path = vendor_file.expanduser() if vendor_file else None

    def handle_sigint(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_sigint)

    with Live(console=console, refresh_per_second=4) as live:
        while True:
            network = scanner.parse_targets(cidr)
            result = await scanner.scan_network(
                network,
                concurrency=concurrency,
                ping_timeout=timeout,
                vendor_map_path=vendor_path,
            )
            live.update(display.build_renderable(result))
            await asyncio.sleep(interval)


def main() -> None:
    """CLI entry point."""
    args = parse_arguments()
    console = Console()

    if args.interval and args.json:
        console.print("[red]Cannot use --interval with --json output.[/red]")
        raise SystemExit(1)

    try:
        if args.json:
            result = asyncio.run(
                run_once(args.cidr, args.concurrency, args.timeout, args.vendor_file)
            )
            json.dump(_result_to_dict(result), indent=2, fp=console.file)
            console.print()
            return

        if args.interval:
            asyncio.run(
                run_refresh(
                    args.cidr,
                    args.concurrency,
                    args.timeout,
                    args.vendor_file,
                    args.interval,
                    console,
                )
            )
            return

        result = asyncio.run(
            run_once(args.cidr, args.concurrency, args.timeout, args.vendor_file)
        )
        display.print_scan(result, console=console)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopping scanner.[/dim]")


if __name__ == "__main__":
    main()
