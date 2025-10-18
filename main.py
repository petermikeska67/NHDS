
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import signal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.live import Live

from src import config as config_module
from src import display, history, notifications, scanner
from src.config import AppConfig, NotificationSettings
from src.logging_utils import setup_logging


def build_parser(cfg: AppConfig) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Discover devices on your local network and assess their health."
    )
    parser.add_argument(
        "--cidr",
        default=cfg.network.default_cidr,
        help="Target IPv4 CIDR (defaults to autodetected /24 or config). Example: 192.168.1.0/24",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=cfg.network.concurrency,
        help=f"Maximum number of concurrent probes (default: {cfg.network.concurrency}).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=cfg.network.timeout,
        help=f"Ping timeout per host in seconds (default: {cfg.network.timeout}).",
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
    parser.add_argument(
        "--vendor-offline",
        action="store_true",
        help="Disable remote vendor lookups (use local data only).",
    )
    parser.add_argument(
        "--vendor-refresh",
        action="store_true",
        help="Force refresh vendor information via the remote API.",
    )
    parser.add_argument(
        "--arp-timeout",
        type=float,
        default=cfg.network.arp_timeout,
        help=f"ARP discovery timeout in seconds (default: {cfg.network.arp_timeout}).",
    )
    parser.add_argument(
        "--export-json",
        type=Path,
        help="Write the latest scan to the specified JSON file.",
    )
    parser.add_argument(
        "--export-csv",
        type=Path,
        help="Write the latest scan to the specified CSV file.",
    )
    default_history_path = (
        Path(cfg.network.history_path).expanduser()
        if cfg.network.history_path
        else history.DEFAULT_HISTORY_PATH
    )
    parser.add_argument(
        "--history-file",
        type=Path,
        default=default_history_path,
        help=f"Path to persist scan history (default: {default_history_path}).",
    )
    parser.add_argument(
        "--history-max",
        type=int,
        default=cfg.network.history_max,
        help=f"Maximum number of history entries to retain (default: {cfg.network.history_max}).",
    )
    parser.add_argument(
        "--notify-changes",
        action="store_true",
        help="Print change notifications (new/missing devices) after each scan.",
    )
    return parser

async def run_once(
    cidr: Optional[str],
    concurrency: int,
    timeout: float,
    vendor_file: Optional[Path],
    vendor_offline: bool,
    vendor_refresh: bool,
    arp_timeout: float,
    history_path: Path,
    history_max: int,
    history_data: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[scanner.ScanResult, List[Dict[str, Any]], Dict[str, List[str]]]:
    network = scanner.parse_targets(cidr)
    vendor_path = vendor_file.expanduser() if vendor_file else None
    result = await scanner.scan_network(
        network,
        concurrency=concurrency,
        ping_timeout=timeout,
        vendor_map_path=vendor_path,
        vendor_remote=not vendor_offline,
        vendor_force_refresh=vendor_refresh,
        arp_timeout=arp_timeout,
    )
    updated_history, changes, _ = history.append_result(
        result,
        history_data,
        path=history_path,
        max_entries=history_max,
    )
    return result, updated_history, changes


async def run_refresh(
    cidr: Optional[str],
    concurrency: int,
    timeout: float,
    vendor_file: Optional[Path],
    interval: float,
    console: Console,
    *,
    vendor_offline: bool,
    vendor_refresh: bool,
    history_path: Path,
    history_max: int,
    arp_timeout: float,
    notify_changes: bool,
    notifications_cfg: NotificationSettings,
) -> None:
    def handle_sigint(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_sigint)

    history_data = history.load_history(history_path)

    with Live(console=console, refresh_per_second=4) as live:
        while True:
            result, history_data, changes = await run_once(
                cidr,
                concurrency,
                timeout,
                vendor_file,
                vendor_offline,
                vendor_refresh,
                arp_timeout,
                history_path,
                history_max,
                history_data=history_data,
            )
            live.update(display.build_renderable(result))
            emit_notifications(
                console,
                changes,
                result,
                print_console=notify_changes,
                notification_settings=notifications_cfg,
                force_notify=True,
            )
            await asyncio.sleep(interval)


def emit_notifications(
    console: Console,
    changes: Dict[str, List[str]],
    result: scanner.ScanResult,
    *,
    print_console: bool,
    notification_settings: NotificationSettings,
    force_notify: bool = False,
) -> None:
    """Handle console and webhook notifications for scan changes."""
    new_devices = changes.get("new_devices") or []
    returned = changes.get("returned_devices") or []
    missing = changes.get("missing_devices") or []

    has_changes = bool(new_devices or returned or missing)

    if print_console and has_changes:
        messages = []
        if new_devices:
            messages.append(f"New devices: {', '.join(new_devices)}")
        if returned:
            messages.append(f"Back online: {', '.join(returned)}")
        if missing:
            messages.append(f"Missing from scan: {', '.join(missing)}")
        console.print("[yellow]Changes detected:[/yellow] " + " | ".join(messages))

    notifications.dispatch_notifications(
        notification_settings,
        changes,
        result.to_dict(),
        force=force_notify,
    )


def export_result_json(destination: Path, result: scanner.ScanResult) -> None:
    """Persist the scan result as JSON."""
    target = destination.expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, indent=2)


def export_result_csv(destination: Path, result: scanner.ScanResult) -> None:
    """Persist the scan result as CSV."""
    target = destination.expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "alias_name",
                "hostname",
                "mac",
                "vendor",
                "latency_ms",
                "online",
                "is_new",
                "tags",
            ],
            extrasaction="ignore",
        )
        writer.writeheader()
        for device in result.devices:
            writer.writerow(device.to_dict())


def main() -> None:
    """CLI entry point."""
    setup_logging()
    cfg = config_module.load_config()
    parser = build_parser(cfg)
    args = parser.parse_args()
    console = Console()

    history_path = args.history_file.expanduser()
    history_max = args.history_max
    notifications_cfg = cfg.notifications

    effective_vendor_offline = args.vendor_offline or not cfg.network.vendor_remote
    effective_vendor_refresh = args.vendor_refresh or cfg.network.vendor_refresh
    notify_console = args.notify_changes

    if args.interval and args.json:
        console.print("[red]Cannot use --interval with --json output.[/red]")
        raise SystemExit(1)

    try:
        if args.json:
            result, _, changes = asyncio.run(
                run_once(
                    args.cidr,
                    args.concurrency,
                    args.timeout,
                    args.vendor_file,
                    effective_vendor_offline,
                    effective_vendor_refresh,
                    args.arp_timeout,
                    history_path,
                    history_max,
                )
            )
            json.dump(result.to_dict(), indent=2, fp=console.file)
            console.print()
            emit_notifications(
                console,
                changes,
                result,
                print_console=notify_console,
                notification_settings=notifications_cfg,
                force_notify=True,
            )
            if args.export_json:
                export_result_json(args.export_json, result)
            if args.export_csv:
                export_result_csv(args.export_csv, result)
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
                    vendor_offline=effective_vendor_offline,
                    vendor_refresh=effective_vendor_refresh,
                    history_path=history_path,
                    history_max=history_max,
                    arp_timeout=args.arp_timeout,
                    notify_changes=notify_console,
                    notifications_cfg=notifications_cfg,
                )
            )
            return

        result, _, changes = asyncio.run(
            run_once(
                args.cidr,
                args.concurrency,
                args.timeout,
                args.vendor_file,
                effective_vendor_offline,
                effective_vendor_refresh,
                args.arp_timeout,
                history_path,
                history_max,
            )
        )
        display.print_scan(result, console=console)
        emit_notifications(
            console,
            changes,
            result,
            print_console=notify_console,
            notification_settings=notifications_cfg,
            force_notify=True,
        )
        if args.export_json:
            export_result_json(args.export_json, result)
        if args.export_csv:
            export_result_csv(args.export_csv, result)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopping scanner.[/dim]")


if __name__ == "__main__":
    main()
