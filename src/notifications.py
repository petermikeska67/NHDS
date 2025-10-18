"""Notification helpers for scanner events."""

from __future__ import annotations

import json
import logging
from typing import Dict, List

import requests

from .config import NotificationSettings

LOGGER = logging.getLogger(__name__)

CHANGE_KEYS = ("new_devices", "returned_devices", "missing_devices")


def dispatch_notifications(
    settings: NotificationSettings,
    changes: Dict[str, List[str]],
    payload: Dict,
    *,
    force: bool = False,
) -> None:
    """Send enabled notifications for the provided changes."""
    if not settings.enabled:
        return
    if not force and not any(changes.get(key) for key in CHANGE_KEYS):
        return

    if settings.webhook_url:
        _send_generic_webhook(settings, changes, payload, force=force)
    if settings.discord_webhook_url:
        _send_discord_webhook(settings, changes, payload, force=force)


def _send_generic_webhook(
    settings: NotificationSettings,
    changes: Dict[str, List[str]],
    payload: Dict,
    *,
    force: bool,
) -> None:
    body = {
        "changes": changes,
        "scan": payload,
        "forced": force,
    }
    headers = {"Content-Type": "application/json"}
    if settings.secret:
        headers["X-Scanner-Secret"] = settings.secret

    try:
        response = requests.post(
            settings.webhook_url,
            data=json.dumps(body),
            headers=headers,
            timeout=settings.timeout,
        )
        response.raise_for_status()
        LOGGER.info("Webhook delivered to %s", settings.webhook_url)
    except requests.RequestException as exc:  # noqa: PERF203
        LOGGER.warning("Failed to deliver webhook: %s", exc)


def _send_discord_webhook(
    settings: NotificationSettings,
    changes: Dict[str, List[str]],
    payload: Dict,
    *,
    force: bool,
) -> None:
    lines: List[str] = []
    if changes.get("new_devices"):
        lines.append("**New devices:** " + ", ".join(changes["new_devices"]))
    if changes.get("returned_devices"):
        lines.append("**Back online:** " + ", ".join(changes["returned_devices"]))
    if changes.get("missing_devices"):
        lines.append("**Missing:** " + ", ".join(changes["missing_devices"]))

    scan = payload
    devices = scan.get("devices", [])

    content_lines: List[str] = ["**Network Scan Update**"]
    if scan.get("network"):
        content_lines.append(f"Network: `{scan['network']}`")
    if scan.get("started_at"):
        content_lines.append(f"Started: `{scan['started_at']}`")
    if scan.get("duration_s") is not None:
        content_lines.append(f"Duration: `{scan['duration_s']:.2f}s`")
    content_lines.append(f"Devices scanned: `{len(devices)}`")

    if lines:
        content_lines.extend(lines)
    elif force:
        content_lines.append("No device changes detected this scan.")

    if devices:
        content_lines.append("")
        content_lines.append("**Devices**")
        max_devices = 20
        device_lines: List[str] = []
        for device in devices[:max_devices]:
            status = "🟢" if device.get("online") else "🔴"
            ip = device.get("ip", "?")
            name = device.get("alias_name") or device.get("hostname") or ip
            tags = device.get("tags") or []
            tag_text = f" ({', '.join(tags)})" if tags else ""
            vendor = device.get("vendor") or "Unknown"
            latency = device.get("latency_ms")
            latency_text = "—" if latency is None else f"{latency:.1f} ms"
            device_lines.append(
                f"{status} `{ip}` {name}{tag_text} • {vendor} • {latency_text}"
            )
        if len(devices) > max_devices:
            device_lines.append(
                f"…and {len(devices) - max_devices} more devices"
            )
        content_lines.extend(device_lines)

    content = "\n".join(content_lines)
    if len(content) > 1800:
        content = content[:1797] + "…"

    payload_body = {"content": content}

    try:
        response = requests.post(
            settings.discord_webhook_url,
            data=json.dumps(payload_body),
            headers={"Content-Type": "application/json"},
            timeout=settings.timeout,
        )
        response.raise_for_status()
        LOGGER.info("Discord webhook delivered")
    except requests.RequestException as exc:  # noqa: PERF203
        LOGGER.warning("Failed to deliver Discord webhook: %s", exc)
