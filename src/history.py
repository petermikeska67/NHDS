"""Scan history helpers for the network scanner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import ScanResult


DEFAULT_HISTORY_PATH = Path(__file__).resolve().parent.parent / "data" / "scan_history.json"
MAX_HISTORY_ENTRIES = 50


def load_history(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load historical scans from disk."""
    target = path or DEFAULT_HISTORY_PATH
    if not target.exists():
        return []
    try:
        with target.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            return data
    except (OSError, ValueError):
        pass
    return []


def save_history(
    history: List[Dict[str, Any]],
    path: Optional[Path] = None,
) -> None:
    """Persist history to disk."""
    target = path or DEFAULT_HISTORY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(history, handle, indent=2)


def _build_prev_index(entry: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not entry:
        return {}
    devices = entry.get("devices", [])
    return {device.get("ip"): device for device in devices if isinstance(device, dict)}


def annotate_with_history(
    result: "ScanResult",
    previous_entry: Optional[Dict[str, Any]],
) -> Dict[str, List[str]]:
    """Mark new/returning devices and summarise changes."""
    previous_by_ip = _build_prev_index(previous_entry)
    previous_online = {
        ip for ip, record in previous_by_ip.items() if record.get("online", False)
    }
    current_ips = set()

    changes = {
        "new_devices": [],
        "returned_devices": [],
        "missing_devices": [],
    }

    for device in result.devices:
        current_ips.add(device.ip)
        previous = previous_by_ip.get(device.ip)
        if previous is None:
            device.is_new = True
            changes["new_devices"].append(device.ip)
            continue

        if not previous.get("online", False) and device.online:
            changes["returned_devices"].append(device.ip)

    for ip in previous_online:
        if ip not in current_ips:
            changes["missing_devices"].append(ip)

    history_block = {
        "new_devices": changes["new_devices"],
        "returned_devices": changes["returned_devices"],
        "missing_devices": changes["missing_devices"],
        "previous_started_at": previous_entry.get("started_at") if previous_entry else None,
    }
    result.diagnostics["history"] = history_block
    return changes


def append_result(
    result: "ScanResult",
    history_data: Optional[List[Dict[str, Any]]] = None,
    *,
    path: Optional[Path] = None,
    max_entries: int = MAX_HISTORY_ENTRIES,
) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]], Optional[Dict[str, Any]]]:
    """
    Append a ScanResult to history, trimming to the max entry count.

    Returns the updated history, a dict describing changes, and the previous entry.
    """
    target_history = history_data[:] if history_data is not None else load_history(path)
    previous_entry = target_history[-1] if target_history else None
    changes = annotate_with_history(result, previous_entry)

    entry = result.to_dict()
    target_history.append(entry)
    if len(target_history) > max_entries:
        target_history = target_history[-max_entries:]

    history_block = result.diagnostics.get("history", {})
    history_block["history_size"] = len(target_history)
    history_block["history_limit"] = max_entries
    result.diagnostics["history"] = history_block

    save_history(target_history, path)
    return target_history, changes, previous_entry
