"""Flask web application for the network scanner (production-ready)."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    url_for,
)

from src import config as config_module
from src import history, notifications, scanner, utils
from src.config import AppConfig

LOGGER = logging.getLogger(__name__)


def _resolve_history_path(cfg: AppConfig) -> Path:
    if cfg.network.history_path:
        return Path(cfg.network.history_path).expanduser()
    return history.DEFAULT_HISTORY_PATH


def _default_form(cfg: AppConfig) -> Dict[str, Any]:
    return {
        "cidr": cfg.network.default_cidr or "",
        "concurrency": str(cfg.network.concurrency),
        "timeout": str(cfg.network.timeout),
        "vendor_file": "",
        "vendor_remote": "on" if cfg.network.vendor_remote else "",
        "vendor_refresh": "on" if cfg.network.vendor_refresh else "",
        "arp_timeout": str(cfg.network.arp_timeout),
    }


def _settings_form(cfg: AppConfig) -> Dict[str, Any]:
    return {
        "default_cidr": cfg.network.default_cidr or "",
        "concurrency": str(cfg.network.concurrency),
        "timeout": str(cfg.network.timeout),
        "vendor_remote": "on" if cfg.network.vendor_remote else "",
        "vendor_refresh": "on" if cfg.network.vendor_refresh else "",
        "arp_timeout": str(cfg.network.arp_timeout),
        "history_max": str(cfg.network.history_max),
        "history_path": cfg.network.history_path or "",
        "webhook_enabled": "on" if cfg.notifications.enabled else "",
        "webhook_url": cfg.notifications.webhook_url or "",
        "webhook_secret": cfg.notifications.secret or "",
        "webhook_timeout": str(cfg.notifications.timeout),
        "discord_webhook_url": cfg.notifications.discord_webhook_url or "",
        "require_auth": "on" if cfg.web.require_auth else "",
        "auth_token": cfg.web.auth_token or "",
    }


def _run_scan(
    cfg: AppConfig,
    cidr: Optional[str],
    concurrency: int,
    timeout: float,
    vendor_file: Optional[str],
    *,
    vendor_offline: bool,
    vendor_refresh: bool,
    arp_timeout: float,
    history_buffer: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Execute a scan and handle history + notifications."""
    network = scanner.parse_targets(cidr)
    result = asyncio.run(
        scanner.scan_network(
            network,
            concurrency=concurrency,
            ping_timeout=timeout,
            vendor_map_path=Path(vendor_file).expanduser() if vendor_file else None,
            vendor_remote=not vendor_offline,
            vendor_force_refresh=vendor_refresh,
            arp_timeout=arp_timeout,
        )
    )
    history_path = _resolve_history_path(cfg)
    updated_history, changes, _ = history.append_result(
        result,
        history_buffer,
        path=history_path,
        max_entries=cfg.network.history_max,
    )

    notifications.dispatch_notifications(cfg.notifications, changes, result.to_dict(), force=True)

    return {
        "result": result,
        "history": updated_history,
        "changes": changes,
    }


def create_app(app_config: Optional[AppConfig] = None) -> Flask:
    cfg = app_config or config_module.load_config()
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.config["NSHS_CONFIG"] = cfg
    app.config["NSHS_HISTORY_PATH"] = _resolve_history_path(cfg)

    state: Dict[str, Any] = {
        "last_result": None,
        "history": history.load_history(app.config["NSHS_HISTORY_PATH"]),
        "last_changes": {
            "new_devices": [],
            "returned_devices": [],
            "missing_devices": [],
        },
    }

    if cfg.web.require_auth and cfg.web.auth_token:
        @app.before_request
        def enforce_token() -> None:
            if request.path.startswith("/static/"):
                return
            header = request.headers.get("Authorization", "")
            token = header[7:].strip() if header.startswith("Bearer ") else ""
            if token != cfg.web.auth_token:
                abort(401)

    @app.route("/", methods=["GET", "POST"])
    def index():
        nonlocal cfg
        error: Optional[str] = None
        result = state.get("last_result")
        form_values = _default_form(cfg)
        settings_form = _settings_form(cfg)
        settings_message: Optional[str] = None
        settings_error: Optional[str] = None
        form_type: Optional[str] = None

        if request.method == "POST":
            form_type = request.form.get("form_type", "scan")
            if form_type == "scan":
                cidr = request.form.get("cidr") or None
                vendor_file = request.form.get("vendor_file") or None
                try:
                    concurrency = int(request.form.get("concurrency") or cfg.network.concurrency)
                    timeout = float(request.form.get("timeout") or cfg.network.timeout)
                    arp_timeout = float(request.form.get("arp_timeout") or cfg.network.arp_timeout)
                except ValueError:
                    concurrency = cfg.network.concurrency
                    timeout = cfg.network.timeout
                    arp_timeout = cfg.network.arp_timeout
                    error = "Invalid numeric values provided. Defaults restored."

                vendor_remote_state = request.form.get("vendor_remote") is not None
                vendor_refresh_state = request.form.get("vendor_refresh") is not None

                try:
                    outcome = _run_scan(
                        cfg,
                        cidr,
                        concurrency,
                        timeout,
                        vendor_file,
                        vendor_offline=not vendor_remote_state,
                        vendor_refresh=vendor_refresh_state,
                        arp_timeout=arp_timeout,
                        history_buffer=state.get("history"),
                    )
                    result = outcome["result"]
                    state["last_result"] = result
                    state["history"] = outcome["history"]
                    state["last_changes"] = outcome["changes"]
                except Exception as exc:  # noqa: BLE001
                    LOGGER.exception("Scan failed")
                    error = f"Failed to run scan: {exc}"

                form_values.update(
                    {
                        "cidr": cidr or "",
                        "concurrency": str(concurrency),
                        "timeout": str(timeout),
                        "vendor_file": vendor_file or "",
                        "vendor_remote": "on" if vendor_remote_state else "",
                        "vendor_refresh": "on" if vendor_refresh_state else "",
                        "arp_timeout": str(arp_timeout),
                    }
                )
            elif form_type == "settings":
                try:
                    cfg.network.default_cidr = request.form.get("setting_default_cidr") or None
                    cfg.network.concurrency = max(1, int(request.form.get("setting_concurrency") or cfg.network.concurrency))
                    cfg.network.timeout = max(0.1, float(request.form.get("setting_timeout") or cfg.network.timeout))
                    cfg.network.vendor_remote = request.form.get("setting_vendor_remote") is not None
                    cfg.network.vendor_refresh = request.form.get("setting_vendor_refresh") is not None
                    cfg.network.arp_timeout = max(0.1, float(request.form.get("setting_arp_timeout") or cfg.network.arp_timeout))
                    cfg.network.history_max = max(1, int(request.form.get("setting_history_max") or cfg.network.history_max))
                    cfg.network.history_path = request.form.get("setting_history_path") or None

                    cfg.notifications.enabled = request.form.get("setting_webhook_enabled") is not None
                    cfg.notifications.webhook_url = request.form.get("setting_webhook_url") or None
                    cfg.notifications.secret = request.form.get("setting_webhook_secret") or None
                    cfg.notifications.timeout = max(1.0, float(request.form.get("setting_webhook_timeout") or cfg.notifications.timeout))
                    cfg.notifications.discord_webhook_url = request.form.get("setting_discord_webhook_url") or None

                    cfg.web.require_auth = request.form.get("setting_require_auth") is not None
                    cfg.web.auth_token = request.form.get("setting_auth_token") or None

                    config_module.save_config(cfg)
                    cfg = config_module.load_config(force_reload=True)
                    app.config["NSHS_CONFIG"] = cfg
                    app.config["NSHS_HISTORY_PATH"] = _resolve_history_path(cfg)
                    state["history"] = history.load_history(app.config["NSHS_HISTORY_PATH"])
                    form_values = _default_form(cfg)
                    settings_form = _settings_form(cfg)
                    settings_message = "Settings updated successfully."
                except Exception as exc:  # noqa: BLE001
                    LOGGER.exception("Failed to update settings")
                    cfg = config_module.load_config(force_reload=True)
                    form_values = _default_form(cfg)
                    settings_form = _settings_form(cfg)
                    settings_error = f"Failed to update settings: {exc}"
        else:
            last = state.get("last_result")
            if last is not None:
                form_values.update(
                    {
                        "cidr": form_values["cidr"] or str(last.network),
                        "concurrency": form_values["concurrency"],
                        "timeout": form_values["timeout"],
                        "vendor_file": "",
                    }
                )

        settings_visible = bool(settings_message or settings_error or (form_type == "settings"))

        return render_template(
            "index.html",
            result=result,
            error=error,
            form=form_values,
            api_url=url_for("api_scan"),
            history_size=len(state.get("history", [])),
            changes=state.get("last_changes", {}),
            history_entries=list(reversed(state.get("history", [])[-5:])),
            notifications_enabled=cfg.notifications.enabled,
            settings_form=settings_form,
            settings_message=settings_message,
            settings_error=settings_error,
            settings_visible=settings_visible,
        )

    @app.post("/api/scan")
    def api_scan():
        payload = request.get_json(silent=True) or {}
        cidr = payload.get("cidr")
        vendor_file = payload.get("vendor_file")
        concurrency = int(payload.get("concurrency", cfg.network.concurrency))
        timeout = float(payload.get("timeout", cfg.network.timeout))
        vendor_offline = bool(payload.get("vendor_offline", not cfg.network.vendor_remote))
        vendor_refresh = bool(payload.get("vendor_refresh", cfg.network.vendor_refresh))
        arp_timeout = float(payload.get("arp_timeout", cfg.network.arp_timeout))

        try:
            outcome = _run_scan(
                cfg,
                cidr,
                concurrency,
                timeout,
                vendor_file,
                vendor_offline=vendor_offline,
                vendor_refresh=vendor_refresh,
                arp_timeout=arp_timeout,
                history_buffer=state.get("history"),
            )
            state["last_result"] = outcome["result"]
            state["history"] = outcome["history"]
            state["last_changes"] = outcome["changes"]
            return jsonify(
                {
                    "result": outcome["result"].to_dict(),
                    "changes": outcome["changes"],
                    "history_size": len(state["history"]),
                }
            )
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("API scan failed")
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/last-scan")
    def api_last_scan():
        result = state.get("last_result")
        if result is None:
            return jsonify({"message": "No scans have been performed yet."}), 404
        return jsonify(
            {
                "result": result.to_dict(),
                "changes": state.get("last_changes", {}),
                "history_size": len(state.get("history", [])),
            }
        )

    @app.get("/api/history")
    def api_history():
        return jsonify(state.get("history", []))

    @app.get("/api/health")
    def api_health():
        result = state.get("last_result")
        status = "ok" if result else "idle"
        return jsonify(
            {
                "status": status,
                "history_size": len(state.get("history", [])),
                "notifications_enabled": cfg.notifications.enabled,
                "last_scan_started": result.started_at.isoformat() + "Z" if result else None,
                "last_network": str(result.network) if result else None,
            }
        )

    @app.get("/api/device/<path:ip_addr>")
    def api_device(ip_addr: str):
        result = state.get("last_result")
        if result is None:
            return jsonify({"error": "No scans have been performed yet."}), 404
        for device in result.devices:
            if device.ip == ip_addr:
                return jsonify(device.to_dict())
        return jsonify({"error": "Device not found."}), 404

    @app.post("/tests/ping")
    def ping_test():
        payload = request.get_json(silent=True) or {}
        ip = payload.get("ip") or request.form.get("ip")
        timeout = payload.get("timeout") or request.form.get("timeout") or 1.0

        if not ip:
            return jsonify({"error": "IP address is required."}), 400

        try:
            latency = utils.ping_host(ip, timeout=float(timeout))
            return jsonify(
                {
                    "ip": ip,
                    "latency_ms": latency,
                    "online": latency is not None,
                }
            )
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 400

    return app


app = create_app()


if __name__ == "__main__":
    logging.basicConfig(level="INFO")
    app.run(host="0.0.0.0", port=5000)
