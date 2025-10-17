"""Flask web application for the network scanner."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, Optional

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    url_for,
)

from src import scanner, utils

DEFAULT_CONCURRENCY = 64
DEFAULT_TIMEOUT = 1.0


def _scan_result_to_dict(result: scanner.ScanResult) -> Dict[str, Any]:
    """Convert a ScanResult into a JSON-serialisable dict."""
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


def _resolve_vendor_path(vendor_file: Optional[str]) -> Optional[Path]:
    if not vendor_file:
        return None
    return Path(vendor_file).expanduser()


def _run_scan(
    cidr: Optional[str],
    concurrency: int,
    timeout: float,
    vendor_file: Optional[str],
) -> scanner.ScanResult:
    """Execute a scan using the asynchronous scanner helpers."""
    network = scanner.parse_targets(cidr)
    return asyncio.run(
        scanner.scan_network(
            network,
            concurrency=concurrency,
            ping_timeout=timeout,
            vendor_map_path=_resolve_vendor_path(vendor_file),
        )
    )


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    state: Dict[str, Any] = {"last_result": None}

    @app.route("/", methods=["GET", "POST"])
    def index():
        error = None
        result: Optional[scanner.ScanResult] = state.get("last_result")

        if request.method == "POST":
            cidr = request.form.get("cidr") or None
            vendor_file = request.form.get("vendor_file") or None
            try:
                concurrency = int(request.form.get("concurrency") or DEFAULT_CONCURRENCY)
                timeout = float(request.form.get("timeout") or DEFAULT_TIMEOUT)
            except ValueError:
                concurrency = DEFAULT_CONCURRENCY
                timeout = DEFAULT_TIMEOUT
                error = "Invalid numeric values provided. Reverting to defaults."

            try:
                result = _run_scan(cidr, concurrency, timeout, vendor_file)
                state["last_result"] = result
            except Exception as exc:  # noqa: BLE001
                error = f"Failed to run scan: {exc}"

        form_values = {
            "cidr": request.form.get("cidr", ""),
            "concurrency": request.form.get("concurrency", str(DEFAULT_CONCURRENCY)),
            "timeout": request.form.get("timeout", str(DEFAULT_TIMEOUT)),
            "vendor_file": request.form.get("vendor_file", ""),
        }

        return render_template(
            "index.html",
            result=result,
            error=error,
            form=form_values,
            api_url=url_for("api_scan"),
        )

    @app.post("/api/scan")
    def api_scan():
        payload = request.get_json(silent=True) or {}
        cidr = payload.get("cidr")
        vendor_file = payload.get("vendor_file")
        concurrency = payload.get("concurrency", DEFAULT_CONCURRENCY)
        timeout = payload.get("timeout", DEFAULT_TIMEOUT)

        try:
            result = _run_scan(cidr, int(concurrency), float(timeout), vendor_file)
            state["last_result"] = result
            return jsonify(_scan_result_to_dict(result))
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/last-scan")
    def api_last_scan():
        result = state.get("last_result")
        if result is None:
            return jsonify({"message": "No scans have been performed yet."}), 404
        return jsonify(_scan_result_to_dict(result))

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
    app.run(debug=True)
