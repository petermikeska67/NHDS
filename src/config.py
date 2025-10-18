"""Configuration management for the network scanner."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"
FALLBACK_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.example.yaml"
ENV_CONFIG_PATH = "NSHS_CONFIG_FILE"


@dataclass(slots=True)
class DeviceAlias:
    """Represents a user-defined device alias."""

    name: str
    tags: List[str] = field(default_factory=list)
    ip: Optional[str] = None
    mac_prefix: Optional[str] = None


@dataclass(slots=True)
class NotificationSettings:
    enabled: bool = False
    webhook_url: Optional[str] = None
    secret: Optional[str] = None
    timeout: float = 5.0
    discord_webhook_url: Optional[str] = None


@dataclass(slots=True)
class NetworkSettings:
    default_cidr: Optional[str] = None
    concurrency: int = 64
    timeout: float = 1.0
    vendor_remote: bool = True
    vendor_refresh: bool = False
    arp_timeout: float = 2.0
    history_max: int = 100
    history_path: Optional[str] = None


@dataclass(slots=True)
class WebSettings:
    require_auth: bool = False
    auth_token: Optional[str] = None


@dataclass(slots=True)
class AppConfig:
    network: NetworkSettings = field(default_factory=NetworkSettings)
    notifications: NotificationSettings = field(default_factory=NotificationSettings)
    web: WebSettings = field(default_factory=WebSettings)
    devices: List[DeviceAlias] = field(default_factory=list)


_CONFIG_CACHE: Optional[AppConfig] = None


def _resolve_config_path() -> Path:
    env_path = os.getenv(ENV_CONFIG_PATH)
    if env_path:
        return Path(env_path).expanduser()
    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    return FALLBACK_CONFIG_PATH


def _load_yaml(path: Path) -> Dict:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
            if not isinstance(data, dict):
                raise ValueError("Configuration root must be a mapping")
            return data
    except FileNotFoundError:
        return {}


def _build_aliases(raw_aliases: List[Dict]) -> List[DeviceAlias]:
    aliases: List[DeviceAlias] = []
    for item in raw_aliases:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not name:
            continue
        tags = item.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        aliases.append(
            DeviceAlias(
                name=name,
                tags=list(tags),
                ip=item.get("ip"),
                mac_prefix=(item.get("mac_prefix") or item.get("mac")),
            )
        )
    return aliases


def _build_config(raw: Dict) -> AppConfig:
    network_cfg = raw.get("network", {})
    notifications_cfg = raw.get("notifications", {})
    web_cfg = raw.get("web", {})
    device_cfg = raw.get("devices", [])

    network = NetworkSettings(
        default_cidr=network_cfg.get("default_cidr"),
        concurrency=int(network_cfg.get("concurrency", 64)),
        timeout=float(network_cfg.get("timeout", 1.0)),
        vendor_remote=bool(network_cfg.get("vendor_remote", True)),
        vendor_refresh=bool(network_cfg.get("vendor_refresh", False)),
        arp_timeout=float(network_cfg.get("arp_timeout", 2.0)),
        history_max=int(network_cfg.get("history_max", 100)),
        history_path=network_cfg.get("history_path"),
    )

    notifications = NotificationSettings(
        enabled=bool(notifications_cfg.get("enabled", False)),
        webhook_url=notifications_cfg.get("webhook_url") or None,
        secret=notifications_cfg.get("secret") or None,
        timeout=float(notifications_cfg.get("timeout", 5.0)),
        discord_webhook_url=notifications_cfg.get("discord_webhook_url") or None,
    )

    web = WebSettings(
        require_auth=bool(web_cfg.get("require_auth", False)),
        auth_token=web_cfg.get("auth_token") or None,
    )

    aliases = _build_aliases(device_cfg if isinstance(device_cfg, list) else [])

    return AppConfig(
        network=network,
        notifications=notifications,
        web=web,
        devices=aliases,
    )


def load_config(force_reload: bool = False) -> AppConfig:
    """Load and cache configuration."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None and not force_reload:
        return _CONFIG_CACHE

    path = _resolve_config_path()
    raw = _load_yaml(path)
    config = _build_config(raw)
    _CONFIG_CACHE = config
    return config


def match_alias(ip: Optional[str], mac: Optional[str]) -> Optional[DeviceAlias]:
    """Return the alias that matches the provided IP or MAC."""
    config = load_config()
    mac_upper = mac.upper() if mac else None
    for alias in config.devices:
        if alias.ip and ip == alias.ip:
            return alias
        if alias.mac_prefix and mac_upper:
            prefix = alias.mac_prefix.upper().rstrip("*")
            if mac_upper.startswith(prefix):
                return alias
    return None


def config_to_dict(cfg: AppConfig) -> Dict:
    """Serialize AppConfig into a dictionary suitable for YAML dumping."""
    return {
        "network": {
            "default_cidr": cfg.network.default_cidr,
            "concurrency": cfg.network.concurrency,
            "timeout": cfg.network.timeout,
            "vendor_remote": cfg.network.vendor_remote,
            "vendor_refresh": cfg.network.vendor_refresh,
            "arp_timeout": cfg.network.arp_timeout,
            "history_max": cfg.network.history_max,
            "history_path": cfg.network.history_path,
        },
        "notifications": {
            "enabled": cfg.notifications.enabled,
            "webhook_url": cfg.notifications.webhook_url or "",
            "secret": cfg.notifications.secret or "",
            "timeout": cfg.notifications.timeout,
            "discord_webhook_url": cfg.notifications.discord_webhook_url or "",
        },
        "web": {
            "require_auth": cfg.web.require_auth,
            "auth_token": cfg.web.auth_token or "",
        },
        "devices": [
            _alias_to_dict(alias) for alias in cfg.devices
        ],
    }


def _alias_to_dict(alias: DeviceAlias) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "name": alias.name,
        "tags": alias.tags,
    }
    if alias.ip:
        data["ip"] = alias.ip
    if alias.mac_prefix:
        data["mac_prefix"] = alias.mac_prefix
    return data


def save_config(cfg: AppConfig, path: Optional[Path] = None) -> Path:
    """Persist the configuration to disk."""
    target = path or _resolve_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    data = config_to_dict(cfg)
    # Remove empty strings for optional fields
    if not data["notifications"]["webhook_url"]:
        data["notifications"].pop("webhook_url")
    if not data["notifications"]["secret"]:
        data["notifications"].pop("secret")
    if not data["notifications"]["discord_webhook_url"]:
        data["notifications"].pop("discord_webhook_url")
    if not data["network"]["history_path"]:
        data["network"].pop("history_path")
    if not data["web"]["auth_token"]:
        data["web"].pop("auth_token")

    with target.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False)

    # Reset cache to ensure subsequent reads pick up changes
    load_config(force_reload=True)
    return target
