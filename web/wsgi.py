"""WSGI entry point for production servers (gunicorn/uwsgi)."""

from __future__ import annotations

from .app import create_app

app = create_app()
