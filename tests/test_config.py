"""
tests/test_config.py – Unit tests verifying environment variable overrides for config.
"""

import os
import importlib
import pytest
import config


def test_config_defaults(monkeypatch):
    monkeypatch.delenv("DECOY_BIND_HOST", raising=False)
    monkeypatch.delenv("DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("DATABASE_PATH", raising=False)

    importlib.reload(config)

    assert config.DECOY_BIND_HOST == "127.0.0.1"
    assert config.DASHBOARD_HOST == "127.0.0.1"
    assert config.DATABASE_PATH.endswith(os.path.join("data", "soc.db"))


def test_config_env_overrides(monkeypatch):
    monkeypatch.setenv("DECOY_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("DASHBOARD_HOST", "0.0.0.0")
    monkeypatch.setenv("DATABASE_PATH", "/app/data/soc.db")

    importlib.reload(config)

    assert config.DECOY_BIND_HOST == "0.0.0.0"
    assert config.DASHBOARD_HOST == "0.0.0.0"
    assert config.DATABASE_PATH == "/app/data/soc.db"

    # Reset config back to clean defaults
    monkeypatch.delenv("DECOY_BIND_HOST", raising=False)
    monkeypatch.delenv("DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("DATABASE_PATH", raising=False)
    importlib.reload(config)

