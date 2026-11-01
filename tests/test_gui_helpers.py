"""
tests/test_gui_helpers.py – Unit tests for non-GUI components of control_panel and attacker_console.
"""

import sys
import os
import pytest

from attacker_console import validate_target_address
from control_panel import get_component_commands, is_port_listening


def test_validate_target_address_valid_lab_networks():
    # Loopback (127.0.0.0/8)
    assert validate_target_address("127.0.0.1") is True
    assert validate_target_address("127.0.0.2") is True
    assert validate_target_address("127.255.255.254") is True
    assert validate_target_address("  127.0.0.1  ") is True

    # 192.168.0.0/16
    assert validate_target_address("192.168.1.1") is True
    assert validate_target_address("192.168.0.100") is True
    assert validate_target_address("192.168.254.254") is True

    # 10.0.0.0/8
    assert validate_target_address("10.0.0.1") is True
    assert validate_target_address("10.10.10.10") is True
    assert validate_target_address("10.255.255.1") is True


def test_validate_target_address_rejects_external_and_invalid():
    # Public IPs outside lab scope
    assert validate_target_address("8.8.8.8") is False
    assert validate_target_address("1.1.1.1") is False
    assert validate_target_address("142.250.190.46") is False

    # 172.16.0.0/12 is not in the allowed list (127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8)
    assert validate_target_address("172.16.0.1") is False

    # Disallowed special IPs
    assert validate_target_address("0.0.0.0") is False
    assert validate_target_address("255.255.255.255") is False

    # Malformed strings or non-strings
    assert validate_target_address("") is False
    assert validate_target_address("not_an_ip") is False
    assert validate_target_address("127.0.0") is False
    assert validate_target_address("999.999.999.999") is False
    assert validate_target_address(None) is False


def test_get_component_commands_default_sys_executable():
    cmds = get_component_commands()

    assert "tcp_decoy" in cmds
    assert "http_decoy" in cmds
    assert "worker" in cmds
    assert "dashboard" in cmds

    assert cmds["tcp_decoy"] == [sys.executable, "-m", "honeypot.tcp_decoy"]
    assert cmds["http_decoy"] == [sys.executable, "-m", "honeypot.http_decoy"]
    assert cmds["worker"] == [sys.executable, "worker.py"]
    assert cmds["dashboard"] == [sys.executable, "app.py"]


def test_get_component_commands_custom_executable():
    custom_exe = "/custom/bin/python3"
    cmds = get_component_commands(python_exe=custom_exe)

    assert cmds["tcp_decoy"] == [custom_exe, "-m", "honeypot.tcp_decoy"]
    assert cmds["http_decoy"] == [custom_exe, "-m", "honeypot.http_decoy"]
    assert cmds["worker"] == [custom_exe, "worker.py"]
    assert cmds["dashboard"] == [custom_exe, "app.py"]


def test_is_port_listening_closed_port():
    # Port 59999 should not be listening
    assert is_port_listening("127.0.0.1", 59999, timeout=0.1) is False

