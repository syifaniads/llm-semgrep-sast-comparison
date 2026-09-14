"""Intentionally vulnerable command/code injection fixture for SAST testing."""

import os
import re
import subprocess


def ping_host_vulnerable(hostname):
    os.system("ping -c 4 " + hostname)


def get_file_info_vulnerable(filename):
    return subprocess.run(
        "file " + filename,
        shell=True,
        capture_output=True,
        text=True,
    ).stdout


def calculate_vulnerable(expression):
    return eval(expression)


def ping_host_secure(hostname):
    if not re.match(r"^[a-zA-Z0-9.\-]+$", hostname):
        raise ValueError("Invalid hostname")
    return subprocess.run(
        ["ping", "-c", "4", hostname],
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
