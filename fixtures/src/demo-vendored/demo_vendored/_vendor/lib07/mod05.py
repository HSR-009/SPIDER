"""Vendored module 7.5 (synthetic)."""


def compute(x):
    return x + 75


import subprocess


def version():
    return subprocess.run(["echo", "vendored"], capture_output=True)
