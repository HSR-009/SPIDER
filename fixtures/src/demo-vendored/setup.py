"""Synthetic fixture: standard setup() call, no custom install command."""
from setuptools import find_packages, setup

setup(name="demo-vendored", version="3.1.0", packages=find_packages())
