#!/usr/bin/env python3
# Copyright (c) 2014-present, Facebook, Inc.

from setuptools import setup


ptr_params = {
    "entry_point_module": "src/nmapscanner/__init__",
    "test_suite": "nmapscanner.tests.base",
    "test_suite_timeout": 300,
    "required_coverage": {"nmapscanner/__init__.py": 45},
    "run_black": True,
    "run_flake8": True,
    "run_mypy": True,
    # Seems to not like 3.10 match statement ...
    "run_usort": False,
}


setup(
    name="nmapscanner",
    version="22.12.30",
    description=("Run NMAP Scans - Parse Output - Send results to scuba"),
    packages=["nmapscanner", "nmapscanner.tests"],
    package_dir={"": "src"},
    python_requires=">=3.10",
    install_requires=["click", "python-libnmap"],
    entry_points={"console_scripts": ["nmapscanner = nmapscanner:main"]},
    extras_require={
        "influxdb": ["influxdb-client"],
    },
)
