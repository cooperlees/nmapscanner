#!/usr/bin/env python3

from setuptools import setup


ptr_params = {
    "entry_point_module": "src/nmapscanner/__init__",
    "test_suite": "nmapscanner.tests.base",
    "test_suite_timeout": 30,
    "required_coverage": {"nmapscanner/__init__.py": 45},
    "run_black": True,
    "run_flake8": True,
    "run_mypy": True,
    "run_usort": True,
}


setup(
    name="nmapscanner",
    version="25.6.22",
    description=("Run NMAP Scans - Parse Output - Send results to scuba"),
    packages=["nmapscanner", "nmapscanner.tests"],
    package_dir={"": "src"},
    python_requires=">=3.13",
    install_requires=["click", "python-libnmap"],
    entry_points={"console_scripts": ["nmapscanner = nmapscanner:main"]},
    extras_require={
        "influxdb": ["influxdb-client"],
    },
)
