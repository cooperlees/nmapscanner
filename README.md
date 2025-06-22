# nmapscanner

Wrap NMAP and scan port dumping data to arbitrary data stores.

# Install

From GitHub:
- `pip install git+https://github.com/cooperlees/nmapscanner`

We have extra insallers to pull in non JSON output storage.
- influxdb
  - `pip install git+https://github.com/cooperlees/nmapscanner#egg=nmapscanner[influxdb]`
- mariadb
  - `pip install git+https://github.com/cooperlees/nmapscanner#egg=nmapscanner[mariadb]`

# Usage

This tool is to run from a scanning host and scan hosts you define on via the CLI.
For example, to scan a host and write out JSON files with the results (default)

- `[sudo] nmapscanner [--debug] [--no-udp] --output-dir /tmp/nmapscanner_output_testing HOST_IP`
  - We don't support hostnames, and only IP addresses so we are more explicit here

We also support:
- influxdb (incomplete support)
- mariadb

These could be coupled with Grafana to visualize the results.

# Maria DB Support (mysql)

We need gcc + the mariadb c libraries to build the mariadb client:

- For Fedora you need:
  - `sudo dnf install mariadb-connector-c-devel`
- For Ubuntu/Debian
  - `sudo apt install libmariadb-dev`

## Create Database, User and perms

Feel free to be smarter with perms if you want ... PR welcome :D

- `create database nmapscanner;`
- `CREATE USER 'nmapscanner' IDENTIFIED BY 'nmapscanner';`
  - Change password naturally and optionally lock to localhost if desired
- `GRANT ALL PRIVILEGES ON `nmapscanner`.* TO 'nmapscanner';`

# Development

```console
python3 -m venv [--upgrade-deps] /tmp/tn
/tmp/tn/bin/pip install -e .[mariadb]
````

## Run Tests

For testing we use [ptr](https://github.com/facebookincubator/ptr/).

```console
/tmp/tn/bin/ptr [-k] [--print-cov] [--debug] [--venv]
```

- `-k`: keep testing venv ptr creates
- `--print-cov`: handy to see what coverage is on all files
- `--debug`: Handy to see all commands run so you can run a step manually
- `--venv`: Reuse an already created venv (much faster to launch + run all CI)

# Docker

To build:

- `cooper@l33t:~/repos/nmapscanner$ docker build --network host -t nmapscanner_devel .`