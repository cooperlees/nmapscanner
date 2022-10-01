#!/usr/bin/env python3
# Copyright (c) 2014-present, Facebook, Inc.

import json
import logging
import shlex
from concurrent.futures import as_completed, ThreadPoolExecutor
from copy import copy
from datetime import datetime
from ipaddress import ip_network, IPv4Network, IPv6Network
from os import sep
from pathlib import Path
from subprocess import PIPE, run, SubprocessError
from tempfile import gettempdir
from time import time
from typing import Dict, List, Optional, Union

import click

# TODO: Workout why mypy can not find this module
from libnmap.parser import NmapParser  # type: ignore


DF = "%Y%m%d%H%M%S"
LOG = logging.getLogger(__name__)


def _handle_debug(
    ctx: click.core.Context,
    param: Union[click.core.Option, click.core.Parameter],
    debug: Union[bool, int, str],
) -> Union[bool, int, str]:
    """Turn on debugging if asked otherwise INFO default"""
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        format="[%(asctime)s] %(levelname)s: %(message)s (%(filename)s:%(lineno)d)",
        level=log_level,
    )
    return debug


def get_nmap_result(nmap_xml_file: Path) -> Dict:
    """Turn the NMAP results into a scuba friendly JSON object"""
    nmap_data: Dict = {}

    nmap_report = NmapParser.parse_fromfile(str(nmap_xml_file))
    # We should only ever have one host due to our parallell nmap runs get prefix
    host = nmap_report.hosts.pop()

    nmap_data["endtime"] = int(host.endtime)
    nmap_data["numservices"] = int(nmap_report._scaninfo["numservices"])
    nmap_data["scanruntime"] = int(host.endtime) - int(host.starttime)
    nmap_data["starttime"] = int(host.starttime)
    nmap_data["time"] = int(time())

    nmap_data["address"] = str(host.address)
    nmap_data["command"] = str(nmap_report.commandline)
    nmap_data["is_up"] = str(host.is_up())
    nmap_data["nmap_version"] = str(nmap_report.version)
    nmap_data["os"] = str(host.os)
    nmap_data["protocol"] = str(nmap_report._scaninfo["protocol"])
    nmap_data["services"] = str(nmap_report._scaninfo["services"])
    nmap_data["status"] = str(host.status)
    nmap_data["type"] = str(nmap_report._scaninfo["type"])

    open_ports: List[str] = []
    for port, proto in host.get_ports():
        open_ports.append(f"{port}/{proto}")
    nmap_data["open_ports"] = open_ports

    return nmap_data


def sanitize_filename(filename: str) -> str:
    return filename.replace("/", "_")


def generate_nmap_cmd(
    ipnet: Union[IPv4Network, IPv6Network],
    output_path: Path,
    nmap: Path,
    timeout: int,
    custom_args: List[str],
    all_ports: bool,
) -> List[List[str]]:
    nmap_cmds: List[List[str]] = []
    nmap_base_cmd = [str(nmap)]
    if ipnet.version == 6:
        nmap_base_cmd.append("-6")

    if all_ports:
        # This causes NMAP to scan all 65k ports
        nmap_base_cmd.append("-p-")

    if custom_args:
        output_logfile = output_path / sanitize_filename(f"{str(ipnet)}_CUSTOM")
        nmap_cmd = nmap_base_cmd
        nmap_cmd.extend(custom_args)
        nmap_cmd.extend(["-oX", str(output_logfile), str(ipnet)])
        nmap_cmds.append(nmap_cmd)
    else:
        for nmap_proto in ("-sS", "-sU"):
            nmap_cmd = copy(nmap_base_cmd)
            protocol = "TCP"
            if nmap_proto == "-sU":
                protocol = "UDP"

            output_logfile = output_path / sanitize_filename(f"{str(ipnet)}_{protocol}")
            # -Pn stops ping probe detection
            # -oX gives us XML output to parse
            nmap_cmd.extend(["-Pn", nmap_proto, "-oX", str(output_logfile), str(ipnet)])
            nmap_cmds.append(nmap_cmd)

    return nmap_cmds


def nmap_prefix(
    ipnet: Union[IPv4Network, IPv6Network],
    output_path: Path,
    nmap: Path,
    timeout: int,
    custom_args: List[str],
    all_ports: bool,
) -> int:
    nmap_cmds = generate_nmap_cmd(
        ipnet, output_path, nmap, timeout, custom_args, all_ports
    )
    custom = " CUSTOM " if custom_args else " "
    for nmap_cmd in nmap_cmds:
        err = 0
        start_time = time()
        friendly_nmap_cmd = " ".join(nmap_cmd)
        LOG.info(f"{ipnet} -{custom}'{friendly_nmap_cmd}' starting")
        try:
            LOG.debug(
                run(nmap_cmd, stdout=PIPE, stderr=PIPE, timeout=timeout, check=True)
            )
        except SubprocessError as spe:
            LOG.error(f"{ipnet} - '{nmap_cmd}' FAILED: {spe}")
            err += 1
            continue

        runtime = int(time() - start_time)
        LOG.info(f"{ipnet} -{custom}'{friendly_nmap_cmd}' complete ({runtime}s)")

    return err


def run_nmap(
    prefixes: List[str],
    output_path: Path,
    atonce: int,
    nmap: Path,
    nmap_timeout: int,
    nmap_opts: Optional[str],
    all_ports: bool,
) -> None:
    nmap_futures = []

    shell_safe_extra_ops: List[str] = []
    if nmap_opts:
        shell_safe_extra_ops = shlex.split(nmap_opts)

    with ThreadPoolExecutor(max_workers=atonce) as executor:
        for prefix in prefixes:
            LOG.info(f"Adding {prefix} scans to run queue")
            nmap_futures.append(
                executor.submit(
                    nmap_prefix,
                    ip_network(prefix),
                    output_path,
                    nmap,
                    nmap_timeout,
                    shell_safe_extra_ops,
                    all_ports,
                )
            )

        success = 0
        fail = 0
        total = len(nmap_futures)
        LOG.info(f"Running {total} nmap scans")
        for future in as_completed(nmap_futures):
            if future.result():
                fail += 1
            else:
                success += 1

            done = success + fail
            LOG.debug(f"{done} / {total} completed ... ({done / total * 100}%)")

        success_pct = int((success / total) * 100)
        LOG.info(
            f"{success} / {total} ({success_pct}%) nmap scans succeeded ({fail} failed)"
        )


def write_to_json_files(output_path: Path) -> int:
    """Temp function to output the scan resilt to JSON
    TODO: Come up with support for multiple data sources
    e.g. SQL DB, MongoDB, Prometheus etc."""
    fails = 0
    for afile in output_path.iterdir():
        if not afile.is_file() or afile.name.endswith(".json"):
            continue

        # Write out JSON along side ugly XML
        json_results = get_nmap_result(afile)
        new_json_file = output_path / f"{afile.name}.json"
        try:
            with new_json_file.open("w") as njfp:
                json.dump(json_results, njfp, sort_keys=True, indent=2)
        except OSError:
            LOG.exception(f"Failed to write JSON out to {new_json_file}")
            fails += 1

    return fails


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--atonce",
    default=10,
    show_default=True,
    help="How many nmap scans should happen at once",
)
@click.option(
    "-A",
    "--all-ports",
    is_flag=True,
    show_default=True,
    help="Have nmap scan all 65k TCP + UDP ports",
)
@click.option(
    "--debug",
    is_flag=True,
    callback=_handle_debug,
    show_default=True,
    help="Turn on debug logging",
)
@click.option(
    "--nmap", default="/usr/bin/nmap", show_default=True, help="Path to nmap binary"
)
@click.option(
    "-N",
    "--nmap-opts",
    default=None,
    show_default=True,
    help="Custom nmap opts - defaults are dropped: https://nmap.org/book/man.html",
)
@click.option(
    "--nmap-timeout",
    default=1800,  # 30 mins
    show_default=True,
    help="How long should we allow nmap to run",
)
@click.option(
    "--output-dir",
    default=f"{gettempdir()}{sep}nmapscanner_run_{datetime.now().strftime(DF)}",
    show_default=True,
    help="Where should we store nmap output",
)
@click.argument("prefixes", nargs=-1)
@click.pass_context
def main(
    ctx,
    all_ports: bool,
    atonce: int,
    debug: bool,
    nmap: str,
    nmap_opts: Optional[str],
    nmap_timeout: int,
    output_dir: str,
    prefixes: List[str],
) -> None:
    nmap_path = Path(nmap)
    if not nmap_path.exists():
        LOG.error(
            f"{nmap} does not exist. Please pass a valid nmap bin path to --nmap."
        )
        ctx.exit(69)

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    LOG.debug(f"nmap output will go to {output_path}")

    run_nmap(
        prefixes, output_path, atonce, nmap_path, nmap_timeout, nmap_opts, all_ports
    )
    ctx.exit(write_to_json_files(output_path))


if __name__ == "__main__":
    main()
