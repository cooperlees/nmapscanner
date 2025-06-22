#!/usr/bin/env python3

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
from typing import Optional, Union

import click
from libnmap.parser import NmapParser  # type: ignore


DF = "%Y%m%d%H%M%S"
LOG = logging.getLogger(__name__)
OUTPUT_FORMATS = ("influxdb", "json")


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


def get_nmap_result(nmap_xml_file: Path) -> dict:
    """Turn the NMAP results into a scuba friendly JSON object"""
    nmap_data: dict = {}

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

    open_ports: list[str] = []
    for port, proto in host.get_ports():
        open_ports.append(f"{port}/{proto}")
    nmap_data["open_ports"] = open_ports

    return nmap_data


def load_json_file(jf: Path) -> dict:
    try:
        with jf.open("r") as jfp:
            return json.load(jfp)
    except (json.JSONDecodeError, OSError):
        LOG.exception(f"Failure to load {jf}")
    return {}


def sanitize_filename(filename: str) -> str:
    return filename.replace("/", "_")


def generate_nmap_cmd(
    ipnet: Union[IPv4Network, IPv6Network],
    output_path: Path,
    nmap: Path,
    timeout: int,
    custom_args: list[str],
    all_ports: bool,
) -> list[list[str]]:
    nmap_cmds: list[list[str]] = []
    nmap_base_cmd = [str(nmap), "-T5"]
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
    custom_args: list[str],
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
            LOG.error(f"{ipnet} - \"{' '.join(nmap_cmd)}\" FAILED: {spe}")
            LOG.debug("Are you running as root / with capabilities?")
            err += 1
            continue

        runtime = int(time() - start_time)
        LOG.info(f"{ipnet} -{custom}'{friendly_nmap_cmd}' complete ({runtime}s)")

    return err


def run_nmap(
    prefixes: list[str],
    output_path: Path,
    atonce: int,
    nmap: Path,
    nmap_timeout: int,
    nmap_opts: Optional[str],
    all_ports: bool,
) -> int:
    nmap_futures = []

    shell_safe_extra_ops: list[str] = []
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

        if success < 1:
            LOG.error("No nmap scans completed ... Giving up!")
            return 1

        success_pct = int((success / total) * 100)
        LOG.info(
            f"{success} / {total} ({success_pct}%) nmap scans succeeded ({fail} failed)"
        )
        return 0


def _check_afile_and_parse(afile: Path) -> dict:
    if not afile.is_file() or afile.name.endswith(".json"):
        return {}

    # Write out JSON along side ugly XML
    return get_nmap_result(afile)


def write_to_json_files(output_path: Path) -> int:
    """Output the scan result to JSON files"""
    fails = 0
    for afile in output_path.iterdir():
        json_results = _check_afile_and_parse(afile)
        if not json_results:
            continue

        new_json_file = output_path / f"{afile.name}.json"
        try:
            with new_json_file.open("w") as njfp:
                json.dump(json_results, njfp, sort_keys=True, indent=2)
        except OSError:
            LOG.exception(f"Failed to write JSON out to {new_json_file}")
            fails += 1

    return fails


def write_to_influxdb(
    influx_settings: dict[str, Union[int, str]], output_path: Path
) -> int:
    from influxdb_client import InfluxDBClient  # type: ignore
    from influxdb_client.client.write_api import SYNCHRONOUS  # type: ignore

    json_results = None
    for afile in output_path.iterdir():
        json_results = _check_afile_and_parse(afile)
        if not json_results:
            continue

    if not json_results:
        LOG.error(f"No JSON files to parse + generate influxdb from in {output_path}")
        return 9

    current_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    measurements: list[dict] = []
    # Count of protocol open ports
    measurements.append(
        {
            "measurement": f"{json_results['protocol']}_open_ports",
            "tags": {"address": json_results["address"]},
            "time": current_time,
            "fields": {"open_port_count": len(json_results["open_ports"])},
        }
    )
    # Add each open port
    proto_port_measurement_name = f"{json_results['protocol']}_open_port"
    for port_name in json_results["open_ports"]:
        port_int = int(port_name.split("/", 1)[0])
        measurements.append(
            {
                "measurement": proto_port_measurement_name,
                "tags": {"address": json_results["address"]},
                "time": current_time,
                "fields": {"open_port": port_int},
            }
        )

    try:
        with InfluxDBClient(
            influx_settings["url"],
            token=influx_settings["token"],
            org=influx_settings["org"],
        ) as client:
            write_api = client.write_api(write_options=SYNCHRONOUS)
            LOG.debug(f"Writing {measurements} to {influx_settings['bucket']}")
            write_api.write(influx_settings["bucket"], measurements)
    except Exception:
        LOG.exception(f"Unable to write measurements to {influx_settings['url']}")
        return 10

    return 0


def write_output(output_format: str, output_path: Path, output_config_file: str) -> int:
    match output_format:
        case "json":
            errors = write_to_json_files(output_path)
            if not errors:
                print(f"--> JSON files written to {output_path}")
            return errors
        case "influxdb":
            output_config_path = Path(output_config_file)
            if not output_config_path.exists():
                LOG.error(f"{output_config_path} does not exist.")
                return 68

            return write_to_influxdb(load_json_file(output_config_path), output_path)
        case other:
            LOG.error(
                f"{other} is an invalid unsupported output format. Fix CLI arguments"
            )
    return 69


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
    "--output-config-file",
    default="/etc/nmapscanner.json",
    show_default=True,
    help="JSON file with kwargs to pass to your output format function - e.g. influxdb",
)
@click.option(
    "--output-dir",
    default=f"{gettempdir()}{sep}nmapscanner_run_{datetime.now().strftime(DF)}",
    show_default=True,
    help=(
        "Where should we store nmap output (XML + optional file output formats "
        + "e.g. json)"
    ),
)
@click.option(
    "--output-format",
    default="json",
    show_default=True,
    help=f"Where should port status be saved. Options: {','.join(sorted(OUTPUT_FORMATS))}",
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
    output_config_file: str,
    output_dir: str,
    output_format: str,
    prefixes: list[str],
) -> None:
    nmap_path = Path(nmap)
    if not nmap_path.exists():
        LOG.error(
            f"{nmap} does not exist. Please pass a valid nmap bin path to --nmap."
        )
        ctx.exit(69)

    if not prefixes:
        LOG.error("Need some prefixes to scan please")
        ctx.exit(70)

    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    LOG.debug(f"nmap output will go to {output_path}")

    if errors := run_nmap(
        prefixes, output_path, atonce, nmap_path, nmap_timeout, nmap_opts, all_ports
    ):
        ctx.exit(errors)

    ctx.exit(write_output(output_format, output_path, output_config_file))


if __name__ == "__main__":
    main()
