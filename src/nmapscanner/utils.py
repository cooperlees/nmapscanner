import json
import logging
from pathlib import Path
from time import time

from libnmap.parser import NmapParser  # type: ignore


LOG = logging.getLogger(__name__)


def check_afile_and_parse(afile: Path) -> dict:
    if not afile.is_file() or afile.name.endswith(".json"):
        return {}

    # Write out JSON along side ugly XML
    return get_nmap_result(afile)


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
