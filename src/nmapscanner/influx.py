import logging
from datetime import datetime
from pathlib import Path

from . import utils


LOG = logging.getLogger(__name__)


def write_to_influxdb(influx_settings: dict[str, int | str], output_path: Path) -> int:
    # Import here so we only try import if we want influx
    from influxdb_client import InfluxDBClient  # type: ignore
    from influxdb_client.client.write_api import SYNCHRONOUS  # type: ignore

    json_results = None
    for afile in output_path.iterdir():
        json_results = utils.check_afile_and_parse(afile)
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
