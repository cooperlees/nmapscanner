#!/usr/bin/env python3

from pathlib import Path

from influxdb_client import InfluxDBClient  # type: ignore

from nmapscanner import load_json_file

influx_settings = load_json_file(Path("/etc/nmapscanner.json"))
print(f"Using settings: {influx_settings}")

with InfluxDBClient(
    influx_settings["url"],
    token=influx_settings["token"],
    org=influx_settings["org"],
    debug=influx_settings["debug"],
) as client:
    query = f'from(bucket:"{influx_settings["bucket"]}") |> range(start: -1h)'
    print(f"query:\n'{query}'")
    tables = client.query_api().query(query, org=influx_settings["org"])
    output = tables.to_json(indent=4)
    print(output)
