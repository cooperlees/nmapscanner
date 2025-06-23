# type: ignore
# TODO: Fix typing + install mariadb module in CI

import json
import logging
from datetime import datetime
from pathlib import Path

from . import utils


LOG = logging.getLogger(__name__)
TABLE_NAME = "scans"


## SQL Fun

CREATE_TABLE_SQL = """\
CREATE TABLE {table} (
  id INT AUTO_INCREMENT,
  address INET6 NOT NULL,
  command TEXT NOT NULL,
  endtime DATETIME NOT NULL,
  is_up BOOLEAN NOT NULL,
  nmap_version VARCHAR(10) NOT NULL,
  numservices INT UNSIGNED NOT NULL,
  open_ports JSON NOT NULL,
  os TEXT,
  protocol VARCHAR(10) NOT NULL,
  scanruntime INT UNSIGNED NOT NULL,
  services TEXT,
  starttime DATETIME NOT NULL,
  status VARCHAR(10) NOT NULL,
  time DATETIME NOT NULL,
  type VARCHAR(10) NOT NULL,
  PRIMARY KEY (id),
  KEY idx_address (address),
  KEY idx_starttime (starttime),
  KEY idx_endtime (endtime)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

INSERT_SCAN_SQL = """\
INSERT INTO {table} (
  address, command, endtime, is_up, nmap_version, numservices, open_ports, os, protocol, scanruntime, services, starttime, status, time, type
) VALUES (
  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
"""


def _create_mariadb_table(cursor) -> None:
    """If we don't detect the scans table create it"""
    from mariadb import ProgrammingError

    # Check if table exists ... create if not ...
    try:
        cursor.execute("SELECT count(*) FROM scans")
    except ProgrammingError as mpe:
        if "doesn't exist" in str(mpe):
            LOG.info("Creating 'scans' table as it does not exist")
            cursor.execute(CREATE_TABLE_SQL.format(table=TABLE_NAME))


def _insert_scan_results(conn, cursor, output_path) -> int:
    def _unix_to_datetime(ts: int) -> str:
        return datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    results: list[dict] = []
    for afile in output_path.iterdir():
        scan_results = utils.check_afile_and_parse(afile)
        if not scan_results:
            continue
        results.append(scan_results)

    if not results:
        LOG.error(f"No nmap xml files to parse in {output_path} for mariadb write")
        return 9

    for result in results:
        values = (
            result["address"],
            result["command"],
            _unix_to_datetime(result["endtime"]),
            True if result["is_up"] == "True" else False,
            result["nmap_version"],
            result["numservices"],
            json.dumps(result["open_ports"]),
            result["os"],
            result["protocol"],
            result["scanruntime"],
            result["services"],
            _unix_to_datetime(result["starttime"]),
            result["status"],
            _unix_to_datetime(result["time"]),
            result["type"],
        )
        cursor.execute(INSERT_SCAN_SQL.format(table=TABLE_NAME), values)
        conn.commit()


def write(settings: dict, output_path: Path) -> int:
    """Parse all the nmap XML output + write into mysql"""
    import mariadb

    try:
        with mariadb.connect(**settings) as conn:
            with conn.cursor() as cursor:
                _create_mariadb_table(cursor)
                # For each file, pase and insert into DB
                return _insert_scan_results(conn, cursor, output_path)
    except mariadb.Error as me:
        LOG.error(f"Error with MariaDB: {me}")
        return 69  # TODO: See if the exception has an error number
