#!/usr/bin/env python3

import unittest
from ipaddress import ip_address
from json import dumps
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import patch

import nmapscanner

from . import base_fixtures as bf


class TestNts(unittest.TestCase):
    maxDiff = 20000

    def test_generate_nmap_cmd(self) -> None:
        ipaddr = ip_address("69::69")
        output_path = Path("/tmp/no")
        nmap = Path("/bin/nmap")
        timeout = 69

        self.assertEqual(
            nmapscanner.generate_nmap_cmd(
                ipaddr, output_path, nmap, timeout, None, False
            ),
            bf.EXPECTED_NMAP_DEFAULT_CMDS,
        )

        # Scan all the ports expected
        self.assertEqual(
            nmapscanner.generate_nmap_cmd(
                ipaddr, output_path, nmap, timeout, None, True
            ),
            bf.EXPECTED_NMAP_ALL_PORTS_CMDS,
        )

        custom_args = ["-sU", "-p", "69"]
        self.assertEqual(
            nmapscanner.generate_nmap_cmd(
                ipaddr, output_path, nmap, timeout, custom_args, False
            ),
            bf.EXPECTED_NMAP_CUSTOM_CMD,
        )

    @patch("nmapscanner.utils.time")
    def test_get_nmap_result(self, mock_time) -> None:
        # We need the time to be the same to match our fixtures
        mock_time.return_value = 0
        for xml, expected in (
            (bf.SAMPLE_NMAP_XML_TCP, bf.EXPECTED_NMAP_DATA_TCP),
            (bf.SAMPLE_NMAP_XML_UDP, bf.EXPECTED_NMAP_DATA_UDP),
        ):
            with NamedTemporaryFile("w", delete=False) as tf:
                tf_path = Path(tf.name)
                tf.write(xml)
                tf.close()

                nmap_data = nmapscanner.utils.get_nmap_result(tf_path)
                self.assertEqual(nmap_data, expected)
                # Test we're JSON seralizable
                self.assertTrue(dumps(nmap_data))

                tf_path.unlink()

    def test_write_to_json_files(self) -> None:
        with TemporaryDirectory() as td:
            td_path = Path(td)
            xml_file_path = td_path / "udp.xml"
            with xml_file_path.open("w") as xfp:
                xfp.write(bf.SAMPLE_NMAP_XML_UDP)

            self.assertEqual(0, nmapscanner.write_to_json_files(td_path))
            found_json = False
            for aFile in td_path.iterdir():
                if aFile.name.endswith(".json"):
                    found_json = True
                    break
            self.assertTrue(found_json)


if __name__ == "__main__":
    unittest.main()
