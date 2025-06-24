#!/usr/bin/env python3

import unittest

from nmapscanner import utils


class TestUtils(unittest.TestCase):
    maxDiff = 20000

    def test_unix_to_datetime(self) -> None:
        ts = 1690000000
        expected = "2023-07-22 04:26:40"
        self.assertEqual(utils.unix_to_datetime(ts), expected)


if __name__ == "__main__":
    unittest.main()
