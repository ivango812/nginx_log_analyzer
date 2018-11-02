#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import log_analyzer
import os
import filecmp


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.config = {
            "REPORT_SIZE": 1000,
            "REPORT_DIR": "./reports_test",
            "REPORT_HTML_TEMPLATE": "./report.html",
            "LOG_DIR": "./log_test",
            "LOGGING_TO_FILE": True,
            "LOGGING_LEVEL": log_analyzer.logging.DEBUG
        }

        # log_file = 'nginx-access-ui.log-20180101'
        report_file = 'report-2018.01.01.html'
        self.source_path = os.path.join(self.config['LOG_DIR'], report_file)
        self.report_path = os.path.join(self.config['REPORT_DIR'], report_file)

        if os.path.exists(self.report_path):
            os.remove(self.report_path)


    def test_main(self):

        log_analyzer.main(self.config)
        filecmp.clear_cache()
        self.assertTrue(filecmp.cmp(self.source_path, self.report_path), 'Report file is not equal to sample Report!')


if __name__ == "__main__":
    unittest.main()