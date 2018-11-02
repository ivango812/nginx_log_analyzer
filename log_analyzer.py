#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import os
import re
import sys
import gzip
import json
import shutil
import logging
import operator
import argparse
import configparser
from typing import Pattern
from string import Template
from datetime import datetime
from collections import namedtuple


config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "REPORT_HTML_TEMPLATE": "./report.html",
    "LOG_DIR": "./log",
    "LOGGING_TO_FILE": False,
    "LOGGING_LEVEL": logging.DEBUG
}

LOG_LINE_REGEXP = (r"^(?P<remote_host>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) +" 
                  """(?P<remote_user>[^ ]+) +"""
                  """(?P<http_x_real_ip>[^ ]+) +"""
                  """(?P<time_local>\[[^\]]+\]) +"""
                  """"[a-z]+ (?P<request>[^"]+) HTTP[^"]+" +"""
                  """(?P<status>[^ ]+) +"""
                  """(?P<body_bytes_sent>[^ ]+) +"""
                  """"(?P<http_referer>[^"]+)" +"""
                  """"(?P<http_user_agent>[^"]+)" +"""
                  """"(?P<http_x_forwarded_for>[^"]+)" +"""
                  """"(?P<http_X_REQUEST_ID>[^"]+)" +"""
                  """"(?P<http_X_RB_USER>[^"]+)" +"""
                  """(?P<request_time>[0-9]+\.[0-9]+)$""")
log_line_pattern = re.compile(LOG_LINE_REGEXP, re.IGNORECASE)

MAX_ERROR_COUNT = 100
MAX_ERROR_PERCENT = 0.1
FLOAT_PRECISION = 3
LogFile = namedtuple('LogFile', ['filename', 'date'])
StatCount = namedtuple('StatCount', ['lines', 'urls', 'time', 'errors'])
ANALYZER_LOG_FILENAME = './logfile.log'


def get_script_args():
    parser = argparse.ArgumentParser("log_analyzer.py")
    parser.add_argument('--config', help="config filename path")
    args = parser.parse_args()
    return args


def configure_logger(is_logging_to_file=None, level=logging.DEBUG):
    logging_filename = ANALYZER_LOG_FILENAME if is_logging_to_file else None
    logging.basicConfig(filename=logging_filename,
                        format="[%(asctime)s] %(levelname).1s %(message)s",
                        datefmt="%Y.%m.%d %H:%M:%S",
                        level=level)


def handle_config_file(config, filename):
    configfile = configparser.ConfigParser(config)
    configfile.optionxform = str
    configfile.read(filename)
    configfile_dict = dict(configfile._sections['config'])
    config.update(configfile_dict)  # Overwriting config options from file
    config['REPORT_SIZE'] = int(config['REPORT_SIZE'])


def median(lst):
    """
    Calculates list mediana
    """
    n = len(lst)
    if n < 1:
        return None
    if n % 2 == 1:
        return sorted(lst)[n//2]
    else:
        return sum(sorted(lst)[n//2-1:n//2+1])/2.0


def prepare_report_dir(report_dir):
    """
    Check and create REPORT_DIR
    Check and copy file: jquery.tablesorter.min.js
    """

    if not os.path.isdir(report_dir):
        os.mkdir(report_dir)

    jquery_file_src = 'jquery.tablesorter.min.js'
    jquery_file_dest = os.path.join(report_dir, jquery_file_src)
    if not os.path.isfile(jquery_file_dest):
        shutil.copyfile(jquery_file_src, jquery_file_dest)


def build_report_filepath(report_dir, dt):
    """
    Build report file path
    """
    return os.path.join(report_dir, "report-%s.html" % dt.strftime("%Y.%m.%d"))


def get_latest_log_filename(log_dir):
    """
    Search latest (by date in filename) log file matches template nginx-access-ui.log-<YearMonthDay> or .gz
    :param log_dir:
    :return:
    """

    latest_log_file = None
    log_file_regexp = re.compile(r"""^nginx-access-ui.log-(?P<date>[0-9]{8})(.gz)?""")  # type: Pattern[str]
    if not os.path.isdir(log_dir):
        raise FileNotFoundError('Directory "%s" is not found!' % log_dir)

    for dir_entry in os.scandir(log_dir):
        if not dir_entry.is_file():
            continue
        matched = log_file_regexp.match(dir_entry.name)
        if not matched:
            continue
        try:
            cur_file_date = datetime.strptime(matched.group('date'), "%Y%m%d")
        except ValueError:
            raise ValueError('Incorrect date in the log filename: %s' % dir_entry.name)

        if not latest_log_file or cur_file_date > latest_log_file.date:
            latest_log_file = LogFile(filename=dir_entry.name, date=cur_file_date)

    if not latest_log_file:
        raise FileNotFoundError('Nginx log files not found in %s' % log_dir)

    return latest_log_file


def read_and_parse_log(filename):
    urls = {}
    lines = errors = requests = time = 0
    opener = (gzip.open if filename.endswith('.gz') else open)
    with opener(filename, 'rt', encoding='utf-8') as file:

        for line in file:
            matches = log_line_pattern.match(line)
            if matches:
                request = matches.group("request")
                request_time = float(matches.group("request_time"))
                if request not in urls:
                    urls[request] = []
                urls[request].append(request_time)
                time += request_time
                requests += 1
            else:
                errors += 1
                logging.debug('Error line: %s' % line)
            lines += 1
            # if lines >= 500: break # limit for test
    stat = StatCount(lines=lines, urls=requests, time=time, errors=errors)
    return urls, stat


def calculate_statistics(urls, total_request_count, total_request_time):

    statistic = []
    # noinspection PyDictCreation
    for url, url_time in urls.items():
        url_stat = {'url': url,
                    'count': len(url_time),
                    'time_sum': round(sum(url_time), FLOAT_PRECISION)}

        # count percent
        url_stat['count_perc'] = round(100 * url_stat['count'] / total_request_count, FLOAT_PRECISION)

        # time_sum percent
        url_stat['time_perc'] = round(100 * url_stat['time_sum'] / total_request_time, FLOAT_PRECISION)

        # time avg, max, med
        url_stat['time_avg'] = round(url_stat['time_sum'] / url_stat['count'], FLOAT_PRECISION)
        url_stat['time_max'] = round(max(url_time), FLOAT_PRECISION)
        url_stat['time_med'] = round(median(url_time), FLOAT_PRECISION)

        statistic.append(url_stat)

    # statistic.sort(key=lambda k: k['time_sum'], reverse=True)
    statistic.sort(key=operator.itemgetter('time_sum', 'url'), reverse=True)  # to make sorting stable for unittests

    return statistic


def write_report(report_filename, statistic, report_html_template, report_size):
    with open(report_html_template, 'rt', encoding='utf-8') as log:
        tpl_string = log.read()

    s = Template(tpl_string)
    report_string = s.safe_substitute(table_json=json.dumps(statistic[:report_size], sort_keys=True))  # , indent=4
    with open(report_filename, 'wt+', encoding='utf-8') as log:
        log.write(report_string)


def main(config):

    logging.info('Launch NGINX Log Analyzer ======================================================')
    logging.debug('Using config: %s' % json.dumps(config, indent=4))
    logging.info('Searching the latest log file...')

    logfile = get_latest_log_filename(config["LOG_DIR"])

    logging.info('Last log found: %s' % logfile.filename)
    logging.info('Parsing log filename and build report filename, creating report directory if not exists')

    prepare_report_dir(config['REPORT_DIR'])
    report_filename = build_report_filepath(config['REPORT_DIR'], logfile.date)
    if os.path.exists(report_filename):
        logging.info('Report "%s" already exists!' % report_filename)
        sys.exit(0)

    logging.info('Reading and analyzing log file...')
    urls, stat = read_and_parse_log(logfile.filename)

    logging.info('Total parsed lines: %d, error lines: %d' % (stat.lines, stat.errors))
    if stat.lines and stat.errors/stat.lines > MAX_ERROR_PERCENT:
        raise RuntimeError('Too many error lines (%.2f%%) in the log file' % (100*stat.errors/stat.lines))

    logging.info('Calculating statistics...')
    statistic = calculate_statistics(urls, stat.urls, stat.time)

    logging.info('Writing report file: %s', report_filename)
    write_report(report_filename, statistic, config['REPORT_HTML_TEMPLATE'], config['REPORT_SIZE'])
    logging.info('Done!')


if __name__ == "__main__":

    script_args = get_script_args()
    if script_args.config:
        handle_config_file(config, script_args.config)
    configure_logger(config["LOGGING_TO_FILE"], config['LOGGING_LEVEL'])

    try:
        main(config)
    except KeyboardInterrupt:  # catching Ctrl+C or other Exception
        logging.info("Interrapted by user!")
        sys.exit(2)
    except Exception as msg:
        logging.exception(msg)
        sys.exit(1)
