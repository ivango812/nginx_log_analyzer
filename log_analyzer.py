#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

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
    "LOG_DIR": "./log",
    "LOGGING_TO_FILE": False,
    "LOGGING_LEVEL": logging.DEBUG
}

MAX_ERROR_COUNT = 100
MAX_ERROR_PERCENT = 0.1
FLOAT_PRECITION = 3
LogFile = namedtuple('LogFile', ['filename', 'date'])
StatCount = namedtuple('StatCount', ['lines', 'urls', 'time', 'errors'])
SELF_LOG_FILENAME = './logfile.log'


def configure_logging(is_logging_to_file=False, level=logging.DEBUG):
    logging_filename = SELF_LOG_FILENAME if is_logging_to_file else None
    logging.basicConfig(filename=logging_filename,
                        format="[%(asctime)s] %(levelname).1s %(message)s",
                        datefmt="%Y.%m.%d %H:%M:%S",
                        level=level)

def get_script_args():
    logging.info('Parsing script args...')
    parser = argparse.ArgumentParser("log_analyzer.py")
    parser.add_argument('--config', help="config filename path")
    args = parser.parse_args()
    return args


def handle_config_file(config, filename):
    configfile = configparser.ConfigParser(config)
    configfile.optionxform = str
    configfile.read(filename)
    configfile_dict = dict(configfile._sections['config'])
    # Overwriting config options from file
    config.update(configfile_dict)
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


def get_last_log_filename(log_dir):
    """
    Search youngest (by date in filename) log file matches template nginx-access-ui.log-<YearMonthDay> or .gz
    :param log_dir:
    :return:
    """
    log_filename = ''
    last_log_date = 0
    log_file_regexp = re.compile(r"""^nginx-access-ui.log-(?P<date>[0-9]{8})(.gz)?""")  # type: Pattern[str]
    if not os.path.isdir(log_dir):
        raise FileNotFoundError('Directory "%s" is not found!' % log_dir)

    for dir_entry in os.scandir(log_dir):
        if dir_entry.is_file():
            matched = log_file_regexp.match(dir_entry.name)
            if matched and int(matched.group('date')) > last_log_date:
                last_log_date = int(matched.group('date'))
                log_filename = dir_entry.path
    if not log_filename:
        raise RuntimeError('Nginx log files not found in %s' % log_dir, logging.INFO)
    return LogFile(filename=log_filename, date=last_log_date)


def read_and_parse_log(logfile):
    urls = {}
    lines = errors = requests = time = 0
    log_line_pattern = re.compile(LOG_LINE_REGEXP, re.IGNORECASE)
    logname = logfile.filename
    with (gzip.open if logname.endswith('.gz') else open)(logname, 'rt', encoding='utf-8') as file:

        for line in file:
            matches = log_line_pattern.match(line)
            if matches:
                url = matches.group("request")
                url_time = float(matches.group("request_time"))
                if url not in urls:
                    urls[url] = []
                urls[url].append(url_time)
                time += url_time
                requests += 1
            else:
                errors += 1
                logging.debug('Error line: %s' % line)
                if errors > MAX_ERROR_COUNT:
                    raise RuntimeError('Too many error lines in log file - $s' % errors, logging.ERROR)
            lines += 1
            # if line_count >= 500: break # limit for test
    stat = StatCount(lines=lines,urls=requests, time=time, errors=errors)
    return urls, stat


def calculate_statistics(urls, total_request_count, total_request_time):

    statistic = []
    # noinspection PyDictCreation
    for url, url_time in urls.items():
        url_stat = {'url': url,
                    'count': len(url_time),
                    'time_sum': round(sum(url_time), FLOAT_PRECITION)}

        # count percent
        url_stat['count_perc'] = round(100 * url_stat['count'] / total_request_count, FLOAT_PRECITION)

        # time_sum percent
        url_stat['time_perc'] = round(100 * url_stat['time_sum'] / total_request_time, FLOAT_PRECITION)

        # time avg, max, med
        url_stat['time_avg'] = round(url_stat['time_sum'] / url_stat['count'], FLOAT_PRECITION)
        url_stat['time_max'] = round(max(url_time), FLOAT_PRECITION)
        url_stat['time_med'] = round(median(url_time), FLOAT_PRECITION)

        statistic.append(url_stat)

    # statistic.sort(key=lambda k: k['time_sum'], reverse=True)
    statistic.sort(key=operator.itemgetter('time_sum', 'url'), reverse=True)  # to make sorting stable for unittests

    return statistic


def write_report(report_filename, statistic, report_size):
    try:
        with open('./report.html', 'rt', encoding='utf-8') as log:
            tpl_string = log.read()
    except FileNotFoundError:
        raise RuntimeError('File report.html not found', logging.ERROR)

    s = Template(tpl_string)
    report_string = s.safe_substitute(table_json=json.dumps(statistic[:report_size], sort_keys=True))  # , indent=4
    with open(report_filename, 'wt+', encoding='utf-8') as log:
        log.write(report_string)


def main():

    try:  # catching Ctrl+C or other Exception
        configure_logging(config["LOGGING_TO_FILE"], config['LOGGING_LEVEL'])
        logging.info('Launch NGINX Log Analyzer =======================================')

        logging.info('Parsing script args...')
        script_args = get_script_args()

        logging.info('Configuring...')
        if script_args.config:
            handle_config_file(config, script_args.config)
            logging.info('Using config: %s' % script_args.config)
        else:
            logging.info('Using default config')
        logging.debug(config)

        logging.info('Searching lastest log file...')
        logfile = get_last_log_filename(config["LOG_DIR"])
        logging.info('Last log found: %s' % logfile.filename)

        logging.info('Parsing log filename and build report filename, creating report directory if not exists')
        try:
            report_dt = datetime.strptime(str(logfile.date), "%Y%m%d")
        except ValueError:
            raise RuntimeError('Incorrect date in the log filename: ' + logfile.filename, logging.ERROR)

        prepare_report_dir(config['REPORT_DIR'])
        report_filename = build_report_filepath(config['REPORT_DIR'], report_dt)
        if os.path.exists(report_filename):
            logging.info('Report "%s" already exists!' % report_filename)
            sys.exit(0)

        logging.info('Reading and analyzing log file...')
        urls, stat = read_and_parse_log(logfile)

        logging.info('Total parsed lines: %d, error lines: %d' % (stat.lines, stat.errors))
        if stat.lines and stat.errors/stat.lines > MAX_ERROR_PERCENT:
            raise RuntimeError('Too many error lines (%.2f%%) in the log file' % (100*stat.errors/stat.lines), logging.ERROR)

        logging.info('Calculating statistics...')
        statistic = calculate_statistics(urls, stat.urls, stat.time)

        logging.info('Writing report file: %s', report_filename)
        write_report(report_filename, statistic, config['REPORT_SIZE'])

        logging.info('Done!')

    except KeyboardInterrupt:
        logging.exception("Interrapted by user!")
        sys.exit(2)

    except RuntimeError as err:  # err.args = [message, error_type]
        if err.args[1] == logging.ERROR:
            logging.error(err.args[0])
            sys.exit(1)
        if err.args[1] == logging.INFO:
            logging.info(err.args[0])
            sys.exit(0)

    except FileNotFoundError as err:
        logging.error(err)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        logging.exception(err)
        sys.exit(1)