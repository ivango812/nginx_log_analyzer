# NGINX Log Analyzer

Build html-report to figure out the most heavy urls in your web-app.
Report has UI for sorting top REPORT_SIZE results.

Search nginx log in the specified dir by lastest date in the log filename
and build html report. Nginx log file can be as plain text or `.gz` file.

Can be configured by `conf.ini` file (see syntax below)
Writes own log to `logfile.log` (INFO, ERRORS) log_level sets in script config.

### Install

Just download to your disc.

Make sure you have `python3` installed.

Make the script executable.
    
    chmod +x log_analyzer.py

`./report.html` - report template file required
`./jquery.tablesorter.min.js` - jQuery script required 

### Usage

Run with default config settings:

    log_analyzer.py

Run with custom config settings:

    log_analyzer.py --config=<your config file>


conf.ini example:

    [config]
    REPORT_SIZE: 200
    REPORT_DIR: "./reports_dir"
    LOG_DIR: ./log_dir
    
   
### Run tests

Just run:

    python3 -m unittest   

Test config:

`./log_test` - dir where placed:

* `report-2018.01.01.html` - report sample (don't delete it)
* `nginx-access-ui.log-20180101.gz` - log sample (don't delete it)

`./reports_test` - dir with test report if test pass

### Author

**Ivan Gorban**

* [ivan@igorban.ru]()

### License

Copyright © 2018, Ivan Gorban. Released under the MIT License.