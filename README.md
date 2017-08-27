# Nagios Couchbase Plugin
A plugin to monitor the Couchbase REST APIs and forward events to Nagios.

It is intended to be a standalone Nagios plugin as well as a reference for how to interact with the Couchbase REST APIs when building plugins for other systems.

## Requirements
* Python requests module
* PyYAML
* send_nsca via the nsca or nsca-ng packages

## Configuration
This plugin is configured to submit passive checks to Nagios via NSCA.  The set of metrics to monitor and thresholds for each metric are locally configured in the check_couchbase.yaml file.

### Minimum configuration
Make sure the following properties match your environment:
* couchbase_host
* couchbase_user
* couchbase_password
* nagios_host
* nsca_port
* nsca_password
* nsca_path

Note that the user executing this script must have read access to /etc/send_nsca.cfg.

### Nagios services
You must have services configured in Nagios in order for the passive check results to be accepted.  The plugin allows you to customize the service description to match your Nagios configuration.  

Service descriptions are built in the following format:
{prefix} {cluster name} {label} - {metric description}

The configuration file documents how the service description is built and how to customize it.

The --dump-services flag can be used to output the Nagios service descriptions this script will use.

### Couchbase metrics
This plugin comes pre-configured with a set of best-practice metrics.  It will be necessary to update the metric thresholds to reflect your Couchbase environment.

## Usage
``` bash
usage: check_couchbase.py [options] -c CONFIG_FILE

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config CONFIG_FILE
                        Path to the check_couchbase YAML file
  -d, --dump-services   Print Nagios service descriptions and exit
  -n, --no-metrics      Do not send metrics to Nagios
  -C COUCHBASE_HOST, --couchbase-host COUCHBASE_HOST
                        Override the configured Couchbase host
  -N NAGIOS_HOST, --nagios-host NAGIOS_HOST
                        Override the configured Nagios host
  -v, --verbose         Enable debug logging to console
```

This script should be executed via cron or via a Nagios NRPE check.
