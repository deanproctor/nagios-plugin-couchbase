#!/usr/bin/env python
# coding=utf-8

"""
Collects statistics from the Couchbase REST API.
See: https://developer.couchbase.com/documentation/server/current/rest-api/rest-intro.html

#### Dependencies

 * PyYAML
 * nsca-ng

"""

import logging as log
import logging.config
import operator
import os
import ssl
import urllib2
import yaml

from argparse import ArgumentParser
from base64 import b64encode
from numbers import Number
from subprocess import Popen, PIPE
from sys import stderr

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus

try:
    import json
except ImportError:
    import simplejson as json

# Basic setup
parser = ArgumentParser(usage="%(prog)s [options] -c CONFIG_FILE")
parser.add_argument("-c", "--config", dest="config_file", action="store", help="Path to the check_couchbase YAML file")
parser.add_argument("-v", dest="verbose", action="store_true", help="Enable debug logging to console")
args = parser.parse_args()

if not args.config_file:
    parser.error("Config file is required. Use -c CONFIG_FILE")

config = yaml.load(open(args.config_file).read())

if args.verbose:
    config["logging"]["handlers"]["console"]["level"] = "DEBUG"

logging.config.dictConfig(config["logging"])


# Sends a passive check result to Nagios
def send(host, service, status, message):
    line = "{0}\t{1}\t{2}\t{3}\n".format(host, service, status, message)
    log.debug(line)

    if config["send_metrics"] == "false":
        return

    if not os.path.exists(config["nsca_path"]):
        log.error("Path to send_nsca is invalid: {0}".format(config["nsca_path"]))
        exit(1)

    cmd = "{0} -H {1} -p {2}".format(config["nsca_path"], str(config["nagios_host"]), str(config["nsca_port"]))

    pipe = Popen(cmd, shell=True, stdin=PIPE)
    pipe.communicate(line)
    pipe.stdin.close()
    pipe.wait()


# Executes a Couchbase REST API request and returns the output
def couchbase_request(uri, service=None):
    host = config["couchbase_host"]

    if service == "query":
        port = config["couchbase_query_port"]
    else:
        port = config["couchbase_admin_port"]

    if config["couchbase_ssl"]:
        protocol = "https"
    else:
        protocol = "http"

    url = "{0}://{1}:{2}{3}".format(protocol, host, str(port), uri)

    auth_string = b64encode("{0}:{1}".format(config["couchbase_user"], config["couchbase_password"]))

    request = urllib2.Request(url)
    request.add_header("Authorization", "Basic {0}".format(auth_string))

    try:
        f = urllib2.urlopen(request, context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))
        return json.load(f)
    except urllib2.HTTPError:
        log.error("Failed to complete request to Couchbase: {0}, verify couchbase_user and couchbase_password settings".format(url))


# For dynamic comparisons
# Thanks to https://stackoverflow.com/a/18591880
def compare(inp, relate, cut):
    ops = {">": operator.gt,
           "<": operator.lt,
           ">=": operator.ge,
           "<=": operator.le,
           "=": operator.eq}
    return ops[relate](inp, cut)


# Builds the nagios service description based on config
def build_service_description(description, cluster_name, label):
    # Format will be {prefix} {cluster_name} {label} - {service_description}
    service = config["prefix"]

    if config["service_include_cluster_name"] and cluster_name:
        service = "{0} {1}".format(service, cluster_name)

    if config["service_include_label"]:
        service = "{0} {1}".format(service, label)

    service = "{0} - {1}".format(service, description)

    return service


# Determines metric status based on value and thresholds
def eval_status(value, critical, warning, op):
    if isinstance(critical, Number) and compare(value, op, critical):
        return 2, "CRITICAL"
    elif isinstance(critical, basestring) and compare(value, op, critical):
        return 2, "CRITICAL"
    elif isinstance(warning, Number) and compare(value, op,    warning):
        return 1, "WARNING"
    elif isinstance(warning, basestring) and compare(value, op, warning):
        return 1, "WARNING"
    else:
        return 0, "OK"


# Evalutes data service stats and sends check results
def process_data_stats(bucket, metrics, host, cluster_name):
    stats = couchbase_request("/pools/default/buckets/{0}/stats".format(bucket))
    samples = stats["op"]["samples"]

    for m in metrics:
        m.setdefault("crit", None)
        m.setdefault("warn", None)
        m.setdefault("op", ">=")

        if validate_metric(m, samples) is False:
            continue

        # Couchbase returns samples for the last 60 seconds.
        # Average them to smooth out values
        value = sum(samples[m["metric"]], 0) / len(samples[m["metric"]])

        service = build_service_description(m["description"], cluster_name, bucket)
        status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
        message = "{0} - {1}: {2}".format(status_text, m["metric"], str(value))

        send(host, service, status, message)


# Evaluates XDCR stats and sends check results
def process_xdcr_stats(bucket, tasks, host, cluster_name):
    if "xdcr" not in config:
        log.warning("XDCR is running but no metrics are configured")
        return

    metrics = config["xdcr"]["metrics"]

    for task in tasks:
        if task["type"] == "xdcr" and task["source"] == bucket:
            if task["status"] == "running":
                for m in metrics:
                    m.setdefault("crit", None)
                    m.setdefault("warn", None)
                    m.setdefault("op", ">=")

                    uri = "/pools/default/buckets/{0}/stats/{1}".format(bucket, quote_plus("replications/{0}/{1}".format(task["id"], m["metric"])))
                    stats = couchbase_request(uri)
                    for node in stats["nodeStats"]:
                        if host == node.split(":")[0]:
                            value = sum(stats["nodeStats"][node], 0) / len(stats["nodeStats"][node])
                            service = build_service_description(m["description"], cluster_name, "xdcr")
                            status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
                            message = "{0} - {1}: {2}".format(status_text, m["metric"], str(value))

                            send(host, service, status, message)
            else:
                log.error("XDCR not running")


# Evaluates query service stats and sends check results
def process_query_stats(host, cluster_name):
    if "query" not in config:
        log.warning("Query service is running but no metrics are configured")
        return

    metrics = config["query"]["metrics"]
    samples = couchbase_request("/admin/vitals", "query")

    for m in metrics:
        m.setdefault("crit", None)
        m.setdefault("warn", None)
        m.setdefault("op", ">=")

        if validate_metric(m, samples) is False:
            continue

        value = samples[m["metric"]]

        service = build_service_description(m["description"], cluster_name, "query")
        status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
        message = "{0} - {1}: {2}".format(status_text, m["metric"], str(value))

        send(host, service, status, message)


def process_node_stats(stats, host, cluster_name):
    metrics = config["node"]["metrics"]

    for m in metrics:
        m.setdefault("crit", None)
        m.setdefault("warn", None)
        m.setdefault("op", "=")

        if validate_metric(m, stats) is False:
            continue

        value = stats[m["metric"]]

        service = build_service_description(m["description"], cluster_name, "node")
        status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
        message = "{0} - {1}: {2}".format(status_text, m["metric"], str(value))

        send(host, service, status, message)


# Validates all config except metrics
def validate_config():
    # set defaults
    config.setdefault("couchbase_host", "localhost")
    config.setdefault("couchbase_admin_port", 18091)
    config.setdefault("couchbase_query_port", 18093)
    config.setdefault("couchbase_ssl", True)
    config.setdefault("nsca_port", 5668)
    config.setdefault("nsca_path", "/sbin/send_nsca")
    config.setdefault("prefix", "CB")
    config.setdefault("service_include_cluster_name", True)
    config.setdefault("service_include_bucket_name", True)

    # For docker environments
    env_couchbase_host = os.getenv("COUCHBASE_HOST", None)
    env_nagios_host = os.getenv("NAGIOS_HOST", None)
    env_send_metrics = os.getenv("SEND_METRICS", "true")

    if env_couchbase_host:
        config["couchbase_host"] = env_couchbase_host

    if env_nagios_host:
        config["nagios_host"] = env_nagios_host

    config["send_metrics"] = env_send_metrics

    # Unrecoverable errors
    for item in ["couchbase_user", "couchbase_password", "nagios_host", "nsca_password"]:
        if item not in config:
            log.error("{0} is not set".format(item))
            exit(1)

    if "data" not in config:
        log.error("Data service metrics are required")
        exit(1)

    if "node" not in config:
        log.error("Node metrics are required")
        exit(1)

    for item in config["data"]:
        if "bucket" not in item:
            log.error("Bucket name is not set")
            exit(1)

        if "metrics" not in item:
            log.error("Metrics are not set for bucket: {0}".format(item["bucket"]))
            exit(1)

    if "query" in config and "metrics" not in config["query"]:
            log.error("Metrics are not set for query service")
            exit(1)

    if "xdcr" in config and "metrics" not in config["xdcr"]:
            log.error("Metrics are not set for XDCR")
            exit(1)


# Validates metric config
def validate_metric(metric, samples):
    if "metric" not in metric or metric["metric"] is None:
        log.info("Skipped: metric name not set")
        return False

    name = metric["metric"]

    if name not in samples:
        log.info("Skipped: metric does not exist: {0}".format(name))
        return False

    if "description" not in metric or metric["description"] is None:
        log.info("Skipped: service description is not set for metric: {0}".format(name))
        return False

    if metric["op"] not in [">", ">=", "=", "<=", "<"]:
        log.info("Skipped: Invalid operator: {0}, for metric: {1}".format(op, name))
        return False


def main():
    validate_config()

    tasks = couchbase_request("/pools/default/tasks")

    pools_default = couchbase_request("/pools/default")
    cluster_name = pools_default["clusterName"]
    nodes = pools_default["nodes"]
    for node in nodes:
        if "thisNode" in node:
            host = node["hostname"].split(":")[0]
            services = node["services"]

            process_node_stats(node, host, cluster_name)

    if "kv" in services:
        for item in config["data"]:
            # _all is a special case where we process stats for all buckets
            if item["bucket"] == "_all":
                for bucket in couchbase_request("/pools/default/buckets?skipMap=true"):
                    process_data_stats(bucket["name"], item["metrics"], host, cluster_name)
                    process_xdcr_stats(bucket["name"], tasks, host, cluster_name)
            else:
                process_data_stats(item["bucket"], item["metrics"], tasks, host, cluster_name)
                process_xdcr_stats(item["bucket"], tasks, host, cluster_name)

    if "n1ql" in services:
        process_query_stats(host, cluster_name)


if __name__ == "__main__":
        main()
