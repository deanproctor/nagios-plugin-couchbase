#!/usr/bin/env python

"""
Collects statistics from the Couchbase REST API.
See: https://developer.couchbase.com/documentation/server/current/rest-api/rest-intro.html

#### Dependencies

 * python-requests
 * PyYAML
 * nsca-client or nsca-ng-client
"""

import argparse
import json
import logging as log
import logging.config
import numbers
import operator
import os
import requests
import subprocess
import sys
import yaml


# Basic setup
parser = argparse.ArgumentParser(usage="%(prog)s [options] -c CONFIG_FILE")
parser.add_argument("-c", "--config", required=True, dest="config_file", action="store", help="Path to the check_couchbase YAML file")
parser.add_argument("-d", "--dump-services",  dest="dump_services", action="store_true", help="Print Nagios service descriptions and exit")
parser.add_argument("-n", "--no-metrics",  dest="no_metrics", action="store_true", help="Do not send metrics to Nagios")
parser.add_argument("-C", "--couchbase-host",  dest="couchbase_host", action="store", help="Override the configured Couchbase host")
parser.add_argument("-N", "--nagios-host",  dest="nagios_host", action="store", help="Override the configured Nagios host")
parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable debug logging to console")
args = parser.parse_args()


# Attempts to load the configuration file and apply argument overrides
def load_config():
    global config

    try:
        f = open(args.config_file).read()
        config = yaml.load(f)
    except IOError:
        print("Unable to read config file {0}".format(args.config_file))
        sys.exit(2)
    except (yaml.reader.ReaderError, yaml.parser.ParserError):
        print("Invalid YAML syntax in config file {0}".format(args.config_file))
        sys.exit(2)
    except:
        raise

    if args.dump_services:
        config["dump_services"] = True

    if args.no_metrics:
        config["send_metrics"] = False

    if args.couchbase_host:
        config["couchbase_host"] = args.couchbase_host

    if args.nagios_host:
        config["nagios_host"] = args.nagios_host

    if args.verbose:
        config["logging"]["handlers"]["console"]["level"] = "DEBUG"

    logging.config.dictConfig(config["logging"])


# Adds the ANSI bold escape sequence
def bold(string):
    return "\033[1m{0}\033[0m".format(string)


# Sends a passive check result to Nagios
def send(host, service, status, message):
    if config["dump_services"]:
        print(service)
        return

    line = "{0}\t{1}\t{2}\t{3}\n".format(host, service, status, message)
    log.debug("{0} {1} {2} {3} {4} {5} {6} {7}".format(bold("Host:"), host, bold("Service:"), service, bold("Status:"), status, bold("Message:"), message))

    if config["send_metrics"] is False:
        return

    if not os.path.exists(config["nsca_path"]):
        print("Path to send_nsca is invalid: {0}".format(config["nsca_path"]))
        sys.exit(2)

    cmd = "{0} -H {1} -p {2}".format(config["nsca_path"], str(config["nagios_host"]), str(config["nsca_port"]))

    try:
        pipe = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = pipe.communicate(line.encode())
        pipe.stdin.close()
        pipe.wait()

        if pipe.returncode:
            print("Failed to send stats to Nagios. {0}".format(err.decode().rstrip()))
            sys.exit(2)
    except:
        raise


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

    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        f = requests.get(url, auth=(config["couchbase_user"], config["couchbase_password"]), verify=False)

        status = f.status_code

        if f.text:
            response = json.loads(f.text)

        # We can provide a helpful error message on 403
        if status == 403:
            if "permissions" in response:
                print("{0}: {1}".format(response["message"], response["permissions"]))

        # Bail if status is anything but successful
        if status != 200:
            f.raise_for_status()

        return response
    except requests.exceptions.HTTPError as e:
        print("Failed to complete request to Couchbase: {0}, {1}".format(url, e))
        sys.exit(2)
    except:
        raise


# Averages multiple metric samples to smooth out values
def avg(samples):
    return sum(samples, 0) / len(samples)


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
# Format will be {service_prefix} {cluster_name} {label} - {description}
def build_service_description(description, cluster_name, label):
    service = ""

    if "service_prefix" in config:
        service += config["service_prefix"]

    if config["service_include_cluster_name"] and cluster_name:
        service += " {0}".format(cluster_name)

    if config["service_include_label"]:
        service += " {0}".format(label)

    if service != "":
        service += " - "

    service += description

    return service


# Determines metric status based on value and thresholds
def eval_status(value, critical, warning, op):
    if isinstance(critical, numbers.Number) and compare(value, op, critical):
        return 2, "CRITICAL"
    elif isinstance(critical, str) and compare(value, op, critical):
        return 2, "CRITICAL"
    elif isinstance(warning, numbers.Number) and compare(value, op, warning):
        return 1, "WARNING"
    elif isinstance(warning, str) and compare(value, op, warning):
        return 1, "WARNING"
    else:
        return 0, "OK"


# Evalutes data service stats and sends check results
def process_data_stats(bucket, metrics, host, cluster_name):
    s = couchbase_request("/pools/default/buckets/{0}/stats".format(bucket))
    stats = s["op"]["samples"]

    for m in metrics:
        m.setdefault("crit", None)
        m.setdefault("warn", None)
        m.setdefault("op", ">=")

        if m["metric"] == "percent_quota_utilization":
            value = avg(stats["mem_used"]) / (avg(stats["ep_mem_high_wat"]) * 1.0) * 100
        elif m["metric"] == "percent_metadata_utilization":
            value = avg(stats["ep_meta_data_memory"]) / (avg(stats["ep_mem_high_wat"]) * 1.0) * 100
        elif m["metric"] == "disk_write_queue":
            value = avg(stats["ep_queue_size"]) + avg(stats["ep_flusher_todo"])
        elif m["metric"] == "total_ops":
            value = 0
            for op in ["cmd_get", "cmd_set", "incr_misses", "incr_hits", "decr_misses", "decr_hits", "delete_misses", "delete_hits"]:
                value += avg(stats[op])
        else:
            if validate_metric(m, stats) is False:
                continue

            value = avg(stats[m["metric"]])

        service = build_service_description(m["description"], cluster_name, bucket)
        status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
        message = "{0} - {1}: {2}".format(status_text, m["metric"], str(round(value, 2)).rstrip("0").rstrip("."))

        send(host, service, status, message)


# Evaluates XDCR stats and sends check results
def process_xdcr_stats(tasks, host, cluster_name):
    for task in tasks:
        if task["type"] == "xdcr":
            if "xdcr" not in config:
                log.warning("XDCR is running but no metrics are configured")
                return

            metrics = config["xdcr"]

            for m in metrics:
                m.setdefault("crit", None)
                m.setdefault("warn", None)
                m.setdefault("op", ">=")

                label = "xdcr {0}/{1}".format(task["id"].split("/")[1], task["id"].split("/")[2])

                if m["metric"] == "status":
                    value = task["status"]
                    service = build_service_description(m["description"], cluster_name, label)
                    status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
                    message = "{0} - {1}: {2}".format(status_text, m["metric"], value)

                    send(host, service, status, message)
                elif task["status"] in ["running", "paused"]:
                    replication = requests.utils.quote("replications/{0}/{1}".format(task["id"], m["metric"]), safe="")
                    uri = "/pools/default/buckets/{0}/stats/{1}".format(task["source"], replication)
                    stats = couchbase_request(uri)

                    for node in stats["nodeStats"]:
                        if host == node.split(":")[0]:
                            if len(stats["nodeStats"][node]) == 0:
                                log.error("Invalid XDCR metric: {0}".format(m["metric"]))
                                return

                            value = avg(stats["nodeStats"][node])

                            service = build_service_description(m["description"], cluster_name, label)
                            status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
                            message = "{0} - {1}: {2}".format(status_text, m["metric"], str(round(value, 2)).rstrip("0").rstrip("."))

                            send(host, service, status, message)


# Evaluates query service stats and sends check results
def process_query_stats(host, cluster_name):
    if "query" not in config:
        log.warning("Query service is running but no metrics are configured")
        return

    metrics = config["query"]
    stats = couchbase_request("/admin/stats", "query")

    for m in metrics:
        m.setdefault("crit", None)
        m.setdefault("warn", None)
        m.setdefault("op", ">=")

        if validate_metric(m, stats) is False:
            continue

        value = stats[m["metric"]]

        service = build_service_description(m["description"], cluster_name, "query")
        status, status_text = eval_status(value, m["crit"], m["warn"], m["op"])
        message = "{0} - {1}: {2}".format(status_text, m["metric"], str(value))

        send(host, service, status, message)


# Evaluates node stats and sends check results
def process_node_stats(stats, host, cluster_name):
    metrics = config["node"]

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
    config.setdefault("service_include_cluster_name", False)
    config.setdefault("service_include_label", False)
    config.setdefault("send_metrics", True)
    config.setdefault("dump_services", False)

    # Unrecoverable errors
    for item in ["couchbase_user", "couchbase_password", "nagios_host", "nsca_password", "node", "data"]:
        if item not in config:
            print("{0} is not set in {1}".format(item, args.config_file))
            sys.exit(2)

    for item in config["data"]:
        if "bucket" not in item or item["bucket"] is None:
            print("Bucket name is not set in {0}".format(args.config_file))
            sys.exit(2)

        if "metrics" not in item or item["metrics"] is None:
            print("Metrics are not set for bucket {0} in {1}".format(item["bucket"], args.config_file))
            sys.exit(2)


# Validates metric config
def validate_metric(metric, samples):
    if "metric" not in metric or metric["metric"] is None:
        log.warning("Skipped: metric name not set")
        return False

    name = metric["metric"]

    if name not in samples:
        log.warning("Skipped: metric does not exist: {0}".format(name))
        return False

    if "description" not in metric or metric["description"] is None:
        log.warning("Skipped: service description is not set for metric: {0}".format(name))
        return False

    if metric["op"] not in [">", ">=", "=", "<=", "<"]:
        log.warning("Skipped: Invalid operator: {0}, for metric: {1}".format(metric["op"], name))
        return False


def main():
    load_config()
    validate_config()

    tasks = couchbase_request("/pools/default/tasks")
    pools_default = couchbase_request("/pools/default")

    if "clusterName" in pools_default:
        cluster_name = pools_default["clusterName"]
    else:
        cluster_name = None

    nodes = pools_default["nodes"]
    for node in nodes:
        if "thisNode" in node:
            host = node["hostname"].split(":")[0]
            services = node["services"]

            process_node_stats(node, host, cluster_name)

    if "kv" in services:
        process_xdcr_stats(tasks, host, cluster_name)

        for item in config["data"]:
            # _all is a special case where we process stats for all buckets
            if item["bucket"] == "_all":
                for bucket in couchbase_request("/pools/default/buckets?skipMap=true"):
                    process_data_stats(bucket["name"], item["metrics"], host, cluster_name)
            else:
                process_data_stats(item["bucket"], item["metrics"], tasks, host, cluster_name)

    if "n1ql" in services:
        process_query_stats(host, cluster_name)

    print("OK - check_couchbase ran successfully")
    return 0

if __name__ == "__main__":
        main()
