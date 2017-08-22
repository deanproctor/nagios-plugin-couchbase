#!/usr/bin/env python
# coding=utf-8

"""
Collect statistics from the Couchbase Buckets API.  
See: http://docs.couchbase.com/admin/admin/REST/rest-bucket-intro.html 

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
  import json 
except ImportError:
  import simplejson as json

# Basic setup
parser = ArgumentParser(usage = "%(prog)s [options] -c CONFIG_FILE")
parser.add_argument('-c', '--config', dest='config_file', action='store', help='Path to the check_couchbase YAML file')
parser.add_argument('-v', dest='verbose', action='store_true', help='Enable debug logging to console')
args = parser.parse_args()

if not args.config_file:
  parser.error('Config file is required.  Use -c CONFIG_FILE')

config = yaml.load(open(args.config_file).read())

if args.verbose:
  config['logging']['handlers']['console']['level'] = 'DEBUG'

logging.config.dictConfig(config['logging'])


# Sends a passive check result to Nagios NSCA
def send(host, service, status, message):
    line = "%s\t%s\t%d\t%s\n" % (host, service, status, message)
    log.debug(line)

    if not os.path.exists(config['nsca_path']):
      log.error('path to send_nsca is invalid: ' + config['nsca_path'])
      exit(1)

    cmd = config['nsca_path'] + ' -H ' + str(config['nagios_host']) + ' -p ' + str(config['nsca_port'])
    pipe = Popen(cmd, shell=True, stdin=PIPE)
    pipe.communicate(line)
    pipe.stdin.close()
    pipe.wait()


# Executes a Couchbase REST API request and returns the output
def couchbase_request(uri):
  host = config['couchbase_host']
  port = config['couchbase_port']
  
  if config['couchbase_ssl']:
    protocol = 'https'
  else:
    protocol = 'http'
  
  url = protocol + '://' + host + ':' + str(port) + uri 

  auth_string = b64encode('%s:%s' % (config['couchbase_user'], config['couchbase_password']))

  request = urllib2.Request(url);
  request.add_header('Authorization', "Basic %s" % auth_string)

  try:
    f = urllib2.urlopen(request, context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))
    return json.load(f)
  except urllib2.HTTPError:
    log.error('Failed to complete request to Couchbase: ' + uri + ', verify couchbase_user and couchbase_password settings')


# For dynamic comparisons
# Thanks to https://stackoverflow.com/a/18591880
def compare(inp, relate, cut):
  ops = {'>': operator.gt,
         '<': operator.lt,
         '>=': operator.ge,
         '<=': operator.le,
         '=': operator.eq}
  return ops[relate](inp, cut)


# Builds the nagios service description based on config
def build_service_description(description, cluster_name, bucket=None):
  # Format will be {prefix} {cluster_name} {bucket_name} - {service_description}
  service = config['prefix']

  if config['service_include_cluster_name']:
    if cluster_name:
      service = service + ' ' + cluster_name

  if bucket is not None and config['service_include_bucket_name']:
    service = service + ' ' + bucket

  service = service + ' - ' + description

  return service


# Evalutes bucket stats and sends check results
def process_bucket_stats(bucket, metrics, host, cluster_name):
  stats = couchbase_request('/pools/default/buckets/' + bucket + '/stats')
  samples = stats['op']['samples']

  for m in metrics:
    m.setdefault('metric', None)
    m.setdefault('description', None)
    m.setdefault('crit', None)
    m.setdefault('warn', None)
    m.setdefault('op', '>=')
    
    metric      = m['metric']
    description = m['description']
    critical    = m['crit']
    warning     = m['warn']
    op          = m['op']

    if metric is None:
      log.error('Metric name not set for bucket: ' + bucket)
      continue

    if metric not in samples:
      log.info('Metric not found for bucket: ' + bucket + ', metric: ' + metric)
      continue

    if description is None:
      log.error('Service description is not set for bucket: ' + bucket + ', metric: ' + metric)
      continue

    if op not in ['>', '>=', '=', '<=', '<']:
      log.error('Invalid operator: ' + op + ' for bucket: ' + bucket + ', metric: ' + metric)
      continue

    # Couchbase returns samples for the last 60 seconds.
    # Average them to smooth out values
    value = sum(samples[metric], 0.0) / len(samples[metric])

    # Evaluate the status and set the message
    if isinstance(critical, Number) and compare(value, op, critical):
      status = 2
      status_text = 'CRITICAL'
    elif isinstance(critical, basestring) and value in critical:
      status = 2
      status_text = 'CRITICAL'
    elif isinstance(warning, Number) and compare(value, op,  warning):
      status = 1
      status_text = 'WARNING'
    elif isinstance(warning, basestring) and value in warning:
      status = 1
      status_text = 'WARNING'
    else:
      status = 0
      status_text = 'OK'

    service = build_service_description(description, cluster_name, bucket)
    message = status_text + ' - ' + metric + ': ' + str(value)

    send(host, service, status, message)


# Validates all config except metrics
def validate_config():
  # set defaults
  config.setdefault('couchbase_host', 'localhost')
  config.setdefault('couchbase_port', 18091)
  config.setdefault('couchbase_ssl', True)
  config.setdefault('nsca_port', 5668)
  config.setdefault('nsca_path', '/sbin/send_nsca')
  config.setdefault('prefix', 'CB')
  config.setdefault('service_include_cluster_name', True)
  config.setdefault('service_include_bucket_name', True)

  # For docker environments
  env_couchbase_host = os.getenv('COUCHBASE_HOST', None)
  env_nagios_host    = os.getenv('NAGIOS_HOST', None)

  if env_couchbase_host:
    config['couchbase_host'] = env_couchbase_host

  if env_nagios_host:
    config['nagios_host'] = env_nagios_host

  # Unrecoverable errors
  for item in ['couchbase_user', 'couchbase_password', 'nagios_host', 'nsca_password']:
    if item not in config:
      log.error(item + ' is not set')
      exit(1)

  if 'buckets' in config:
    for bucket in config['buckets']:
      if 'name' not in bucket:
        log.error('Bucket name is not set')
        exit(1)

      if 'metrics' not in bucket:
        log.error('Metrics are not set for bucket: ' + bucket['name'])
        exit(1)


def main():
  validate_config();

  pools_default = couchbase_request('/pools/default/')
  cluster_name = pools_default['clusterName']
  nodes = pools_default['nodes']
  for node in nodes:
    if 'thisNode' in node:
      host = node['hostname'].split(':')[0]
      services = node['services']

  if 'kv' in services:
    for bucket in config['buckets']:
      # _all is a special case where we process stats for all buckets
      if bucket['name'] == '_all':
        for b in couchbase_request('/pools/default/buckets/'):
          process_bucket_stats(b['name'], bucket['metrics'], host, cluster_name)
      else:
        process_bucket_stats(bucket['name'], bucket['metrics'], host, cluster_name)
        
  if 'n1ql' in services:
    print 'n1ql'

if __name__ == '__main__':
    main()
