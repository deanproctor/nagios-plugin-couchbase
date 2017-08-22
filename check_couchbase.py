#!/usr/bin/env python
# coding=utf-8

"""
Collect statistics from the Couchbase Buckets API.  
See: http://docs.couchbase.com/admin/admin/REST/rest-bucket-intro.html 

#### Dependencies

 * pyyaml
 * nsca-ng

"""

import logging as log 
import logging.config
import operator
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
  log.basicConfig(stream=stderr, level=log.DEBUG)
else: 
  logging.config.dictConfig(config['logging'])


# Sends a passive check result to Nagios NSCA
def send(service, status, message):
    line = "%s\t%s\t%d\t%s\n" % (config['couchbase_host'], service, status, message)
    log.debug(line)

    cmd = config['nsca_path'] + ' -H ' + str(config['nagios_host']) + ' -p ' + str(config['nsca_port'])
    pipe = Popen(cmd, shell=True, stdin=PIPE)
    pipe.communicate(line)
    pipe.stdin.close()
    pipe.wait()


# Executes a Couchbase REST API request and returns the output
def couchbaseRequest(uri):
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
    f = urllib2.urlopen(request)
    return json.load(f)
  except urllib2.HTTPError:
    log.error('Failed to complete request to Couchbase: ' + uri)


# For dynamic comparisons
# Thanks to https://stackoverflow.com/a/18591880
def compare(inp, relate, cut):
  ops = {'>': operator.gt,
         '<': operator.lt,
         '>=': operator.ge,
         '<=': operator.le,
         '=': operator.eq}
  return ops[relate](inp, cut)


# Evalutes bucket stats and sends check results
def processStats(bucket, metrics):
  stats = couchbaseRequest('/pools/default/buckets/' + bucket + '/stats')
  if not stats:
    log.error('Failed to retrieve stats for bucket: ' + bucket)
    return

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

    # Build the Nagios service name
    # Format will be {prefix} {cluster_name} {bucket_name} - {service_description}
    service = config['prefix']

    if config['service_include_cluster_name']:
      cluster_name = couchbaseRequest('/pools/default/')['clusterName']
      if cluster_name:
        service = service + ' ' + cluster_name

    if config['service_include_bucket_name']:
      service = service + ' ' + bucket

    service = service + ' - ' + description

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

    message = status_text + ' - ' + metric + ': ' + str(value)

    send(service, status, message)


# Validates all config except metrics
def validate_config():
  config.setdefault('couchbase_server', 'localhost')
  config.setdefault('couchbase_port', 18091)
  config.setdefault('couchbase_user', None)
  config.setdefault('couchbase_password', None)
  config.setdefault('couchbase_ssl', True)
  config.setdefault('nagios_host', None)
  config.setdefault('nsca_port', 5668)
  config.setdefault('nsca_password', None)
  config.setdefault('nsca_path', '/sbin/send_nsca')
  config.setdefault('prefix', 'CB')
  config.setdefault('service_include_cluster_name', True)
  config.setdefault('service_include_bucket_name', True)
  config.setdefault('buckets', None)

  if config['couchbase_user'] is None:
    log.error('couchbase_user is not set')
    exit(1)

  if config['couchbase_password'] is None:
    log.error('couchbase_password is not set')
    exit(1)

  if config['nagios_host'] is None:
    log.error('nagios_host is not set')
    exit(1)

  if config['nsca_password'] is None:
    log.error('nsca_password is not set')
    exit(1)

  if config['buckets'] is None:
    log.error('buckets is not set')
    exit(1)

  for bucket in config['buckets']:
    bucket.setdefault('name', None)
    bucket.setdefault('metrics', None)

    if bucket['name'] is None:
      log.error('Bucket name is not set')
      exit(1)

    if bucket['metrics'] is None:
      log.error('Metrics are not set for bucket: ' + bucket['name'])
      exit(1)


def main():
  validate_config();
  for bucket in config['buckets']:
    # _all is a special case where we processStats for all buckets
    if bucket['name'] == '_all':
      for b in couchbaseRequest('/pools/default/buckets/'):
        processStats(b['name'], bucket['metrics'])
    else:
      processStats(bucket['name'], bucket['metrics'])
        

if __name__ == '__main__':
    main()
