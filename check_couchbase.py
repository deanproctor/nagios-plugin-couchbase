#!/usr/bin/env python
# coding=utf-8

"""
Collect statistics from the Couchbase Buckets API.  
See: http://docs.couchbase.com/admin/admin/REST/rest-bucket-intro.html 

#### Dependencies

 * pyyaml

"""

from argparse import ArgumentParser
from base64 import b64encode
from numbers import Number
from subprocess import Popen, PIPE
from urllib2 import Request, urlopen, HTTPError
from yaml import load

try:
  import json 
except ImportError:
  import simplejson as json



# Setup command line arguments
parser = ArgumentParser(usage = "usage: %prog [options] -c CONFIG_FILE")
parser.add_argument('-c', '--config', dest='config_file', action='store', help='Path to the check_couchbase YAML file')
args = parser.parse_args()

if not args.config_file:
  parser.error('Config file is required.  Use -c CONFIG_FILE')

# Parse config file
yaml = file(args.config_file, 'r')
config = load(yaml)

# Sends a passive check result to Nagios NSCA
def send(service, status, message):
    line = "%s\t%s\t%d\t%s\n" % (config['couchbase_host'], service, status, message)
    print line

    cmd = config['nsca_path'] + ' -H ' + config['nagios_host']
    pipe = Popen(cmd, shell=True, stdin=PIPE)
    pipe.communicate(line)
    pipe.stdin.close()
    pipe.wait()

# Executes a Couchbase REST API request and returns the output
def couchbaseRequest(uri):
  host = config['couchbase_host']
  port = config['port']
  
  if config['ssl']:
    protocol = 'https'
  else:
    protocol = 'http'
  
  url = protocol + '://' + host + ':' + str(port) + uri 

  auth_string = b64encode('%s:%s' % (config['user'], config['password']))

  request = Request(url);
  request.add_header("Authorization", "Basic %s" % auth_string)

  try:
    f = urlopen(request)
    return load(f)
  except HTTPError, err:
    print 'Failed to complete request to Couchbase: ' + uri

# Fetches, evalutes, and sends check results for bucket stats
def processStats(bucket, metrics):
  stats = couchbaseRequest('/pools/default/buckets/' + bucket + '/stats')
  if not stats['op']['samples']:
    print 'Failed to retrieve stats for bucket: ' + bucket

  samples = stats['op']['samples']

  for m in metrics:
    metric   = m['metric']
    critical = m['crit']
    warning  = m['warn']
    value    = sum(samples[metric], 0.0) / len(samples[metric])

    # Build the Nagios service name
    service = config['prefix']

    if config['include_cluster_name']:
      cluster_name = couchbaseRequest('/pools/default/')['clusterName']
      if cluster_name:
        service = service + ' ' + cluster_name

    if config['include_bucket_name']:
      service = service + ' ' + bucket

    service = service + ' - ' + m['description']

    # Evaluate the status and set the message
#    if ((type(critical) is float or type(critical) is int or type(critical) is long or critical is None) and 
#       (type(warning) is float or type(warning) is int or type(warning) is long or warning is None)):
    if (isinstance(critical, Number) or critical is None) and (isinstance(warning, Number) or warning is None): 
      if value >= critical:
        status = 2
        status_text = "CRITICAL"
      elif value >= warning:
        status = 1
        status_text = "WARNING"
      else:
        status = 0
        status_text = "OK"
    else:
      if value in critical:
        status = 2
        status_text = "CRITICAL"
      elif value in warning:
        status = 1
        status_text = "WARNING"
      else:
        status = 0
        status_text = "OK"

    message = status_text + " - " + metric + ": " + str(value)

    send(service, status, message)

def main():
  for bucket in config['buckets']:
    # _all is a special case where we processStats for all buckets
    if bucket['name'] == '_all':
      for b in couchbaseRequest('/pools/default/buckets/'):
        processStats(b['name'], bucket['metrics'])
    else:
      processStats(bucket['name'], bucket['metrics'])
        
if __name__ == '__main__':
    main()
