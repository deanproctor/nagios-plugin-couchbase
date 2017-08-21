#!/usr/bin/env python
# coding=utf-8

"""
Collect statistics from the Couchbase Buckets API.  
See: http://docs.couchbase.com/admin/admin/REST/rest-bucket-intro.html 

#### Dependencies

 * json
 * optparse
 * pyyaml
 * urllib2

"""

import base64
import urllib2 
from optparse import OptionParser
from subprocess import Popen, PIPE
from yaml import load

try:
  import json
except ImportError:
  import simplejson as json

parser = OptionParser()
parser.add_option('-c', dest='config_file', action='store')
options, args = parser.parse_args()

if(options.config_file is None):
  print "Config file not specified.  Use -c CONFIG_FILE"
  exit(1)

yaml = file(options.config_file, 'r')
config = load(yaml)

def send(service, status, message):
    line = "%s\t%s\t%d\t%s\n" % (config['couchbase_host'], service, status, message)
    print line

    cmd = config['nsca_path'] + ' -H ' + config['nagios_host']
    pipe = Popen(cmd, shell=True, stdin=PIPE)
    pipe.communicate(line)
    pipe.stdin.close()
    pipe.wait()

def getStats(bucket=None):
  host = config['couchbase_host']
  port = config['port']
  
  if config['ssl'] is True:
    protocol = 'https'
  else:
    protocol = 'http'
  
  url = protocol + '://' + host + ':' + str(port) + '/pools/default/buckets/' 

  if bucket is not None:
    url = url + bucket + '/stats'

  auth_string = base64.b64encode('%s:%s' % (config['user'], config['password']))

  request = urllib2.Request(url);
  request.add_header("Authorization", "Basic %s" % auth_string)

  try:
    f = urllib2.urlopen(request)
    return json.load(f)
  except urllib2.HTTPError, err:
    print "Failed to get stats for bucket: " + bucket
  
def processMetrics(bucket, metrics):
  data = getStats(bucket)
  if not data:
    return 

  samples = data['op']['samples']

  for m in metrics:
    metric = m['metric']
    avg_value = sum(samples[metric], 0.0) / len(samples[metric])

    message = 'Bucket: ' + bucket + ', ' + metric + '= ' + str(avg_value)

    if config['include_bucket_name'] is True:
      service = 'CB ' + bucket + ' - ' + m['description']
    else:
      service = 'CB ' + bucket + ' - ' + m['description']

    status = 0
    send(service, status, message)

def main():
  for bucket in config['buckets']:
    if bucket['name'] == '_all':
      for b in getStats():
        processMetrics(b['name'], bucket['metrics'])
    else:
      processMetrics(bucket['name'], bucket['metrics'])
        
if __name__ == '__main__':
    main()
