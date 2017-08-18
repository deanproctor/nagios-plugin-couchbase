# coding=utf-8

"""
Collect statistics from the Couchbase Buckets API.  
See: http://docs.couchbase.com/admin/admin/REST/rest-bucket-intro.html 

#### Dependencies

 * json
 * urllib2

"""

import base64
import urllib2 
from subprocess import Popen, PIPE
from yaml import load

try:
  import json
except ImportError:
  import simplejson as json

def send(message,
         nsca,
         nagios_host,
         host_name,
         service_description,
         service_status):
    line = "%s\t%s\t%d\t%s\n" % (host_name, service_description, service_status, message)
    print line
"""
    pipe = Popen((nsca, nagios_host), stdin=PIPE)
    pipe.communicate(line)
    pipe.stdin.close()
    pipe.wait()
"""

def getStats(config, bucket=None):
  host = config['couchbase_host']
  port = config['port']
  
  if config['ssl'] is True:
    protocol = 'https'
  else:
    protocol = 'http'
  
  url = protocol + '://' + host + ":" + str(port) + '/pools/default/buckets/' 

  if bucket is not None:
    url = url + bucket + '/stats'

  auth_string = base64.b64encode('%s:%s' % (config['user'], config['password']))

  request = urllib2.Request(url);
  request.add_header("Authorization", "Basic %s" % auth_string)

  try:
    f = urllib2.urlopen(request)
    return json.load(f)
  except urllib2.HTTPError, err:
    log.error("CouchbaseCollector: %s, %s", url, err)
  
def main():
  yaml = file("check_couchbase.yaml", "r")
  config = load(yaml)

  buckets = config['buckets']

  if buckets == 'all':
    buckets = []
    [buckets.append(bucket['name']) for bucket in getStats(config)] 

  if isinstance(buckets, basestring):
    buckets = [buckets]

  for bucket in buckets:
    data = getStats(config, bucket)
    if not data:
      continue

    samples = data['op']['samples']
    metrics = config['metrics']

    for m in metrics:
      metric = m["metric"]
      avg_value = sum(samples[metric], 0.0) / len(samples[metric])
      send("message", config["nsca_path"], config["nagios_host"], config["couchbase_host"], m["description"], 01) 

if __name__ == "__main__":
    main()
