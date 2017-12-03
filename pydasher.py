#!/usr/bin/python2
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
import yaml
import os


parser = argparse.ArgumentParser()
parser.add_argument('-log', '--log', nargs='?', help='set log level - defaults to INFO, set to DEBUG to see all MAC addresses', default='INFO')
args = parser.parse_args()

loglevelstr = args.log.upper()
numeric_level = getattr(logging, loglevelstr)
if not isinstance(numeric_level, int):
  raise ValueError('Invalid log level: %s' % loglevelstr)
logging.basicConfig(level=numeric_level)


logging.info('starting... (log level: ' + loglevelstr + ")")


# Get current working directory
path = os.path.dirname(os.path.realpath(__file__))

# Creat a log file
dashlog = open(path + '/pydasher.log', 'a')

# Place config in dict
yaml_dict = yaml.load(open(path + '/config.yaml'))

# Place HA settings in seperate dict
config = yaml_dict['home_assistant']
# Extract HA host and api password
host = config['host']
password = config.get('api_password', None)

if password != None:
  passwordParam = "x-ha-access: " + password
else:
  passwordParam = ""


# Remove HA settings from dict
del yaml_dict['home_assistant']

#Create empty button dict
buttons = {}

# Populate buttons dict with yaml buttons
for v in yaml_dict.itervalues():
  mac = v['MAC'].lower()
  event = v['HA_EVENT']
  logging.info(" adding MAC " + mac + ", event '" + event + "'")
  buttons[mac] = event

# Look for arps
def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].hwsrc in buttons.keys(): # Found a button's MAC
      url = "http://" + host + ":8123/api/events/" + buttons.get(pkt[ARP].hwsrc)
      dashlog.write("Found a button - mac: " + pkt[ARP].hwsrc +  ", ip: " + pkt[ARP].psrc + " - sending event '" + buttons.get(pkt[ARP].hwsrc) + "' by POSTing to: '" + url + "'\n")
      logging.info("Found a button - mac: " + pkt[ARP].hwsrc +  ", ip: " + pkt[ARP].psrc + " - sending event '" + buttons.get(pkt[ARP].hwsrc) + "' by POSTing to: '" + url + "'\n")
      # Fire a curl POST to HA's web API, Output response to log
      dashlog.write("\n")
      subprocess.call(["curl", "-S", "-s", "-H", passwordParam, "-X", "POST", url], stdout=dashlog)
      # Output response to log
    else:
      # Output unknown ARP's to the log as well
      #dashlog.write("ARP Probe from unknown device: " + pkt[ARP].hwsrc + "\n")
      logging.debug("ARP Probe from unknown device: mac: " + pkt[ARP].hwsrc + " ip: " +  pkt[ARP].psrc + "\n")


logging.info('sniffing...')
# Run it
sniff(prn=arp_display, filter="arp", store=0, count=0)
