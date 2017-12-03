import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
import yaml
import os


logging.info('starting...')


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
  buttons[v['MAC']] = v['HA_EVENT']

# Look for arps
def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].hwsrc in buttons.keys(): # Found a button's MAC
      dashlog.write("Found a button\n")
      logging.info("Found a button - mac: " + pkt[ARP].hwsrc +  ", ip: " + pkt[ARP].psrc + " - sending event '" + buttons.get(pkt[ARP].hwsrc) + "'\n")
      # Fire a curl POST to HA's web API
      dashlog.write("\n")
      subprocess.call(["curl", "-H",              passwordParam, "-X", "POST", "http://" + host + ":8123/api/events/" + buttons.get(pkt[ARP].hwsrc)], stdout=dashlog)
      # Output response to log
    else:
      # Output unknown ARP's to the log as well
      dashlog.write("ARP Probe from unknown device: " + pkt[ARP].hwsrc + "\n")
      logging.debug("ARP Probe from unknown device: mac: " + pkt[ARP].hwsrc + " ip: " +  pkt[ARP].psrc + "\n")


logging.info('sniffing...')
# Run it
sniff(prn=arp_display, filter="arp", store=0, count=0)
