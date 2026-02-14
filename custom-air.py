#!/usr/bin/env python

import json
import sys
import time
import os

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip3 install requests")
    sys.exit(1)
    
# ossec.conf configuration:
#  <integration>
#    <name>custom-air</name>
#    <hook_url>Wazuh WebHook URL</hook_url>
#    <rule_id>XXXXXX</rule_id>
#    <alert_format>json</alert_format>
#  </integration>


debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)


def main(args):
    debug("# Starting")

    # Read args
    alert_file_location = args[1]
    webhook = args[3]

    debug("# Webhook")
    debug(webhook)
    debug("# File location")
    debug(alert_file_location)
    
    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)
    debug("# Generating message")
    msg = generate_msg(json_alert)
    debug(msg)
    debug("# Sending message")
    send_msg(msg, webhook)

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file, "a")
        f.write(msg)
        f.close()
        
def generate_msg(alert):
    level = alert['rule']['level']
    msg = {}
    msg['pretext'] = "WAZUH AIR integration"
    msg['Name'] = alert['agent']['name']
    msg['IP'] = alert['agent']['ip']
    msg['Title'] = alert['rule']['description'] if 'description' in alert['rule'] else "N/A"
    msg['Rule ID'] = alert['rule']['id']
    msg['ts'] = alert['id']
    attach = {'attachments': [msg]}
    return json.dumps(attach)
    
def send_msg(msg, url):
    headers = {'User-Agent': 'AIR Script', 'Content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers)
    debug(res)
    
if __name__ == "__main__":

    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                now,
                sys.argv[1],
                sys.argv[2],
                sys.argv[3],
                sys.argv[4] if len(sys.argv) > 4 else '',
            )
            debug_enabled = (len(sys.argv) > 4 and sys.argv[4] == 'debug')
            
             else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True
            
            # Logging the call
        f = open(log_file, 'a')
        f.write(msg + '\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
