# Wazuh integration: forward alerts to a Home Assistant webhook.
#
# ossec.conf configuration structure
#  <integration>
#      <name>custom-homeassistant</name>
#      <hook_url>http://HA_HOST:8123/api/webhook/WEBHOOK_ID</hook_url>
#      <level>10</level>
#      <alert_format>json</alert_format>
#  </integration>

import json
import os
import sys

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3
# Rule groups that never notify, whatever their level.
SKIP_GROUPS = {'vulnerability-detector'}


def log(msg: str) -> None:
    with open(LOG_FILE, 'a') as f:
        f.write(f'custom-homeassistant: {msg}\n')


def get_json_alert(file_location: str) -> dict:
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        log(f"alert file {file_location} doesn't exist")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        log(f'failed parsing alert JSON: {e}')
        sys.exit(ERR_INVALID_JSON)


def generate_msg(alert: dict) -> dict:
    rule = alert.get('rule', {})
    agent = alert.get('agent', {})
    level = rule.get('level', 0)
    description = rule.get('description', 'N/A')
    agent_name = agent.get('name', 'unknown')

    return {
        'title': f'Wazuh level {level}: {agent_name}',
        'message': f"{description} (rule {rule.get('id', '?')})",
        'level': level,
        'rule_id': rule.get('id'),
        'description': description,
        'agent': agent_name,
        'groups': rule.get('groups', []),
        'timestamp': alert.get('timestamp'),
        'alert_id': alert.get('id'),
    }


def main(args) -> None:
    if len(args) < 4:
        log(f'wrong arguments: {args}')
        sys.exit(ERR_BAD_ARGUMENTS)

    alert = get_json_alert(args[ALERT_INDEX])
    msg = generate_msg(alert)

    # Vulnerability findings are inventory, not incidents. A single browser
    # update can produce dozens at level 10+, so they stay in the dashboard
    # and out of the phone.
    if any(g in SKIP_GROUPS for g in msg['groups']):
        log(f"rule {msg['rule_id']} level {msg['level']} skipped (group filter)")
        return

    # The webhook URL is a secret, so it is never written to the log.
    try:
        res = requests.post(args[WEBHOOK_INDEX], json=msg, timeout=10)
        log(f"rule {msg['rule_id']} level {msg['level']} sent, HTTP {res.status_code}")
    except requests.RequestException as e:
        log(f"rule {msg['rule_id']} level {msg['level']} send failed: {type(e).__name__}")
        raise


if __name__ == '__main__':
    main(sys.argv)
