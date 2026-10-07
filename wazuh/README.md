# Wazuh single node

Wazuh 4.9.2 SIEM (manager, indexer, dashboard) on Docker Desktop for Windows. State lives in named volumes under the `single-node` project name; this folder holds the compose file, mounted config, and the custom detection content that gets copied into the manager.

## What's custom

- `unifi_decoder.xml`, `unifi_rules.xml`: decoder and rules for UniFi gateway syslog.
- `local_tuning_rules.xml`: noise reduction and overrides for Sysmon and the home LAN.
- `custom-homeassistant.py`: integration script that forwards alerts at or above a level threshold to a Home Assistant webhook, with group filtering, cooldown and burst protection. Copy of [wazuh-homeassistant](https://github.com/benschugel/wazuh-homeassistant), which also has the Home Assistant package and tests.
- `DockerListener.py`: Wazuh's Docker event listener wodle, kept here so it can be dropped back into the manager after an upgrade.
- `docker-compose.yml`: upstream single-node compose with passwords moved to `.env`.

## Files that stay local

Copy each example and fill it in; the real files are gitignored.

| Example | Real file | Holds |
|---|---|---|
| `.env.example` | `.env` | `INDEXER_PASSWORD`, `API_PASSWORD`, `DASHBOARD_PASSWORD` used by the compose file |
| `config/wazuh_dashboard/wazuh.yml.example` | `config/wazuh_dashboard/wazuh.yml` | the dashboard's API connection, including the `wazuh-wui` password |

Also local and ignored: `config/wazuh_indexer/internal_users.yml` (hashed indexer users; must match `.env`) and `config/wazuh_indexer_ssl_certs/` (generated once with `docker compose -f generate-indexer-certs.yml run --rm generator`).

## Run

```
docker compose up -d
```

First start takes a minute or two while the indexer initializes. Dashboard is at https://localhost (port 443), API at https://localhost:55000.

## Attribution

`docker-compose.yml`, `generate-indexer-certs.yml`, everything under `config/`, and `DockerListener.py` are adapted from [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker) and remain under that project's GPLv2 license. The custom rules, decoder, tuning, and Home Assistant integration are mine and are covered by this repository's license.
