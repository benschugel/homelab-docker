# Wazuh single node

Wazuh 4.14.8 SIEM (manager, indexer, dashboard) on Docker Desktop for Windows. State lives in named volumes under the `single-node` project name; this folder holds the compose file, mounted config, the shared agent config and the two scripts that run on the manager.

## Detection content

The UniFi decoder, the detection and tuning rules, the Sysmon configuration the agents run, and their test suite live in [wazuh-detections](https://github.com/benschugel/wazuh-detections) (checkout `C:\Users\schug\src\wazuh-detections`). That repository is the source of truth; nothing under this folder carries rules any more.

Deploy from that checkout into the running manager:

```
cd C:\Users\schug\src\wazuh-detections
./deploy.sh --dry-run
./deploy.sh
```

The rules sit in the `wazuh_etc` named volume, so they survive restarts but not `docker compose down -v`; run `deploy.sh` again after that or after an image upgrade. The deployed commit is in `/var/ossec/etc/wazuh-detections.version` inside the container.

## What's custom here

- `custom-homeassistant.py`: integration script that forwards alerts at or above a level threshold to a Home Assistant webhook, with group filtering, cooldown and burst protection. Copy of [wazuh-homeassistant](https://github.com/benschugel/wazuh-homeassistant), which also has the Home Assistant package and tests.
- `DockerListener.py`: Wazuh's Docker event listener wodle, patched to split multi-event chunks (the stock copy crashed on "Extra data" every few minutes). Copy it back to `/var/ossec/wodles/docker/DockerListener.py` (`root:wazuh`, mode 750) after an image upgrade.
- `agent.conf`: shared config for the `default` agent group, see below.
- `docker-compose.yml`: upstream single-node compose with passwords moved to `.env`.

## Files that stay local

Copy each example and fill it in; the real files are gitignored.

| Example | Real file | Holds |
|---|---|---|
| `.env.example` | `.env` | `INDEXER_PASSWORD`, `API_PASSWORD`, `DASHBOARD_PASSWORD` used by the compose file |
| `config/wazuh_dashboard/wazuh.yml.example` | `config/wazuh_dashboard/wazuh.yml` | the dashboard's API connection, including the `wazuh-wui` password |
| `config/wazuh_cluster/wazuh_manager.conf.example` | `config/wazuh_cluster/wazuh_manager.conf` | manager config; the real one holds the Home Assistant webhook URL and the cluster key |

Also local and ignored: `config/wazuh_indexer/internal_users.yml` (hashed indexer users; must match `.env`) and `config/wazuh_indexer_ssl_certs/` (generated once with `docker compose -f generate-indexer-certs.yml run --rm generator`).

## Run

```
docker compose up -d
```

First start takes a minute or two while the indexer initializes. Dashboard is at https://localhost (port 443), API at https://localhost:55000.

## Manager config quirks

- `config/wazuh_cluster/wazuh_manager.conf` is only copied into the container on its first start. A restart does not re-copy it, so config edits must also be applied to `/var/ossec/etc/ossec.conf` inside the container (then `wazuh-control restart`).
- The live `ossec.conf` carries a VirusTotal integration block with an API key that the host file does not. Recreating the container would drop it; reconcile the host file first.
- `log_alert_level` is 1 since 2026-10-07, so level 1 and 2 alerts are stored and indexed. Home Assistant is notified at level 10 and above.
- Since 2026-10-08 the VirusTotal block triggers on `<rule_id>550,554</rule_id>` instead of `<group>syscheck</group>` (registry changes were burning the API quota), and the manager's own `<sca>` block is `<enabled>no</enabled>` in the live config, the host config and the tracked example.
- Since 2026-10-09 the `<ruleset>` block declares the three `etc/lists/malicious-ioc/*` lists that the stock image config has and the host config lacked. Without them rules 99901 to 99920 were skipped at every start with a "could not be loaded" warning.
- The Windows agents' client buffer is raised in `agent.conf` because the default queue of 5000 events overflowed every time the manager restarted.

## Shared agent config

`agent.conf` is the centralized config for the `default` agent group
(`/var/ossec/etc/shared/default/agent.conf` in the manager). It holds the
Windows client buffer size, the Downloads FIM path, the Claude Desktop config
FIM entries with `report_changes` (tuning rule 100262 in wazuh-detections keeps
those modifications at level 3), and the W32Time registry ignores. After
copying it in, run `/var/ossec/bin/verify-agent-conf` inside the container.

## Attribution

`docker-compose.yml`, `generate-indexer-certs.yml`, everything under `config/`, and `DockerListener.py` are adapted from [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker) and remain under that project's GPLv2 license. The Home Assistant integration is mine and is covered by this repository's license.
