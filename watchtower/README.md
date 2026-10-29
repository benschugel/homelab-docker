# watchtower

Nightly image updates for the opt-in containers in this repo, using the maintained [nickfedor/watchtower](https://github.com/nicholas-fedor/watchtower) fork (the original containrrr/watchtower was archived in December 2025).

## What gets updated

Watchtower runs with `WATCHTOWER_LABEL_ENABLE=true`, so it only touches containers carrying `com.centurylinklabs.watchtower.enable: "true"`:

| Stack | Labeled | Why |
|---|---|---|
| uptime-kuma | yes | rolling `:2` tag |
| paperless (webserver, db, broker, gotenberg) | yes | rolling tags; Paperless runs its own DB migrations on start |
| paperless tika | no | pinned to 3.3.1.0 on purpose (4.x breaks .eml parsing) |
| watchtower | yes | self-update |
| frigate | no | local build (`frigate-trt:local`), nothing to pull |
| wazuh, wazuh-mcp | no | pinned versions; Wazuh upgrades are a manual job |

To opt a service in, add under it in its compose file and run `docker compose up -d` in that stack's folder:

```yaml
labels:
  com.centurylinklabs.watchtower.enable: "true"
```

Schedule is daily at 04:00 America/Chicago (`WATCHTOWER_SCHEDULE`, 6-field cron). Old images are removed after a successful update (`WATCHTOWER_CLEANUP`).

## Uptime Kuma heartbeat

After every scan Watchtower sends its session report through shoutrrr's generic webhook to the Uptime Kuma push endpoint. Kuma ignores the body and reads `status=up` from the query string, so the monitor goes DOWN only when a scan does not happen.

Setup:

1. In Uptime Kuma: Add New Monitor, type **Push**, name `Watchtower`, Heartbeat Interval `90000` (25 h, one daily push plus slack), Retries `0`. Save.
2. Copy the token from the monitor's Push URL (`/api/push/<TOKEN>`) into `.env` as `KUMA_PUSH_TOKEN` (see `.env.example`).
3. `docker compose up -d` here. The startup message pushes immediately, so the monitor should turn green within a few seconds.

Verify: `docker logs watchtower` should show the notification being sent, and the monitor's latest heartbeat should read `watchtower scan ok`.

Trigger a scan by hand (restarts the container, which also re-sends the startup heartbeat): `docker compose restart`. For a one-off dry run that touches nothing:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock nickfedor/watchtower:1 --run-once --label-enable --monitor-only
```

## Notes

- Watchtower joins the external network `uptime-kuma_default` to reach Kuma as `uptime-kuma:3001`. If the Kuma stack's project name ever changes, update `networks.kuma.name`.
- When Watchtower updates Uptime Kuma itself, that night's push can fail while Kuma restarts. The 25 h heartbeat window absorbs one miss; the next night's push clears it.
- `.env` holds the push token and is gitignored.
