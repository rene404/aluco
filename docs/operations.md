# Operations: backup, restore, update

As of: 2026-11-19

## Backup – `scripts/backup.sh`

```sh
scripts/backup.sh                 # to ./backups, the last 7 are kept
ALUCO_BACKUP_KEEP=14 scripts/backup.sh /mnt/usb/aluco
```

- Runs **while in operation** – no DNS outage. The Aluco database is copied consistently with the SQLite online backup (works with any Aluco version, including before an update).
- Contains `data/` (Aluco, AdGuard, NetAlertX, Caddy certificates), `.env` and `compose.override.yaml` if present. The threat list cache is left out.
- Archives are readable by the owner only (`600`). They contain **passwords, tokens and the private key of the HTTPS certificate authority** – store them off-site only encrypted.

Daily and automatic (crontab of the user who is allowed to use Docker):

```cron
30 3 * * *  cd /opt/aluco && scripts/backup.sh >/dev/null 2>>backups/backup.log
```

## Restore – `scripts/restore.sh`

```sh
scripts/restore.sh backups/aluco-20261119-033000.tar.gz
```

Asks for confirmation, stops the services, moves the current state to `data.vor-restore-<time>` (and `.env` likewise), unpacks, sets the permissions and restarts. Archives with absolute paths or `..` are rejected.

## Update – `scripts/update.sh`

```sh
scripts/update.sh           # latest state of main
scripts/update.sh v0.2.0    # specific version
```

Procedure: **backup → `git` to the new state → pull/build images → restart → dashboard health check**. Aborts if the repo has local changes. If HTTPS (Caddy) is running, it stays active.

Going back if there are problems: `git checkout <previous version> && docker compose up -d --build` or `scripts/restore.sh <latest backup>`.

## Disk space

On every run, Aluco checks the free space on the disk holding the data. Below **1 GB or 5 %**, a warning appears under data sources in the dashboard and in the timeline ("Disk space low"). Remedies: delete old backups, shorten retention (`ALUCO_RETENTION_DAYS`), `docker image prune`.
