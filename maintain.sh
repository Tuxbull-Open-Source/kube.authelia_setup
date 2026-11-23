#!/usr/bin/env bash
# Only the fixed reviewed root-owned helper crosses the privilege boundary.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
HELPER=/usr/local/libexec/authelia-maintenance-v1.py
if [[ $# -eq 0 || "$1" == --help || "$1" == -h || "$1" == help ]]; then
  printf '%s\n' \
    'Usage: ./maintain.sh COMMAND' \
    '  status                       Read-only enrolled resource status' \
    '  plan [--latest-stable]        Prepare immutable same-family patch plan' \
    '  upgrade PLAN                 Supervised cold backup, upgrade and checks' \
    '  logs OP                      Durable state and private log locations' \
    '  backup                       Supervised cold backup (downtime)' \
    '  list-backups                 Eligible Velero recovery points' \
    '  restore BACKUP --accept-data-loss  Safety backup then namespace replacement' \
    'One checkout: current_config/config.json. No --config or CONFIG_FILE override.' \
    'Enroll first with ./provision-host.sh; existing sudo rights required.' \
    'Never sudo this checkout launcher. No automatic image/schema rollback.'
  exit 0
fi
[[ $EUID -ne 0 ]] || { printf 'Run as the checkout operator, not root.\n' >&2; exit 2; }
[[ -z "${CONFIG_FILE:-}" ]] || { printf 'CONFIG_FILE overrides are not supported.\n' >&2; exit 2; }
/usr/bin/python3 -I -c '
import pathlib, stat, sys
p = pathlib.Path("/usr/local/libexec/authelia-maintenance-v1.py")
try:
    for executable in (p, pathlib.Path("/usr/bin/python3.12")):
        for item in (executable, *executable.parents):
            s = item.lstat()
            if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
                raise ValueError()
            if item == executable and not stat.S_ISREG(s.st_mode):
                raise ValueError()
            if item != executable and not stat.S_ISDIR(s.st_mode):
                raise ValueError()
except (OSError, ValueError):
    sys.exit("Reviewed protected helper required; enroll with provision-host.sh before maintenance.")
'
exec /usr/bin/sudo "$HELPER" --checkout "$ROOT" "$@"
