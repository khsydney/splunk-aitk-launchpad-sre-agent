#!/usr/bin/env bash
# Install or update the TukTukPay SRE Agent Splunk app (splunk/sre-app) on the EC2 Splunk WITHOUT a restart:
# upload, stage under $SPLUNK_HOME, POST services/apps/local (update=true), then clear Splunk Web's static cache (_bump).
# The admin password reaches the instance on stdin into a mode-600 netrc file that is removed afterwards.
# Usage: install-sre-app.sh splunk/sre-app/dist/tuktukpay_sre_agent-<version>.tgz
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd); PKG=$1
# environment: SPLUNK_CREDS_FILE (line 1 admin user, line 2 password), SSH_KEY, SPLUNK_SSH_HOST (ssh target),
# SPLUNK_HOSTNAME (name on the TLS certificate of the management port), SPLUNK_WEB_URL (for the static-cache bump)
CREDS=${SPLUNK_CREDS_FILE:?set SPLUNK_CREDS_FILE}; KEY=${SSH_KEY:?set SSH_KEY}
[ "$(tar -tzf "$PKG" | head -1 | cut -d/ -f1)" = tuktukpay_sre_agent ] || { echo "not the tuktukpay_sre_agent package" >&2; exit 1; }
HOST=${SPLUNK_HOSTNAME:?set SPLUNK_HOSTNAME}; IP=${SPLUNK_SSH_HOST:?set SPLUNK_SSH_HOST}
ssh_() { ssh -i "$KEY" -o ConnectTimeout=10 "ec2-user@$IP" "$@"; }
scp -q -i "$KEY" "$PKG" "ec2-user@$IP:/tmp/sre-app.tgz"
{ printf 'machine %s login %s password ' "$HOST" "$(sed -n 1p "$CREDS")"; sed -n 2p "$CREDS"; } | ssh_ 'umask 077; cat > /tmp/sre-app.netrc'
ssh_ HOST=$HOST bash -s <<'REMOTE'
set -euo pipefail
trap 'rm -f /tmp/sre-app.netrc /tmp/sre-app.tgz' EXIT
STAGE=/opt/splunk/var/run/tuktukpay-stage; sudo install -d -o splunk -g splunk -m 700 $STAGE
sudo install -o splunk -g splunk -m 600 /tmp/sre-app.tgz $STAGE/sre-app.tgz
C=(curl -sS --netrc-file /tmp/sre-app.netrc --resolve "$HOST:8089:127.0.0.1")
"${C[@]}" -o /dev/null -w "apps/local -> HTTP %{http_code}\n" "https://$HOST:8089/services/apps/local" --data-urlencode "name=$STAGE/sre-app.tgz" -d filename=true -d update=true
sudo rm -f $STAGE/sre-app.tgz
"${C[@]}" "https://$HOST:8089/services/apps/local/tuktukpay_sre_agent?output_mode=json" | python3 -c 'import json,sys; c=json.load(sys.stdin)["entry"][0]["content"]; print("installed", c.get("version"), "disabled" if c["disabled"] else "enabled")'
REMOTE
python3 -I -c "
import sys; sys.path.insert(0,'$DIR/../lib')
from stack import S, BASE
st,_=S._req(BASE + '/en-US/_bump', b'', S.h); print('static cache bump ->', st)"
