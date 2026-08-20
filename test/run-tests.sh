#!/usr/bin/env bash
# Sentinel functional test suite.
#
# Runs a real WordPress against a real MariaDB and asserts that each signal
# fires. wp-cli bootstraps WordPress fully and fires the same hooks a web
# request would, so no Apache is needed.
#
#   ./run-tests.sh
#
# Leaves nothing behind: every container and volume is removed on exit.

set -uo pipefail

NET=pdsentinel-test-net
DB=pdsentinel-test-db
SHARED="$(cd "$(dirname "$0")" && pwd)/.shared"
PLUGIN="$(cd "$(dirname "$0")/.." && pwd)/wp-sentinel.php"
WPVOL=pdsentinel-test-wp

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }

cleanup() {
  docker rm -f "$DB" pdsentinel-listener >/dev/null 2>&1
  docker volume rm "$WPVOL" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$SHARED"
}
trap cleanup EXIT

rm -rf "$SHARED"; mkdir -p "$SHARED"
cleanup >/dev/null 2>&1
docker network create "$NET" >/dev/null
docker volume create "$WPVOL" >/dev/null

wp() {
  docker run --rm --network "$NET" \
    -v "$WPVOL":/var/www/html \
    -v "$SHARED":/shared \
    -u33:33 -w /var/www/html \
    wordpress:cli wp --allow-root "$@" 2>&1
}

echo "== booting database =="
docker run -d --name "$DB" --network "$NET" \
  -e MARIADB_ROOT_PASSWORD=root \
  -e MARIADB_DATABASE=wp \
  mariadb:10.11 >/dev/null

until docker exec "$DB" mariadb -uroot -proot -e 'select 1' >/dev/null 2>&1; do sleep 2; done
echo "   database up"

echo "== installing wordpress =="
wp core download --version=6.5 >/dev/null
wp config create --dbname=wp --dbuser=root --dbpass=root --dbhost="$DB" --skip-check >/dev/null
wp core install --url=http://test.local --title="Sentinel Test" \
  --admin_user=owner --admin_password=pw --admin_email=owner@test.local --skip-email >/dev/null
echo "   $(wp core version) installed"

echo "== starting webhook listener =="
docker run -d --name pdsentinel-listener --network "$NET" \
  -v "$(pwd)":/app -v "$SHARED":/shared -w /app \
  wordpress:cli php -S 0.0.0.0:8080 listener.php >/dev/null
sleep 3

echo "== installing sentinel =="
wp config set SENTINEL_WEBHOOK "http://pdsentinel-listener:8080/" >/dev/null
wp config set SENTINEL_SECRET  "test-secret-value"                >/dev/null
wp config set SENTINEL_LABEL   "Sentinel Test Site"               >/dev/null
wp config set SENTINEL_EMAIL   "alerts@test.local"                >/dev/null

docker run --rm -v "$WPVOL":/var/www/html -v "$(dirname "$PLUGIN")":/src -v "$(pwd)":/test \
  -u0:0 wordpress:cli sh -c \
  'mkdir -p /var/www/html/wp-content/mu-plugins && \
   cp /src/wp-sentinel.php /var/www/html/wp-content/mu-plugins/ && \
   cp /test/mail-capture.php /var/www/html/wp-content/mu-plugins/ && \
   chown -R 33:33 /var/www/html/wp-content/mu-plugins' >/dev/null

# Sanity gates. Without these a broken wp-config or a plugin that never loaded
# shows up as a wall of confident-looking passes on tests that never ran.
CFG=$(wp option get siteurl)
if echo "$CFG" | grep -qi "parse error\|fatal error"; then
  echo "ABORT: wp-config is broken, nothing below would mean anything:"
  echo "$CFG"
  exit 1
fi

LOADED=$(wp eval 'echo class_exists("Sentinel") ? "yes" : "no";')
if [ "$LOADED" != "yes" ]; then
  echo "ABORT: Sentinel class did not load (got: $LOADED)"
  exit 1
fi
echo "   sentinel loaded"

# init runs, baseline is recorded
wp option get siteurl >/dev/null

echo ""
echo "== TESTS =="

# ---------------------------------------------------------------- baseline
BASE=$(wp option get sentinel_baseline --format=json)
if echo "$BASE" | grep -q "plugins"; then ok "baseline recorded on first run"; else bad "baseline not recorded (got: $BASE)"; fi
if [ ! -s "$SHARED/webhook.log" ]; then ok "silent on install (no alert for pre-existing plugins)"; else bad "alerted on install"; fi

# --------------------------------------------------------- admin created
wp user create intruder intruder@evil.test --role=administrator >/dev/null
sleep 1
if grep -q '"type":"admin_created"' "$SHARED/webhook.log" 2>/dev/null; then ok "new administrator fires admin_created"; else bad "no admin_created alert"; fi
if grep -q '"new_user":"intruder"' "$SHARED/webhook.log" 2>/dev/null; then ok "alert names the new account"; else bad "alert missing username"; fi
if grep -q '"site":"Sentinel Test Site"' "$SHARED/webhook.log" 2>/dev/null; then ok "alert names the site"; else bad "alert missing site label"; fi
if grep -q 'sha256=' "$SHARED/webhook.log" 2>/dev/null; then ok "webhook body is HMAC signed"; else bad "no signature header"; fi
if grep -q 'admin_created' "$SHARED/mail.log" 2>/dev/null || grep -q 'New administrator' "$SHARED/mail.log" 2>/dev/null; then ok "email path also fires"; else bad "no email sent"; fi

ADMCREATED=$(grep -c '"type":"admin_created"' "$SHARED/webhook.log" 2>/dev/null; true)
ADMPROMO=$(grep -c '"type":"admin_promoted"' "$SHARED/webhook.log" 2>/dev/null; true)
if [ "$ADMCREATED" = "1" ]; then ok "exactly one admin_created (no duplicate)"; else bad "expected 1 admin_created, got $ADMCREATED"; fi
if [ "$ADMPROMO" = "0" ]; then ok "creating an admin does not also fire admin_promoted"; else bad "creation double-alerted as promotion ($ADMPROMO)"; fi

# ------------------------------------------------------- non-admin quiet
BEFORE=$(wc -l < "$SHARED/webhook.log")
wp user create normaluser normal@test.local --role=author >/dev/null
sleep 1
AFTER=$(wc -l < "$SHARED/webhook.log")
if [ "$BEFORE" = "$AFTER" ]; then ok "creating a non-admin is silent"; else bad "author creation raised an alert"; fi

# ---------------------------------------------------------- promotion
wp user set-role normaluser administrator >/dev/null
sleep 1
if grep -q '"type":"admin_promoted"' "$SHARED/webhook.log" 2>/dev/null; then ok "promotion to admin fires admin_promoted"; else bad "no admin_promoted alert"; fi
if grep -q '"from_roles":"author"' "$SHARED/webhook.log" 2>/dev/null; then ok "promotion alert records the previous role"; else bad "promotion alert missing from_roles"; fi

# ------------------------------------------------- webshell dropped on disk
docker run --rm -v "$WPVOL":/var/www/html -u0:0 wordpress:cli sh -c \
  'mkdir -p /var/www/html/wp-content/plugins/security-version-mitigation && \
   echo "<?php /* shell */" > /var/www/html/wp-content/plugins/security-version-mitigation/icon.php && \
   chown -R 33:33 /var/www/html/wp-content/plugins/security-version-mitigation' >/dev/null
wp cron event run sentinel_scan >/dev/null
sleep 1
if grep -q '"type":"files_appeared"' "$SHARED/webhook.log" 2>/dev/null; then ok "unactivated folder on disk fires files_appeared"; else bad "no files_appeared alert"; fi
if grep -q 'security-version-mitigation' "$SHARED/webhook.log" 2>/dev/null; then ok "alert names the folder"; else bad "alert missing folder name"; fi

# ------------------------------------------------------- plugin activated
wp plugin activate hello >/dev/null 2>&1 || wp plugin activate akismet >/dev/null 2>&1
sleep 1
if grep -q '"type":"plugin_activated"' "$SHARED/webhook.log" 2>/dev/null; then ok "plugin activation fires plugin_activated"; else bad "no plugin_activated alert"; fi

# ------------------------------------------------------------- heartbeat
wp cron event run sentinel_heartbeat >/dev/null
sleep 2
if grep -q '"type":"heartbeat"' "$SHARED/webhook.log" 2>/dev/null; then ok "daily heartbeat fires"; else bad "no heartbeat"; fi
if grep -q '"admins":3' "$SHARED/webhook.log" 2>/dev/null; then ok "heartbeat reports the administrator count"; else bad "heartbeat admin count wrong (expected 3)"; fi
if ! grep -q '"type":"heartbeat"' "$SHARED/mail.log" 2>/dev/null; then ok "heartbeat does not email (webhook only)"; else bad "heartbeat sent an email"; fi

# ----------------------------------------------------------- signature check
python3 - "$SHARED/webhook.log" <<'PY'
import json,sys,hmac,hashlib
bad=0; checked=0
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    rec=json.loads(line)
    body=json.dumps(rec["body"],separators=(',',':'))
    sig=rec["sig"]
    checked+=1
print(f"  INFO  {checked} webhook deliveries captured")
PY

# --------------------------------------------------- identity on a clone
# These installs get cloned to spin up new sites, and a clone inherits the
# source site's SENTINEL_LABEL. An alert titled with the wrong practice is
# worse than no alert, so the live domain has to win.
if grep -q '"host":' "$SHARED/webhook.log" 2>/dev/null; then ok "alerts carry the live domain, not just the label"; else bad "no host field in alert"; fi
if grep -q '"wp_path":' "$SHARED/webhook.log" 2>/dev/null; then ok "alerts carry the install path"; else bad "no wp_path in alert"; fi

# Simulate a clone: the recorded origin host no longer matches the live one.
wp option update sentinel_origin_host "some-other-client.example" >/dev/null
wp user create clonecheck clone@test.local --role=administrator >/dev/null
sleep 1
if grep -q '"cloned_from":"some-other-client.example"' "$SHARED/webhook.log" 2>/dev/null; then ok "a cloned install reports where it was cloned from"; else bad "clone not detected"; fi
if grep -q 'label_warning' "$SHARED/webhook.log" 2>/dev/null; then ok "stale label raises a warning"; else bad "stale label not flagged"; fi
MAILHOST=$(grep -c 'Sentinel Test Site' "$SHARED/mail.log" 2>/dev/null; true)
if grep -q 'Domain:' "$SHARED/mail.log" 2>/dev/null; then ok "email leads with the domain"; else bad "email missing Domain line"; fi

# ----------------------------------------------------------------- dedupe
BEFORE=$(grep -c '"type":"files_appeared"' "$SHARED/webhook.log" 2>/dev/null; true)
wp cron event run sentinel_scan >/dev/null
sleep 1
AFTER=$(grep -c '"type":"files_appeared"' "$SHARED/webhook.log" 2>/dev/null; true)
if [ "$BEFORE" = "$AFTER" ]; then ok "rescan does not re-alert for the same folder"; else bad "duplicate files_appeared on rescan"; fi

echo ""
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
