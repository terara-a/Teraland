#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
teraland_output=artifacts/conformance
if [ "${CONFORMANCE_PROFILE:-federation}" = basic ]; then teraland_output=artifacts/conformance-basic; fi
mkdir -p "$teraland_output"
# Do not leave reports from an older successful run after a startup/build failure.
rm -f "$teraland_output/results.json" "$teraland_output/junit.xml" "$teraland_output/summary.md"
# No production deployment, external account or persistent credentials are used.
teraland_suite="${CONFORMANCE_SUITE_DIR:-$PWD/.local/conformance-suite}"
teraland_pin=$(node -p "JSON.parse(require('fs').readFileSync('scripts/conformance/upstream.json')).commit")
teraland_repo=$(node -p "JSON.parse(require('fs').readFileSync('scripts/conformance/upstream.json')).repository")
teraland_mongo_image=$(node -p "JSON.parse(require('fs').readFileSync('scripts/conformance/upstream.json')).mongoImage")
if [ ! -d "$teraland_suite/.git" ]; then
  mkdir -p "$teraland_suite"
  git -C "$teraland_suite" init -q
  git -C "$teraland_suite" remote add origin "$teraland_repo"
  git -C "$teraland_suite" fetch --depth 1 origin "$teraland_pin"
  git -C "$teraland_suite" checkout --detach FETCH_HEAD
fi
[ "$(git -C "$teraland_suite" rev-parse HEAD)" = "$teraland_pin" ] || { echo 'Unexpected suite revision' >&2; exit 1; }
git -C "$teraland_suite" diff --exit-code HEAD --quiet
# Compile the upstream server, not its own Java unit-test suite. Its protocol
# modules run below against the actual bundled Worker.
mvn -B -C -f "$teraland_suite/pom.xml" -Dmaven.test.skip=true -Dcheckstyle.skip=true -Dpmd.skip=true package
npm run build
mkdir -p .local artifacts/conformance
teraland_run=$(mktemp -d "$PWD/.local/conformance.XXXXXX")
teraland_mongo=''
cleanup() {
  if [ -n "$teraland_mongo" ]; then docker rm -f "$teraland_mongo" >/dev/null; fi
  rm -rf "$teraland_run"
}
trap cleanup EXIT
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=Teraland ephemeral CI CA' -keyout "$teraland_run/ca.key" -out "$teraland_run/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=op.teraland.test' \
  -keyout "$teraland_run/server.key" -out "$teraland_run/server.csr" >/dev/null 2>&1
cat > "$teraland_run/extensions" <<'EXT'
subjectAltName=DNS:op.teraland.test,DNS:suite.teraland.test
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in "$teraland_run/server.csr" -CA "$teraland_run/ca.pem" -CAkey "$teraland_run/ca.key" \
  -CAcreateserial -days 1 -sha256 -extfile "$teraland_run/extensions" -out "$teraland_run/server.pem" >/dev/null 2>&1
keytool -importcert -noprompt -alias teraland-ci -file "$teraland_run/ca.pem" \
  -keystore "$teraland_run/trust.p12" -storetype PKCS12 -storepass changeit >/dev/null 2>&1
printf '127.0.0.1 localhost op.teraland.test suite.teraland.test\n' > "$teraland_run/hosts"
teraland_mongo=$(docker run -d --rm -p 127.0.0.1::27017 "$teraland_mongo_image")
teraland_mongo_port=$(docker port "$teraland_mongo" 27017/tcp | sed 's/.*://')
node scripts/conformance/runner.mjs "$teraland_suite" "$teraland_run" "$teraland_mongo_port"
