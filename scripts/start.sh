#!/usr/bin/env sh
# Builds and starts the Audit Integrity Platform in Docker (macOS and Linux; scripts/start.ps1 on
# Windows). Only Docker is required. The first run creates API keys in keys/api-keys.txt, their
# SHA-256 entries in keys/aip.env and an Ed25519 signing key in the aip-keys volume.
#
#   scripts/start.sh             build and start the API (8000) and the test UI (8080)
#   scripts/start.sh --dbadmin   also start the SQLite browser (8082)
#   scripts/start.sh --reset     delete all audit data first, then start (keys are kept)
#   scripts/start.sh --stop      stop and remove the containers (data and keys are kept)
#   scripts/start.sh --show-keys print the API keys at the end
set -eu

cd "$(dirname "$0")/.."
IMAGE=audit-integrity-platform
DBADMIN=0; RESET=0; STOP=0; SHOW_KEYS=0
for arg in "$@"; do
  case "$arg" in
    --dbadmin) DBADMIN=1 ;;
    --reset) RESET=1 ;;
    --stop) STOP=1 ;;
    --show-keys) SHOW_KEYS=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '==> %s\n' "$1"; }
fail() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "Docker is not installed. Install Docker Desktop (or Docker Engine) and run this script again."
docker info >/dev/null 2>&1 || fail "The Docker engine is not running. Start Docker and run this script again."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is missing. Update Docker."

# Containers with these names that compose did not create (an older manual setup) block `compose up`.
remove_legacy() {
  managed=$(docker ps -a --filter label=com.docker.compose.project=aip --format '{{.Names}}')
  for name in aip aip-ui aip-sqlite-web; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$name" && ! printf '%s\n' "$managed" | grep -qx "$name"; then
      step "Removing container '$name' from the earlier manual setup (data is kept)"
      docker rm -f "$name" >/dev/null
    fi
  done
}

if [ "$STOP" = 1 ]; then
  step "Stopping the stack (data and keys are kept)"
  docker compose --profile dbadmin down >/dev/null
  remove_legacy
  echo "Stopped. Start again with scripts/start.sh"
  exit 0
fi

if [ "$RESET" = 1 ]; then
  step "Deleting all audit data (volumes aip-data and aip-archives; keys are kept)"
  docker compose --profile dbadmin down >/dev/null
  remove_legacy
  for volume in aip-data aip-archives; do
    if docker volume ls -q | grep -qx "$volume"; then docker volume rm "$volume" >/dev/null; fi
  done
fi

step "Building the API image"
docker compose build aip

mkdir -p keys
NEW_KEYS=0
if [ ! -f keys/aip.env ]; then
  step "Creating API keys for writer, auditor and admin"
  umask 077
  {
    echo "# API keys for the local aip stack. Keep them private (keys/ is git-ignored)."
    echo "# Paste each key into the matching box at http://127.0.0.1:8080"
  } > keys/api-keys.txt
  entries=""
  for role in writer auditor admin; do
    out=$(docker run --rm "$IMAGE" python -m aip.cli new-api-key --role "$role")
    echo "$role key: $(printf '%s\n' "$out" | sed -n 's/^api key (shown once): //p')" >> keys/api-keys.txt
    entries="$entries,$(printf '%s\n' "$out" | sed -n 's/^AIP_API_KEYS entry: *//p')"
  done
  printf 'AIP_API_KEYS=%s\nAIP_SIGNING_KEY_PATH=keys/signing.pem\n' "${entries#,}" > keys/aip.env
  NEW_KEYS=1
fi

remove_legacy
if ! docker compose run --rm --no-deps aip test -f keys/signing.pem; then
  step "Creating the Ed25519 signing key (volume aip-keys)"
  out=$(docker compose run --rm --no-deps aip python -m aip.cli new-signing-key --out keys/signing.pem)
  printf '\nsigning public key (hex): %s\n' "$(printf '%s\n' "$out" | sed -n 's/^public key (hex): *//p')" >> keys/api-keys.txt
fi

step "Starting the containers"
if [ "$DBADMIN" = 1 ]; then set -- --profile dbadmin; else set --; fi
if ! docker compose "$@" up -d; then
  docker logs --tail 30 aip || true
  fail "The stack did not start. If the log says 'unexpected schema', the database was edited by hand: run scripts/start.sh --reset"
fi

health=""
i=0
while [ $i -lt 60 ]; do
  health=$(docker inspect -f '{{.State.Health.Status}}' aip)
  [ "$health" = healthy ] && break
  i=$((i + 1)); sleep 1
done
if [ "$health" != healthy ]; then
  docker logs --tail 30 aip || true
  fail "The API is not healthy ($health). If the log says 'unexpected schema', run scripts/start.sh --reset"
fi

echo
echo "Audit Integrity Platform is running"
echo "  Test UI         http://127.0.0.1:8080"
echo "  API docs        http://127.0.0.1:8000/docs"
[ "$DBADMIN" = 1 ] && echo "  SQLite browser  http://127.0.0.1:8082"
echo
if [ "$NEW_KEYS" = 1 ] || [ "$SHOW_KEYS" = 1 ]; then
  echo "API keys (also saved in keys/api-keys.txt):"
  grep ' key: ' keys/api-keys.txt | sed 's/^/  /'
else
  echo "API keys: keys/api-keys.txt (run with --show-keys to print them)"
fi
echo
echo "Paste the keys into the boxes at the top of the test UI, then try Write > Load 12 sample events"
echo "and Verify > Verify now. Stop with scripts/start.sh --stop"
