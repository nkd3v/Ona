#!/bin/sh
# Deploy the committed code to the bot's server and restart it there.
#   sh deploy.sh         deploys HEAD
#   sh deploy.sh <ref>   deploys another commit
# Only committed files are copied, so uncommitted edits never go live.
# The server's .env and data/ folder are left as they are.
set -eu

HOST=${DEPLOY_HOST:-root@oci1}
DIR=${DEPLOY_DIR:-/opt/ona}
REF=${1:-HEAD}
FILES="Dockerfile .dockerignore compose.yaml pyproject.toml uv.lock bot.py main.py scam_filter.py scam-images"

cd "$(dirname "$0")"
commit=$(git rev-parse --short "$REF^{commit}")
echo "Deploying $commit to $HOST:$DIR"

# shellcheck disable=SC2086
git archive "$REF" $FILES | ssh "$HOST" "
  set -e
  mkdir -p '$DIR'
  tar -x -C '$DIR' --no-same-owner
  echo '$commit' > '$DIR/DEPLOYED_COMMIT'
  cd '$DIR'
  started=\$(date -u +%Y-%m-%dT%H:%M:%SZ)
  docker compose up -d --build --remove-orphans 2>&1 | tail -5
  for i in \$(seq 1 30); do
    if docker logs --since \"\$started\" ona 2>&1 | grep -q 'Logged in as'; then
      docker logs --since \"\$started\" ona 2>&1 | grep -E 'Logged in as|WARNING|ERROR' | head -10
      echo 'Bot is up.'
      exit 0
    fi
    sleep 2
  done
  echo 'The bot did not log in within 60 seconds. Last log lines:' >&2
  docker logs --tail 30 ona >&2
  exit 1
"
