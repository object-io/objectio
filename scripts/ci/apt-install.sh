#!/usr/bin/env bash
# apt-install.sh <package>...: install packages on a CI runner, retrying a
# stalled mirror instead of waiting on it. A runner's Azure mirror has hung
# `apt-get update` for hours; each attempt here is cut off after 3 minutes,
# and apt gives up on an unresponsive server after 30 seconds.
set -uo pipefail
opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
for attempt in 1 2 3; do
  if sudo timeout 180 apt-get "${opts[@]}" update &&
    sudo timeout 600 apt-get "${opts[@]}" install -y "$@"; then
    exit 0
  fi
  echo "::warning::apt attempt $attempt of 3 failed; retrying"
  sleep $((attempt * 10))
done
echo "::error::apt could not install: $*"
exit 1
