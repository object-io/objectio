#!/usr/bin/env bash
# The development container (dev/README.md).
#
#   dev/devbox.sh up       # build the image and start the container
#   dev/devbox.sh shell    # a shell in it (starts it if needed)
#   dev/devbox.sh claude   # Claude Code in it, in the repo
#   dev/devbox.sh down     # stop and remove it (the caches stay)
#
#   CODE   the directory holding the repos, mounted at the same path
#          (default: the parent of this repo)
#   CACHE  cargo's cache (default: $CODE/.devbox-cache)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CODE=${CODE:-$(dirname "$REPO")}
CACHE=${CACHE:-$CODE/.devbox-cache}
NAME=objectio-dev
IMAGE=objectio-dev:latest
DOCKER_GID=$(stat -c %g /var/run/docker.sock 2>/dev/null || echo 999)

mounts=(
    -v "$CODE:$CODE"
    -v "$CACHE/cargo:/cargo"
    -v /var/run/docker.sock:/var/run/docker.sock
)
# What carries over from the host user, if present: Claude Code (binary,
# settings, sessions, memory), git and gh credentials, kubeconfig.
for p in .claude .claude.json .local/bin/claude .local/share/claude .ssh .gitconfig .config/gh .kube; do
    [ -e "$HOME/$p" ] && mounts+=(-v "$HOME/$p:/home/dev/$p")
done

up() {
    mkdir -p "$CACHE/cargo"
    # The toolchain the repo pins, so nothing is downloaded at first use.
    local rust
    rust=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$REPO/rust-toolchain.toml")
    docker build -q -t "$IMAGE" \
        --build-arg RUST_VERSION="${rust:-1.94}" \
        --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" --build-arg DOCKER_GID="$DOCKER_GID" \
        -f "$REPO/dev/Dockerfile" "$REPO/dev" >/dev/null
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --hostname objectio-dev \
        --network host --init \
        "${mounts[@]}" -w "$REPO" \
        "$IMAGE" sleep infinity >/dev/null
    echo "started $NAME ($IMAGE); dev/devbox.sh shell"
}

running() { [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = true ]; }

case "${1:-shell}" in
    up) up ;;
    shell) running || up; docker exec -it -w "$PWD" "$NAME" bash -l ;;
    claude) running || up; shift; docker exec -it -w "$REPO" "$NAME" /home/dev/.local/bin/claude "$@" ;;
    down) docker rm -f "$NAME" >/dev/null && echo "removed $NAME" ;;
    *) sed -n '2,13p' "$0"; exit 1 ;;
esac
