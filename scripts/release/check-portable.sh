#!/usr/bin/env bash
# Checks that Linux release binaries run on the distributions production
# hosts use, not only on the machine that built them.
#
#   scripts/release/check-portable.sh [--needed-only] BINARY...
#
# For each binary:
#   1. Every GLIBC_x.y symbol version it needs is at most $GLIBC_MAX
#      (default 2.28, the glibc of the AlmaLinux 8 image the release builds
#      in). A binary built against a newer glibc fails to start on an older
#      one with "version `GLIBC_2.39' not found".
#   2. It NEEDs only glibc's own libraries, libgcc_s and the dynamic loader:
#      libraries every Linux has. Anything else (libpcre2-8, libssl, libhs)
#      is a package the host may not have; link it statically instead.
#   3. `BINARY --version` runs, with every symbol
#      bound at startup (LD_BIND_NOW), in a container of each of $DISTROS.
#      Needs docker; the images are pulled for the host's architecture.
#
# --needed-only checks 2 alone: CI's builds are linked on the runner's
# glibc, not the release's. The release runs all three before publishing.

set -euo pipefail

GLIBC_MAX="${GLIBC_MAX:-2.28}"
DISTROS="${DISTROS:-ubuntu:22.04 debian:12 rockylinux:9 amazonlinux:2023}"
ALLOWED="libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1"
ALLOWED="$ALLOWED libgcc_s.so.1 ld-linux-x86-64.so.2 ld-linux-aarch64.so.1"

all=1
if [ "${1:-}" = "--needed-only" ]; then all=0; shift; fi
if [ "$#" -eq 0 ]; then
  echo "usage: $0 [--needed-only] BINARY..." >&2
  exit 2
fi

fail=0
err() { echo "::error::$*"; fail=1; }

for bin in "$@"; do
  name=$(basename "$bin")
  echo "=== $name"

  # NEEDED entries: the shared libraries the loader must find.
  needed=$(readelf -d -W "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
  echo "NEEDED: $(echo "$needed" | tr '\n' ' ')"
  for lib in $needed; do
    case " $ALLOWED " in
      *" $lib "*) ;;
      *) err "$name needs $lib, which a host may not have: link it statically" ;;
    esac
  done

  if [ "$all" -eq 0 ]; then continue; fi

  # The glibc symbol versions it requires (.gnu.version_r).
  versions=$(readelf -V -W "$bin" | grep -o 'Name: GLIBC_[A-Z0-9._]*' | sed 's/Name: GLIBC_//' | sort -u -V)
  if echo "$versions" | grep -qv '^[0-9.]*$'; then
    err "$name needs a private glibc symbol version: $(echo "$versions" | grep -v '^[0-9.]*$' | tr '\n' ' ')"
  fi
  max=$(echo "$versions" | grep '^[0-9.]*$' | tail -1 || true)
  echo "glibc required: ${max:-none} (allowed: ${GLIBC_MAX})"
  if [ -n "$max" ] && [ "$(printf '%s\n%s\n' "$max" "$GLIBC_MAX" | sort -V | tail -1)" != "$GLIBC_MAX" ]; then
    # Name the symbols that need more, which is where to look.
    over=$(readelf --dyn-syms -W "$bin" | grep -o '[A-Za-z0-9_]*@GLIBC_[0-9.]*' | sort -u \
           | while IFS=@ read -r sym ver; do
               v=${ver#GLIBC_}
               if [ "$(printf '%s\n%s\n' "$v" "$GLIBC_MAX" | sort -V | tail -1)" != "$GLIBC_MAX" ]; then
                 echo "$sym@$ver"
               fi
             done | tr '\n' ' ')
    err "$name needs glibc $max, above $GLIBC_MAX: $over"
  fi

  dir=$(cd "$(dirname "$bin")" && pwd)
  for image in $DISTROS; do
    if out=$(docker run --rm -e LD_BIND_NOW=1 -v "$dir:/check:ro" "$image" "/check/$name" --version 2>&1); then
      echo "$image: $out"
    else
      err "$name does not run on $image: $out"
    fi
  done
done

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "portable: ok"
