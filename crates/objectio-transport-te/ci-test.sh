#!/usr/bin/env bash
# Everything that needs Transfer Engine, in TCP mode (no RDMA hardware).
# Runs inside test.Dockerfile's image; CI's `rdma` job calls it.
set -euo pipefail

cargo test -p objectio-transport-te --features te
cargo test -p objectio-osd --features rdma rdma
cargo test -p objectio-gateway --features rdma rdma::

# The whole path, end to end: aio built with rdma, run with --rdma tcp.
cargo build -p objectio-aio --features rdma
OBJECTIO_E2E_RDMA=tcp cargo test -p objectio-e2e --test rdma -- --test-threads=1
