#!/bin/bash
# B4 single-host baseline: ObjectIO, RustFS and SeaweedFS on the same disk,
# driven by the same warp cells. Results (warp output per cell) land in
# $BENCH/results; see the developer guide's performance page.
#
#   BENCH=/data/bench scripts/bench/baseline.sh objectio rustfs seaweedfs
#
# Needs in $BENCH/bin: warp, objectio-aio (release, --features isal,io-uring),
# weed; and docker for RustFS. Ports 19000, 19010, 19020 (+ SeaweedFS's
# 19080, 19333, 19888) must be free.
set -u
B=${BENCH:?set BENCH to a directory on the disk under test}
W=$B/bin/warp; OUT=$B/results; mkdir -p "$OUT"
SIZES=${SIZES:-"4KiB 64KiB 1MiB 16MiB"}; CONC=${CONC:-32}; DUR=${DUR:-30s}
AK=benchkey; SK=benchsecret123

wait_up() { for _ in $(seq 120); do curl -s -o /dev/null --max-time 2 "$1" && return 0; sleep 1; done; echo "$1 never came up"; return 1; }

bench() { # name host
  local name=$1 host=$2
  for size in $SIZES; do
    for op in put get; do
      echo "== $name $op $size"
      "$W" $op --host "$host" --access-key $AK --secret-key $SK --obj.size "$size" \
        --concurrent "$CONC" --duration "$DUR" --bucket "b-$op-$(echo "$size" | tr A-Z a-z)" \
        --benchdata "$OUT/$name-$op-$size" > "$OUT/$name-$op-$size.txt" 2>&1
      grep -a "Average\|Reqs:\|Error" "$OUT/$name-$op-$size.txt" | head -3
    done
  done
}

# 4+2 over six OSDs in one process. 64 GiB sparse disks: the default
# 10 GiB fills during one 16 MiB PUT cell.
objectio() {
  rm -rf "$B/objectio"
  for i in 0 1 2 3 4 5; do
    mkdir -p "$B/objectio/osd-$i/disk0"
    truncate -s 64G "$B/objectio/osd-$i/disk0/disk.raw"
  done
  "$B/bin/objectio-aio" --data "$B/objectio" --osds 6 --ec-k 4 --ec-m 2 --port 19000 \
    --strict-port --log-level warn > "$B/objectio.log" 2>&1 & local pid=$!
  wait_up http://127.0.0.1:19000/ && sleep 5
  bench objectio 127.0.0.1:19000
  kill $pid; wait $pid 2>/dev/null; rm -rf "$B/objectio"
}

# EC:2 over six directories (4+2). They share one device here, which
# RustFS refuses unless told.
rustfs() {
  docker rm -f bench-rustfs >/dev/null 2>&1
  rm -rf "$B/rustfs"; mkdir -p "$B"/rustfs/d{0,1,2,3,4,5}
  docker run -d --name bench-rustfs --network host --user "$(id -u):$(id -g)" -v "$B/rustfs:/mnt" \
    -e RUSTFS_ADDRESS=:19010 -e RUSTFS_ACCESS_KEY=$AK -e RUSTFS_SECRET_KEY=$SK \
    -e RUSTFS_STORAGE_CLASS_STANDARD=EC:2 -e RUSTFS_UNSAFE_BYPASS_DISK_CHECK=true \
    rustfs/rustfs:latest server "/mnt/d{0...5}" > /dev/null
  wait_up http://127.0.0.1:19010/ && sleep 5
  bench rustfs 127.0.0.1:19010
  docker logs bench-rustfs > "$B/rustfs.log" 2>&1
  docker rm -f bench-rustfs >/dev/null; rm -rf "$B/rustfs"
}

# One server (master, volume, filer, S3) with its defaults: one copy, no
# fsync per write. Not durability-equivalent to the other two.
seaweedfs() {
  rm -rf "$B/weed"; mkdir -p "$B/weed"
  printf '{"identities":[{"name":"bench","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Admin","Read","Write","List","Tagging"]}]}\n' \
    $AK $SK > "$B/weed-s3.json"
  "$B/bin/weed" server -dir="$B/weed" -s3 -s3.port=19020 -s3.config="$B/weed-s3.json" \
    -master.port=19333 -volume.port=19080 -filer.port=19888 -volume.max=0 \
    -s3.port.iceberg=0 -s3.port.lance=0 > "$B/weed.log" 2>&1 & local pid=$!
  wait_up http://127.0.0.1:19020/ && sleep 10
  bench seaweedfs 127.0.0.1:19020
  kill $pid; wait $pid 2>/dev/null; rm -rf "$B/weed"
}

for s in "$@"; do $s; done
