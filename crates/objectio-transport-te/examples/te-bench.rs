//! Raw Transfer Engine throughput between two processes, in the shape the
//! shard path uses: a "gateway" serves registered shards, an "OSD" pulls them.
//! For measuring a fabric before and alongside ObjectIO's own numbers.
//!
//! ```text
//! te-bench serve <tcp|rdma> <host> <shards> <shard-bytes>
//!     registers shards of a known pattern, prints `SEGMENT <ip:port> ADDR <addr>`,
//!     then serves until killed.
//! te-bench pull <tcp|rdma> <host> <segment> <addr> <shards> <shard-bytes> <iterations>
//!     checks every byte once, then reports batched throughput (all shards at
//!     once) and single-shard latency.
//! ```
//!
//! `<host>` is this process's address on the storage network. Over RDMA, set
//! `MC_TE_FILTERS` to the NIC both sides share (on a rail-optimised fabric,
//! the same rail).

use std::time::{Duration, Instant};

use objectio_transport_te::{Engine, EngineConfig, Protocol, RemoteBuffer, SlotPool};

fn byte(shard: usize, i: usize) -> u8 {
    u8::try_from((shard * 7 + i) % 251).unwrap_or(0)
}

fn protocol(s: &str) -> Protocol {
    match s {
        "rdma" => Protocol::Rdma,
        "tcp" => Protocol::Tcp,
        other => panic!("protocol {other}: expected tcp or rdma"),
    }
}

fn arg<T: std::str::FromStr>(args: &[String], i: usize, what: &str) -> T {
    args.get(i)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("argument {i}: expected {what}"))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map_or("", String::as_str);
    let engine = Engine::start(&EngineConfig {
        protocol: protocol(args.get(2).map_or("", String::as_str)),
        host: arg(&args, 3, "host"),
    })
    .expect("start transfer engine");

    match mode {
        "serve" => {
            let (shards, size): (usize, usize) =
                (arg(&args, 4, "shards"), arg(&args, 5, "shard bytes"));
            let pool = SlotPool::new(shards * size, 1).expect("pool");
            let _registration = engine.register(&pool, true).expect("register");
            let mut slot = pool.acquire().expect("slot");
            for s in 0..shards {
                for i in 0..size {
                    slot.as_mut_slice()[s * size + i] = byte(s, i);
                }
            }
            println!("SEGMENT {} ADDR {}", engine.segment(), slot.addr());
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
        "pull" => {
            let segment: String = arg(&args, 4, "segment");
            let base: u64 = arg(&args, 5, "addr");
            let (shards, size, iterations): (usize, usize, usize) = (
                arg(&args, 6, "shards"),
                arg(&args, 7, "shard bytes"),
                arg(&args, 8, "iterations"),
            );
            let pool = SlotPool::new(size, shards).expect("pool");
            let _registration = engine.register(&pool, false).expect("register");
            let remote = |s: usize| RemoteBuffer {
                segment: segment.clone(),
                addr: base + (s * size) as u64,
                len: size as u64,
            };

            // Correctness first.
            let slots = futures::future::join_all(
                (0..shards).map(|s| engine.read(pool.acquire().expect("slot"), 0, remote(s))),
            )
            .await;
            let mut bad = 0usize;
            for (s, slot) in slots.into_iter().enumerate() {
                let slot = slot.expect("read");
                bad += (0..size)
                    .filter(|&i| slot.as_slice()[i] != byte(s, i))
                    .count();
            }
            println!("verify: {bad} bad bytes of {}", shards * size);

            let started = Instant::now();
            for _ in 0..iterations {
                futures::future::join_all(
                    (0..shards).map(|s| engine.read(pool.acquire().expect("slot"), 0, remote(s))),
                )
                .await
                .into_iter()
                .for_each(|r| drop(r.expect("read")));
            }
            let secs = started.elapsed().as_secs_f64();
            #[allow(clippy::cast_precision_loss)]
            let gbps = (iterations * shards * size) as f64 / secs / 1e9;
            println!(
                "batched: {iterations} x {shards} shards of {size} B: {gbps:.2} GB/s, {:.1} us per batch",
                secs / iterations as f64 * 1e6
            );

            let mut lat: Vec<f64> = Vec::with_capacity(iterations);
            for k in 0..iterations {
                let t = Instant::now();
                drop(
                    engine
                        .read(pool.acquire().expect("slot"), 0, remote(k % shards))
                        .await
                        .expect("read"),
                );
                lat.push(t.elapsed().as_secs_f64() * 1e6);
            }
            lat.sort_by(f64::total_cmp);
            println!(
                "single {size} B read: p50 {:.1} us, p99 {:.1} us",
                lat[lat.len() / 2],
                lat[lat.len() * 99 / 100]
            );
        }
        _ => panic!("usage: te-bench serve|pull ... (see the source)"),
    }
}
