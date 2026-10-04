//! With meta unreachable, a request that needs it says "retry" (503); it
//! never reports an outcome it didn't reach. The B2 soak found a DELETE
//! answered 204, and the object still there, while meta elected a leader.

use std::time::Duration;

use objectio_e2e::ha::HaCluster;

#[test]
fn with_meta_down_a_delete_or_head_says_retry_not_done() {
    let ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/down", &[]).status, 200);
    assert_eq!(c.request("PUT", "/down/k", b"still here").status, 200);

    ha.kill_meta(0);
    let del = c.request("DELETE", "/down/k", &[]);
    assert_eq!(
        del.status,
        503,
        "a delete that reached nothing: {}",
        del.text()
    );
    let head = c.request("HEAD", "/down/k", &[]);
    assert_eq!(head.status, 503, "an object not known to be missing");

    ha.start_meta(0);
    let _ = ha.await_leader(Duration::from_secs(30));
    let mut got = c.request("GET", "/down/k", &[]);
    for _ in 0..50 {
        if got.status == 200 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
        got = c.request("GET", "/down/k", &[]);
    }
    assert_eq!(got.bytes, b"still here");
}
