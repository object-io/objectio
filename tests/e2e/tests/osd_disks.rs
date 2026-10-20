//! An OSD's disks are known by their ids, not by their order (issue #74).
//!
//! A shard's location names its disk by index. The index was a disk's
//! place in the sorted list of paths the OSD was started with, so an OSD
//! started without one of its disks renumbered the rest: its shards were
//! looked for on the wrong disks, and the blocks they held there were handed
//! to new writes. Now the OSD records which disk is at each index, refuses
//! to start with one missing, and finds the rest at their indexes in
//! whatever order they are named.
//!
//! The OSD is run alone: what is checked happens before it registers, so
//! its meta endpoint answers nothing.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

struct Osd {
    dir: tempfile::TempDir,
}

impl Osd {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["d0", "d1", "d2"] {
            // Blank, as a new drive reads; named with --disks, so formatted.
            std::fs::File::create(dir.path().join(name))
                .and_then(|f| f.set_len(1 << 30))
                .expect("disk file");
        }
        Self { dir }
    }

    fn disk(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn log(&self) -> PathBuf {
        self.dir.path().join("osd.log")
    }

    fn spawn(&self, disks: &[&str]) -> Child {
        let _ = std::fs::remove_file(self.state().join("osd.addr"));
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log())
            .expect("log");
        let mut cmd = Command::new(objectio_e2e::binary("objectio-osd"));
        cmd.args([
            "--config",
            &self.dir.path().join("none.toml").display().to_string(),
            "--listen",
            "127.0.0.1:0",
            "--meta-endpoint",
            "http://127.0.0.1:1",
            "--data-dir",
            &self.state().display().to_string(),
            "--metrics-port",
            "0",
        ]);
        for d in disks {
            cmd.arg("--disks").arg(self.disk(d));
        }
        cmd.stdout(Stdio::from(log.try_clone().expect("log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn objectio-osd")
    }

    /// Start on `disks` and wait until the store is open and the OSD
    /// listens (it writes its address then); then stop it.
    fn start_and_stop(&self, disks: &[&str]) {
        let mut child = self.spawn(disks);
        let addr = self.state().join("osd.addr");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !addr.exists() {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the OSD exited with {status}:\n{}", self.log_text());
            }
            assert!(Instant::now() < deadline, "the OSD did not start in 60 s");
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Start on `disks`, expecting the OSD to exit by itself.
    fn start_refused(&self, disks: &[&str]) -> ExitStatus {
        let mut child = self.spawn(disks);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("the OSD kept running:\n{}", self.log_text());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(self.log()).unwrap_or_default()
    }
}

fn shown(p: &Path) -> String {
    p.display().to_string()
}

/// Restarted without one of its disks, the OSD doesn't start, and says
/// which disk is missing. Named in another order, all three, it starts.
#[test]
fn an_osd_without_one_of_its_disks_refuses_to_start() {
    let osd = Osd::new();
    osd.start_and_stop(&["d0", "d1", "d2"]);

    let status = osd.start_refused(&["d0", "d2"]);
    assert!(!status.success(), "exited {status}");
    let log = osd.log_text();
    assert!(
        log.contains("missing") && log.contains(&shown(&osd.disk("d1"))),
        "the refusal doesn't name the missing disk:\n{log}"
    );

    osd.start_and_stop(&["d2", "d0", "d1"]);

    // A disk file gone (a mount that failed) is a missing disk too: no new
    // file is made in its place to be taken for a replacement.
    std::fs::remove_file(osd.disk("d1")).expect("remove d1");
    let status = osd.start_refused(&["d0", "d1", "d2"]);
    assert!(!status.success(), "exited {status}");
    assert!(!osd.disk("d1").exists(), "a disk file was made for d1");
    assert!(
        osd.log_text().contains("does not exist"),
        "the refusal doesn't say the disk is gone:\n{}",
        osd.log_text()
    );
}

/// A disk named with --disks that can't be claimed (neither blank nor
/// formatted as a disk) stops the OSD; it isn't skipped.
#[test]
fn a_named_disk_that_cannot_be_claimed_stops_the_osd() {
    let osd = Osd::new();
    osd.start_and_stop(&["d0", "d1", "d2"]);
    // Something else written over d1's superblocks, both copies.
    std::fs::write(osd.disk("d1"), vec![0x5a; 64 * 1024]).expect("overwrite");
    std::fs::File::options()
        .write(true)
        .open(osd.disk("d1"))
        .and_then(|f| f.set_len(1 << 30))
        .expect("resize");

    let status = osd.start_refused(&["d0", "d1", "d2"]);
    assert!(!status.success(), "exited {status}");
    let log = osd.log_text();
    assert!(
        log.contains("cannot be claimed") && log.contains(&shown(&osd.disk("d1"))),
        "the refusal doesn't name the disk:\n{log}"
    );
}
