//! Standard `process_*` metrics and `objectio_build_info`, hand-rendered in
//! the Prometheus text format like the rest of ObjectIO's metrics.
//!
//! Every service calls [`render`]. In the all-in-one binary they share one
//! process, so each exposition also carries [`instance_id`]: the gateway,
//! which merges the others into its own `/metrics`, drops process metrics
//! that came from its own process rather than repeating them per OSD.

use std::fmt::Write;
use std::sync::OnceLock;

/// Release version baked in at build time (`OBJECTIO_VERSION`), falling
/// back to the crate version. The crate version is the same for every
/// build, so a release sets the tag here.
pub const VERSION: &str = match option_env!("OBJECTIO_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

/// Git commit baked in at build time (`OBJECTIO_GIT_COMMIT`).
pub const COMMIT: &str = match option_env!("OBJECTIO_GIT_COMMIT") {
    Some(c) if !c.is_empty() => c,
    _ => "unknown",
};

/// Random per-process identifier, stable for the life of the process.
pub fn instance_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// Render build info and process stats. `labels` (e.g. `osd_id="…"`) is
/// added to every sample; pass `""` for none.
#[must_use]
pub fn render(labels: &str) -> String {
    let mut out = String::with_capacity(1024);
    let sep = if labels.is_empty() { "" } else { "," };

    family(
        &mut out,
        "objectio_build_info",
        "gauge",
        "Build version and commit; always 1",
    );
    writeln!(
        out,
        "objectio_build_info{{version=\"{VERSION}\",commit=\"{COMMIT}\"{sep}{labels}}} 1"
    )
    .unwrap();

    let braces = |l: &str| {
        if l.is_empty() {
            String::new()
        } else {
            format!("{{{l}}}")
        }
    };
    let l = braces(labels);
    let stats = sample();
    for (name, kind, help, value) in [
        (
            "process_cpu_seconds_total",
            "counter",
            "User and system CPU time",
            stats.cpu_seconds,
        ),
        (
            "process_resident_memory_bytes",
            "gauge",
            "Resident memory",
            stats.resident_bytes,
        ),
        (
            "process_open_fds",
            "gauge",
            "Open file descriptors",
            stats.open_fds,
        ),
        (
            "process_max_fds",
            "gauge",
            "File descriptor limit",
            stats.max_fds,
        ),
        (
            "process_start_time_seconds",
            "gauge",
            "Process start, seconds since the epoch",
            stats.start_time,
        ),
    ] {
        // Leave out what this platform cannot measure rather than report 0.
        let Some(v) = value else { continue };
        family(&mut out, name, kind, help);
        writeln!(out, "{name}{l} {v}").unwrap();
    }
    out
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} {kind}").unwrap();
}

#[derive(Default)]
struct Stats {
    cpu_seconds: Option<f64>,
    resident_bytes: Option<f64>,
    open_fds: Option<f64>,
    max_fds: Option<f64>,
    start_time: Option<f64>,
}

#[allow(clippy::cast_precision_loss)]
fn sample() -> Stats {
    let mut s = Stats {
        cpu_seconds: cpu_seconds(),
        max_fds: max_fds(),
        start_time: Some(start_time()),
        ..Default::default()
    };
    #[cfg(target_os = "linux")]
    {
        s.resident_bytes = linux::resident_bytes();
        s.open_fds = std::fs::read_dir("/proc/self/fd")
            .ok()
            .map(|d| d.count() as f64);
    }
    #[cfg(target_os = "macos")]
    {
        s.open_fds = std::fs::read_dir("/dev/fd").ok().map(|d| d.count() as f64);
    }
    s
}

#[allow(unsafe_code, clippy::cast_precision_loss)]
fn cpu_seconds() -> Option<f64> {
    // SAFETY: getrusage fills the zeroed struct we pass and reads nothing else.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut ru) } != 0 {
        return None;
    }
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    Some(tv(ru.ru_utime) + tv(ru.ru_stime))
}

#[allow(unsafe_code, clippy::cast_precision_loss)]
fn max_fds() -> Option<f64> {
    // SAFETY: getrlimit fills the zeroed struct we pass and reads nothing else.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) } != 0 {
        return None;
    }
    if rl.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    Some(rl.rlim_cur as f64)
}

/// When the process started. Linux reads it from `/proc`; elsewhere it is
/// the first time metrics were rendered, which is within seconds of start.
fn start_time() -> f64 {
    static START: OnceLock<f64> = OnceLock::new();
    *START.get_or_init(|| {
        #[cfg(target_os = "linux")]
        if let Some(t) = linux::start_time() {
            return t;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    })
}

#[cfg(target_os = "linux")]
mod linux {
    #[allow(unsafe_code, clippy::cast_precision_loss, clippy::cast_sign_loss)]
    fn sysconf(name: libc::c_int) -> Option<f64> {
        // SAFETY: sysconf takes a constant and has no memory effects.
        let v = unsafe { libc::sysconf(name) };
        (v > 0).then_some(v as f64)
    }

    pub fn resident_bytes() -> Option<f64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: f64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * sysconf(libc::_SC_PAGESIZE)?)
    }

    pub fn start_time() -> Option<f64> {
        // Field 22 of /proc/self/stat is start time in clock ticks since
        // boot; the command name (field 2) may contain spaces, so count
        // from the closing parenthesis.
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let after = &stat[stat.rfind(')')? + 2..];
        let ticks: f64 = after.split_whitespace().nth(19)?.parse().ok()?;
        let btime: f64 = std::fs::read_to_string("/proc/stat")
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()?;
        Some(btime + ticks / sysconf(libc::_SC_CLK_TCK)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_build_info_and_cpu() {
        let out = render("osd_id=\"a\"");
        assert!(out.contains("objectio_build_info{version=\""), "{out}");
        assert!(out.contains(",osd_id=\"a\"} 1"), "{out}");
        assert!(
            out.contains("process_cpu_seconds_total{osd_id=\"a\"} "),
            "{out}"
        );
        assert!(
            out.contains("process_start_time_seconds{osd_id=\"a\"} "),
            "{out}"
        );
    }

    #[test]
    fn no_labels_renders_bare_names() {
        let out = render("");
        assert!(out.contains("process_cpu_seconds_total "), "{out}");
        assert!(out.contains("objectio_build_info{version=\""), "{out}");
    }
}
