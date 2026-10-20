//! Disk detection, checks and preparation.

use anyhow::{Result, bail};
use std::fs;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use tracing::info;

/// What is on a disk.
#[derive(Debug, PartialEq, Eq)]
pub enum DiskState {
    Missing,
    /// An ObjectIO superblock (either copy).
    ObjectIo {
        disk_id: String,
        block_size: u32,
    },
    /// Both superblock places all zeros: what the OSD formats.
    Blank,
    /// Anything else: data that isn't ObjectIO's, or a disk that can't be
    /// read.
    Other(String),
}

impl std::fmt::Display for DiskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "not found"),
            Self::ObjectIo {
                disk_id,
                block_size,
            } => write!(f, "ObjectIO disk (ID: {disk_id}, block size {block_size})"),
            Self::Blank => write!(f, "blank"),
            Self::Other(why) => write!(f, "not an ObjectIO disk ({why})"),
        }
    }
}

/// What is on the disk at `path`, read without changing anything.
pub fn state(path: &str) -> DiskState {
    if !Path::new(path).exists() {
        return DiskState::Missing;
    }
    if let Ok(sb) = objectio_storage::probe_superblock(path) {
        return DiskState::ObjectIo {
            disk_id: sb.disk_id.to_string(),
            block_size: sb.block_size,
        };
    }
    match objectio_storage::is_blank(path) {
        Ok(true) => DiskState::Blank,
        Ok(false) => DiskState::Other("holds data".into()),
        Err(e) => DiskState::Other(format!("cannot read: {e}")),
    }
}

/// Detect available disks that can be used for ObjectIO
pub fn detect_available_disks() -> Result<Vec<String>> {
    let mut available = Vec::new();
    for dev_path in list_all_disks()? {
        if is_disk_suitable(&dev_path) {
            available.push(dev_path);
        }
    }
    Ok(available)
}

/// List all block devices (including those in use)
pub fn list_all_disks() -> Result<Vec<String>> {
    let mut all = Vec::new();
    let sys_block = Path::new("/sys/block");
    if sys_block.exists() {
        for entry in fs::read_dir(sys_block)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            // Virtual devices: loop, RAM disks, device mapper, optical,
            // floppy.
            if ["loop", "ram", "dm-", "sr", "fd"]
                .iter()
                .any(|p| name.starts_with(p))
            {
                continue;
            }
            let dev_path = format!("/dev/{name}");
            if Path::new(&dev_path).exists() {
                all.push(dev_path);
            }
        }
    }
    Ok(all)
}

/// Whether `path` or a partition of it is mounted.
fn is_mounted(path: &str) -> bool {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    mounts
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|dev| dev.starts_with(path))
}

/// Whether a device is unmounted and so may be offered for ObjectIO.
fn is_disk_suitable(path: &str) -> bool {
    Path::new(path).exists() && !is_mounted(path)
}

/// Check the disks an OSD is to be given: each must be blank (the OSD
/// formats it when it first starts) or an ObjectIO disk already. Anything
/// else is refused: it may be someone's data.
pub fn check_for_osd(paths: &[String]) -> Result<()> {
    for path in paths {
        match state(path) {
            DiskState::Blank => info!("{path}: blank; the OSD formats it when it first starts"),
            s @ DiskState::ObjectIo { .. } => info!("{path}: {s}"),
            DiskState::Missing => bail!("disk {path} not found"),
            DiskState::Other(why) => bail!(
                "disk {path} is neither blank nor an ObjectIO disk ({why}): wipe it first if it \
                 is to hold ObjectIO's data, or `objectio-install disk prepare --force` it"
            ),
        }
        if is_mounted(path) {
            bail!("disk {path} is mounted");
        }
    }
    Ok(())
}

/// Format the disk at `path` for ObjectIO, with `block_size`, or the OSD's
/// default when `None`. Refuses a disk that isn't blank unless `force`:
/// formatting it destroys what it holds.
pub fn prepare_disk(path: &str, force: bool, block_size: Option<u32>) -> Result<String> {
    match state(path) {
        DiskState::Missing => bail!("disk {path} not found"),
        DiskState::Blank => {}
        s if !force => bail!("disk {path} is not blank: {s}. --force formats it, destroying that"),
        _ => {}
    }
    if is_mounted(path) {
        bail!("disk {path} is mounted: unmount it first");
    }

    // A block device's length is where its end is.
    let size = fs::File::open(path)?.seek(SeekFrom::End(0))?;
    let disk = objectio_storage::DiskManager::init(path, size, block_size)
        .map_err(|e| anyhow::anyhow!("formatting {path}: {e}"))?;
    let disk_id = disk.id().to_string();
    info!(
        "formatted {path}: ID {disk_id}, block size {}",
        disk.block_size()
    );
    Ok(disk_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(dir: &tempfile::TempDir, name: &str) -> String {
        let path = dir.path().join(name);
        fs::File::create(&path)
            .and_then(|f| f.set_len(2 << 30))
            .unwrap();
        path.display().to_string()
    }

    #[test]
    fn a_missing_disk_is_not_found() {
        assert_eq!(state("/nonexistent/path"), DiskState::Missing);
        assert!(check_for_osd(&["/nonexistent/path".into()]).is_err());
    }

    #[test]
    fn a_blank_disk_is_formatted_with_the_osds_block_size_and_then_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = disk(&dir, "d0");
        assert_eq!(state(&path), DiskState::Blank);
        check_for_osd(std::slice::from_ref(&path)).unwrap();

        let id = prepare_disk(&path, false, None).unwrap();
        assert_eq!(
            state(&path),
            DiskState::ObjectIo {
                disk_id: id.clone(),
                block_size: objectio_storage::DEFAULT_BLOCK_SIZE,
            }
        );
        check_for_osd(std::slice::from_ref(&path)).unwrap();
        // A second prepare would destroy it.
        let err = prepare_disk(&path, false, None).unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");
        assert_ne!(prepare_disk(&path, true, None).unwrap(), id);
    }

    #[test]
    fn a_disk_holding_other_data_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = disk(&dir, "d0");
        {
            use std::os::unix::fs::FileExt;
            let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all_at(b"\x53\xef ext4, say", 1080).unwrap();
        }
        assert!(matches!(state(&path), DiskState::Other(_)));
        assert!(check_for_osd(std::slice::from_ref(&path)).is_err());
        assert!(prepare_disk(&path, false, None).is_err());
        prepare_disk(&path, true, None).unwrap();
    }
}
