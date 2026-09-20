use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
#[cfg(any(test, not(feature = "read-only-downloads")))]
use std::{os::unix::ffi::OsStrExt, path::Component};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub ctime: i64,
    pub ctime_ns: i64,
    pub links: u64,
}
#[cfg(any(test, not(feature = "read-only-downloads")))]
impl Identity {
    pub fn at(path: &Path) -> Result<Self, String> {
        let m = path.symlink_metadata().map_err(|_| "FILE_UNAVAILABLE")?;
        if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 {
            return Err("UNSAFE_FILE".into());
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
            links: m.nlink(),
        })
    }
    pub fn same_payload_metadata(&self, other: &Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.size == other.size
            && self.mtime == other.mtime
            && self.mtime_ns == other.mtime_ns
            && self.links == other.links
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub name: String,
    pub relative: String,
    pub bytes: u64,
    pub reason: String,
    pub protected: bool,
    pub selected: bool,
    pub identity: Identity,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scan {
    pub profile: String,
    pub compute_hash: bool,
    pub items: Vec<Item>,
    pub skipped: Vec<String>,
    pub content_reads: u64,
    pub hashes: u64,
    pub network_calls: u64,
    pub complete: bool,
    pub visited: usize,
}

#[cfg(any(test, not(feature = "read-only-downloads")))]
pub fn relative_file(value: &str) -> Result<&Path, String> {
    let p = Path::new(value);
    if p.components().count() != 1
        || !matches!(p.components().next(), Some(Component::Normal(_)))
        || value.starts_with('.')
    {
        return Err("SCOPE_ESCAPE".into());
    }
    Ok(p)
}

// Open directory descriptors only. Payloads are never opened. Descendants are
// resolved with openat(O_NOFOLLOW), so symlink replacement cannot redirect traversal.
fn open_dir(path: &Path) -> Result<File, String> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "SCOPE_UNAVAILABLE".into())
}
fn child_dir(parent: &File, name: &CStr) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err("DIRECTORY_UNAVAILABLE".into())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn names(dir: &File, limit: usize) -> Result<(Vec<Vec<u8>>, bool), String> {
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err("DIRECTORY_UNAVAILABLE".into());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let dp = unsafe { libc::fdopendir(owned.as_raw_fd()) };
    if dp.is_null() {
        return Err("DIRECTORY_UNAVAILABLE".into());
    }
    std::mem::forget(owned);
    let mut entries = Vec::new();
    let mut complete = true;
    loop {
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(dp) };
        if entry.is_null() {
            let error = unsafe { *libc::__error() };
            if error != 0 {
                unsafe {
                    libc::closedir(dp);
                }
                return Err("DIRECTORY_READ_FAILED".into());
            }
            break;
        }
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if raw != b"." && raw != b".." {
            if entries.len() == limit {
                complete = false;
                break;
            }
            entries.push(raw.to_vec());
        }
    }
    unsafe {
        libc::closedir(dp);
    }
    entries.sort();
    Ok((entries, complete))
}

#[cfg(any(test, not(feature = "read-only-downloads")))]
pub fn enumerate(root: &Path, scope_id: &str) -> Result<Scan, String> {
    enumerate_bounded(root, scope_id, 5000, false)
}
#[cfg(any(test, feature = "read-only-downloads"))]
pub fn enumerate_read_only(root: &Path, scope_id: &str) -> Result<Scan, String> {
    enumerate_bounded(root, scope_id, 50_000, true)
}
fn enumerate_bounded(
    root: &Path,
    scope_id: &str,
    limit: usize,
    partial: bool,
) -> Result<Scan, String> {
    let root_fd = open_dir(root)?;
    let root_dev = root_fd.metadata().map_err(|_| "SCOPE_UNAVAILABLE")?.dev();
    let mut scan = Scan {
        profile: "inventory_metadata".into(),
        complete: true,
        ..Default::default()
    };
    let mut stack = vec![(root_fd, String::new())];
    let keywords: Vec<String> =
        serde_json::from_str(include_str!("../rules/high-risk-keywords.json"))
            .map_err(|_| "RULES_INVALID")?;
    let started = std::time::Instant::now();
    while let Some((dir, prefix)) = stack.pop() {
        if scan.visited == limit || started.elapsed().as_secs() >= 30 {
            scan.complete = false;
            break;
        }
        let (entries, complete) = names(&dir, limit - scan.visited)?;
        scan.complete &= complete;
        for bytes in entries {
            scan.visited += 1;
            let Ok(name) = String::from_utf8(bytes.clone()) else {
                scan.skipped.push("UNSUPPORTED_NAME".into());
                continue;
            };
            let relative = format!("{prefix}{name}");
            let cname = CString::new(bytes).map_err(|_| "UNSUPPORTED_NAME")?;
            let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    cname.as_ptr(),
                    info.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                scan.skipped.push(format!("{relative}:UNAVAILABLE"));
                continue;
            }
            let m = unsafe { info.assume_init() };
            if name.starts_with('.') || m.st_flags & libc::UF_HIDDEN != 0 {
                scan.skipped.push(format!("{relative}:HIDDEN"));
                continue;
            }
            if m.st_dev as u64 != root_dev {
                scan.skipped.push(format!("{relative}:OTHER_VOLUME"));
                continue;
            }
            match m.st_mode & libc::S_IFMT {
                libc::S_IFLNK => {
                    scan.skipped.push(format!("{relative}:SYMLINK"));
                }
                libc::S_IFDIR => {
                    let ext = Path::new(&name)
                        .extension()
                        .and_then(OsStr::to_str)
                        .unwrap_or("")
                        .to_lowercase();
                    if ["app", "bundle", "framework", "photoslibrary", "pkg", "rtfd"]
                        .contains(&ext.as_str())
                    {
                        scan.skipped.push(format!("{relative}:PACKAGE"));
                        continue;
                    }
                    match child_dir(&dir, &cname) {
                        Ok(child) if child.metadata().is_ok_and(|m| m.dev() == root_dev) => {
                            stack.push((child, format!("{relative}/")))
                        }
                        Ok(_) => scan.skipped.push(format!("{relative}:OTHER_VOLUME")),
                        Err(_) => scan.skipped.push(format!("{relative}:UNAVAILABLE")),
                    }
                }
                libc::S_IFREG => {
                    if m.st_nlink != 1 {
                        scan.skipped.push(format!("{relative}:HARDLINK"));
                        continue;
                    }
                    let lower = relative.to_lowercase();
                    // MAC-001 executes only a single flat fixture item. Nested files are visible but protected.
                    let protected =
                        !prefix.is_empty() || keywords.iter().any(|word| lower.contains(word));
                    let identity = Identity {
                        dev: m.st_dev as u64,
                        ino: m.st_ino,
                        size: m.st_size as u64,
                        mtime: m.st_mtime,
                        mtime_ns: m.st_mtime_nsec,
                        ctime: m.st_ctime,
                        ctime_ns: m.st_ctime_nsec,
                        links: m.st_nlink as u64,
                    };
                    scan.items.push(Item {
                        id: format!("{scope_id}:{}", scan.items.len()),
                        name,
                        relative,
                        bytes: identity.size,
                        identity,
                        protected,
                        selected: false,
                        reason: if protected {
                            "含重要资料线索，请保留"
                        } else {
                            "临时样本，可用于验证可恢复处理；尚未判断是否值得清理"
                        }
                        .into(),
                    });
                }
                _ => scan.skipped.push(format!("{relative}:SPECIAL_FILE")),
            }
        }
    }
    if !scan.complete && !partial {
        return Err("FIXTURE_LIMIT".into());
    }
    scan.items.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(scan)
}

#[cfg(any(test, not(feature = "read-only-downloads")))]
pub fn restore_verified(
    source: &Path,
    destination: &Path,
    expected: &Identity,
    root_dev: u64,
    root_ino: u64,
) -> Result<(), String> {
    // Anchor the destination without requesting read access to the whole Trash
    // directory. The source is the exact URL returned by the native adapter.
    // Final identity checks narrow, but do not eliminate, hostile rename races.
    let destination_dir = open_dir(destination.parent().ok_or("INVALID_PATH")?)?;
    let root = destination_dir
        .metadata()
        .map_err(|_| "SCOPE_UNAVAILABLE")?;
    if root.dev() != root_dev || root.ino() != root_ino {
        return Err("SCOPE_DRIFT".into());
    }
    let src = CString::new(source.as_os_str().as_bytes()).map_err(|_| "INVALID_PATH")?;
    let dst = CString::new(destination.file_name().ok_or("INVALID_PATH")?.as_bytes())
        .map_err(|_| "INVALID_PATH")?;
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            libc::AT_FDCWD,
            src.as_ptr(),
            info.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err("FILE_UNAVAILABLE".into());
    }
    let m = unsafe { info.assume_init() };
    if m.st_mode & libc::S_IFMT != libc::S_IFREG
        || m.st_dev as u64 != expected.dev
        || m.st_ino != expected.ino
        || m.st_size as u64 != expected.size
        || m.st_mtime != expected.mtime
        || m.st_mtime_nsec != expected.mtime_ns
        || m.st_ctime != expected.ctime
        || m.st_ctime_nsec != expected.ctime_ns
        || m.st_nlink as u64 != expected.links
    {
        return Err("TRASH_FILE_DRIFT".into());
    }
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            src.as_ptr(),
            destination_dir.as_raw_fd(),
            dst.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        return match Identity::at(destination) {
            Ok(actual) if expected.same_payload_metadata(&actual) => Ok(()),
            _ => Err("RESTORE_OUTCOME_UNKNOWN".into()),
        };
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EEXIST) => Err("RESTORE_CONFLICT".into()),
        Some(libc::EXDEV) => Err("CROSS_VOLUME_UNSUPPORTED".into()),
        _ => Err("RESTORE_PERMISSION_DENIED".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("mac001-unit-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn bounded_scan_labels_partial_results_instead_of_reporting_complete_totals() {
        let f = Fixture::new();
        for i in 0..4 {
            std::fs::write(f.0.join(format!("file-{i}")), "fixture").unwrap();
        }
        let partial = enumerate_bounded(&f.0, "s", 2, true).unwrap();
        assert!(!partial.complete);
        assert_eq!(partial.visited, 2);
        assert_eq!(partial.items.len(), 2);
        assert_eq!(
            enumerate_bounded(&f.0, "s", 2, false).unwrap_err(),
            "FIXTURE_LIMIT"
        );
        let complete = enumerate_bounded(&f.0, "s", 4, true).unwrap();
        assert!(complete.complete);
        assert_eq!(complete.items.len(), 4);
    }
    #[test]
    fn rejects_path_traversal() {
        for path in ["/etc/passwd", "../x", "sub/x", ".hidden", ".", ""] {
            assert!(relative_file(path).is_err());
        }
        assert!(relative_file("sample.txt").is_ok());
    }
    #[test]
    fn scanner_skips_links_packages_and_hidden_payloads() {
        let f = Fixture::new();
        let root = f.0.join("scope");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("sample.txt"), "fixture").unwrap();
        std::fs::write(root.join("合同.txt"), "fixture").unwrap();
        std::fs::write(root.join(".hidden"), "fixture").unwrap();
        let outside = f.0.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), "fixture").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        std::fs::create_dir(root.join("A.app")).unwrap();
        std::fs::write(root.join("A.app/body"), "fixture").unwrap();
        let result = enumerate(&root, "session").unwrap();
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.skipped.len(), 3);
        assert!(
            result
                .items
                .iter()
                .find(|i| i.name == "合同.txt")
                .unwrap()
                .protected
        );
        assert!(result.items.iter().all(|i| !i.selected));
        assert_eq!(
            (result.content_reads, result.hashes, result.network_calls),
            (0, 0, 0)
        );
        symlink(&root, f.0.join("rootlink")).unwrap();
        assert!(enumerate(&f.0.join("rootlink"), "session").is_err());
    }
    #[test]
    fn restore_never_overwrites_even_with_dangling_symlink() {
        let f = Fixture::new();
        let src = f.0.join("trash");
        let dst = f.0.join("original");
        std::fs::write(&src, "fixture").unwrap();
        symlink(f.0.join("missing"), &dst).unwrap();
        assert_eq!(
            restore_verified(
                &src,
                &dst,
                &Identity::at(&src).unwrap(),
                f.0.metadata().unwrap().dev(),
                f.0.metadata().unwrap().ino()
            )
            .unwrap_err(),
            "RESTORE_CONFLICT"
        );
        assert!(src.exists());
        assert!(dst.is_symlink());
    }
    #[test]
    fn identity_detects_change_and_replacement() {
        let f = Fixture::new();
        let p = f.0.join("sample");
        std::fs::write(&p, "fixture").unwrap();
        let old = Identity::at(&p).unwrap();
        std::fs::write(&p, "changed length").unwrap();
        assert_ne!(old, Identity::at(&p).unwrap());
    }
    #[test]
    fn verified_restore_checks_drift_and_directory_identity_then_moves() {
        let f = Fixture::new();
        let src = f.0.join("trash");
        let dst = f.0.join("restored");
        std::fs::write(&src, "controlled fixture").unwrap();
        let identity = Identity::at(&src).unwrap();
        let root = f.0.metadata().unwrap();
        assert_eq!(
            restore_verified(&src, &dst, &identity, root.dev(), root.ino() + 1).unwrap_err(),
            "SCOPE_DRIFT"
        );
        let mut drift = identity.clone();
        drift.ctime_ns += 1;
        assert_eq!(
            restore_verified(&src, &dst, &drift, root.dev(), root.ino()).unwrap_err(),
            "TRASH_FILE_DRIFT"
        );
        assert!(src.exists());
        assert!(!dst.exists());
        restore_verified(&src, &dst, &identity, root.dev(), root.ino()).unwrap();
        assert!(!src.exists());
        assert_eq!(std::fs::read_to_string(dst).unwrap(), "controlled fixture");
    }
}
