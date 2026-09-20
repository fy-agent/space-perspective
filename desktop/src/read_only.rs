//! Separate compile-time entry point: no plan, receipt, Trash, or restore adapter.
use crate::{
    advice::{self, Advice},
    scope::{self, Identity, Scan},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

unsafe extern "C" {
    fn sp_pick(expected: *const libc::c_char) -> *mut libc::c_char;
    fn sp_close_scope();
}

struct Session {
    grant: Option<(String, u64, u64)>,
    scan: Option<Scan>,
    advice: Option<Advice>,
    decisions: BTreeMap<String, (Identity, String)>,
}
pub struct Desktop {
    root: PathBuf,
    data_dir: PathBuf,
    session: Mutex<Session>,
    _instance_lock: File,
}
fn registered_downloads(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() == 4
        && path
            .components()
            .skip(1)
            .all(|c| matches!(c, Component::Normal(_)))
        && path.parent().and_then(Path::parent) == Some(Path::new("/Users"))
        && path.file_name().is_some_and(|n| n == "Downloads")
}
fn summary(scan: &Scan) -> Value {
    let mut skipped = BTreeMap::<&str, usize>::new();
    for entry in &scan.skipped {
        *skipped
            .entry(entry.rsplit(':').next().unwrap_or(entry))
            .or_default() += 1;
    }
    let mut extensions = BTreeMap::<String, (usize, u64)>::new();
    for item in &scan.items {
        let ext = Path::new(&item.name)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("(none)")
            .to_lowercase();
        let group = extensions.entry(ext).or_default();
        group.0 += 1;
        group.1 += item.bytes;
    }
    json!({"profile":scan.profile,"complete":scan.complete,"visited":scan.visited,
        "files":scan.items.len(),"logical_bytes":scan.items.iter().map(|i|i.bytes).sum::<u64>(),
        "skipped":skipped,"extensions":extensions,"content_reads":scan.content_reads,
        "hashes":scan.hashes,"network_calls":scan.network_calls,"file_actions":0})
}
fn comparison(before: &Scan, after: &Scan) -> Value {
    let left: BTreeMap<_, _> = before
        .items
        .iter()
        .map(|i| (&i.relative, &i.identity))
        .collect();
    let right: BTreeMap<_, _> = after
        .items
        .iter()
        .map(|i| (&i.relative, &i.identity))
        .collect();
    json!({"before_files":left.len(),"after_files":right.len(),
        "unchanged":left.iter().filter(|(p,i)|right.get(*p)==Some(*i)).count(),
        "changed":left.iter().filter(|(p,i)|right.get(*p).is_some_and(|v|v!=*i)).count(),
        "missing":left.keys().filter(|p|!right.contains_key(*p)).count(),
        "added":right.keys().filter(|p|!left.contains_key(*p)).count(),
        "both_complete":before.complete && after.complete,
        "skipped_entries_equal":before.skipped==after.skipped,
        "content_integrity_verified":false,"file_actions":0})
}
impl Desktop {
    fn record(&self, name: &str, value: &Value) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.data_dir.join(name))
            .map_err(|_| "EVIDENCE_WRITE_FAILED")?;
        serde_json::to_writer_pretty(&mut file, value).map_err(|_| "EVIDENCE_WRITE_FAILED")?;
        file.write_all(b"\n")
            .and_then(|_| file.sync_all())
            .map_err(|_| "EVIDENCE_WRITE_FAILED".into())
    }
    pub fn open(resources: &Path, data_dir: PathBuf) -> Result<Self, String> {
        let config: Value = serde_json::from_slice(
            &fs::read(resources.join("read-only.json"))
                .map_err(|_| "READ_ONLY_REGISTRATION_REQUIRED")?,
        )
        .map_err(|_| "READ_ONLY_REGISTRATION_INVALID")?;
        let root = PathBuf::from(
            config["root"]
                .as_str()
                .ok_or("READ_ONLY_REGISTRATION_INVALID")?,
        );
        if !registered_downloads(&root) {
            return Err("READ_ONLY_REGISTRATION_INVALID".into());
        }
        fs::create_dir_all(&data_dir).map_err(|_| "EVIDENCE_WRITE_FAILED")?;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| "EVIDENCE_WRITE_FAILED")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(data_dir.join("session.lock"))
            .map_err(|_| "EVIDENCE_WRITE_FAILED")?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("ALREADY_RUNNING".into());
        }
        let app = Self {
            root,
            data_dir,
            session: Mutex::new(Session {
                grant: None,
                scan: None,
                advice: None,
                decisions: BTreeMap::new(),
            }),
            _instance_lock: lock,
        };
        app.record(
            "startup.json",
            &json!({"pid":std::process::id(),"read_only":true,
            "shell":"AppKit","scope_granted":false,"file_actions":0}),
        )?;
        Ok(app)
    }
    fn live(&self, s: &Session, id: Option<&str>) -> Result<(), String> {
        let (expected, dev, ino) = s.grant.as_ref().ok_or("SCOPE_REQUIRED")?;
        if id.is_some_and(|id| id != expected) {
            return Err("SCOPE_EXPIRED".into());
        }
        let m = self
            .root
            .symlink_metadata()
            .map_err(|_| "SCOPE_UNAVAILABLE")?;
        if !m.is_dir() || m.file_type().is_symlink() || m.dev() != *dev || m.ino() != *ino {
            return Err("SCOPE_DRIFT".into());
        }
        Ok(())
    }
    fn close(&self) -> Result<Value, String> {
        let mut s = self.session.lock().map_err(|_| "SESSION_FAILED")?;
        let had_grant = s.grant.is_some();
        let verification = if s.grant.is_some() && s.scan.is_some() {
            self.live(&s, None)
                .and_then(|_| scope::enumerate_read_only(&self.root, "after"))
                .and_then(|after| {
                    self.live(&s, None)?;
                    Ok(comparison(s.scan.as_ref().unwrap(), &after))
                })
        } else {
            Ok(json!(null))
        };
        s.grant = None;
        unsafe {
            sp_close_scope();
        }
        let result = json!({"scope_revoked":true,"verification":verification,"file_actions":0});
        if had_grant || !self.data_dir.join("close.json").exists() {
            self.record("close.json", &result)?;
        }
        Ok(result)
    }
    pub fn dispatch(&self, command: &str, args: &Value) -> Result<Value, String> {
        // Allowlist is independent of the UI. File-action commands have no implementation.
        let result = match command {
            "status" => {
                let s = self.session.lock().map_err(|_| "SESSION_FAILED")?;
                Ok(
                    json!({"read_only":true,"fixture_only":false,"scope_id":s.grant.as_ref().map(|g|&g.0),
                    "scan":s.scan,"advice":s.advice,"receipts":[],"plan":null,"unresolved":false,"file_actions":0}),
                )
            }
            "choose" => {
                self.close()?;
                {
                    let mut s = self.session.lock().map_err(|_| "SESSION_FAILED")?;
                    s.scan = None;
                    s.advice = None;
                    s.decisions.clear();
                }
                let expected = CString::new(self.root.to_string_lossy().as_bytes())
                    .map_err(|_| "INVALID_PATH")?;
                let ptr = unsafe { sp_pick(expected.as_ptr()) };
                let picked = (|| {
                    if ptr.is_null() {
                        return Err("NATIVE_FAILED".to_string());
                    }
                    let raw = unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec();
                    unsafe {
                        libc::free(ptr.cast());
                    }
                    let v: Value = serde_json::from_slice(&raw).map_err(|_| "NATIVE_FAILED")?;
                    if let Some(error) = v["error"].as_str() {
                        return Err(error.into());
                    }
                    if v["path"].as_str() != self.root.to_str()
                        || v["bookmark_resolved"] != true
                        || v["started_access"] != true
                    {
                        return Err("BOOKMARK_INVALID".into());
                    }
                    let m = self
                        .root
                        .symlink_metadata()
                        .map_err(|_| "SCOPE_UNAVAILABLE")?;
                    if !m.is_dir() || m.file_type().is_symlink() {
                        return Err("UNSAFE_SCOPE".into());
                    }
                    self.session.lock().map_err(|_| "SESSION_FAILED")?.grant =
                        Some((uuid::Uuid::new_v4().to_string(), m.dev(), m.ino()));
                    Ok(json!({"scope_granted":true,"read_only":true,"bookmark_resolved":true}))
                })();
                if picked.is_err() {
                    unsafe {
                        sp_close_scope();
                    }
                }
                picked
            }
            "scan" => {
                let mut s = self.session.lock().map_err(|_| "SESSION_FAILED")?;
                self.live(
                    &s,
                    Some(args["scope_id"].as_str().ok_or("INVALID_ARGUMENT")?),
                )?;
                let started = Instant::now();
                let mut scan =
                    scope::enumerate_read_only(&self.root, &s.grant.as_ref().unwrap().0)?;
                self.live(&s, None)?;
                for item in &mut scan.items {
                    item.protected = true;
                    item.reason = "仅供查看；未判断是否可以清理".into();
                }
                scan.items
                    .sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.relative.cmp(&b.relative)));
                let mut result = summary(&scan);
                result["elapsed_ms"] = json!(started.elapsed().as_millis());
                self.record("scan-summary.json", &result)?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "CLOCK_INVALID")?
                    .as_secs() as i64;
                let mut report = advice::analyze(&scan, now);
                let identities = scan
                    .items
                    .iter()
                    .map(|i| (i.id.as_str(), &i.identity))
                    .collect::<BTreeMap<_, _>>();
                for item in &mut report.items {
                    let identity = *identities.get(item.id.as_str()).ok_or("ITEM_NOT_FOUND")?;
                    if let Some((previous, decision)) = s.decisions.get(&item.relative) {
                        if previous == identity
                            && (decision != "consider" || item.can_consider_cleanup)
                        {
                            item.decision = decision.clone();
                        }
                    }
                }
                self.record("advice-summary.json",&json!({"rules_version":report.rules_version,"groups":report.groups,
                    "categories":report.categories,"file_actions":0,"content_reads":0,"hashes":0,"network_calls":0}))?;
                s.advice = Some(report);
                s.scan = Some(scan);
                Ok(result)
            }
            "decide" => {
                let mut s = self.session.lock().map_err(|_| "SESSION_FAILED")?;
                let id = args["item_id"].as_str().ok_or("INVALID_ARGUMENT")?;
                let decision = args["decision"].as_str().ok_or("INVALID_ARGUMENT")?;
                if !["none", "keep", "consider"].contains(&decision) {
                    return Err("INVALID_ARGUMENT".into());
                }
                let report = s.advice.as_ref().ok_or("SCAN_REQUIRED")?;
                let index = report
                    .items
                    .iter()
                    .position(|i| i.id == id)
                    .ok_or("ITEM_NOT_FOUND")?;
                let item = &report.items[index];
                if decision == "consider" {
                    if !item.can_consider_cleanup {
                        return Err("ADVICE_PROTECTED".into());
                    }
                    if report.items.iter().any(|other| {
                        other.decision == "consider"
                            && (item.related_id.as_deref() == Some(other.id.as_str())
                                || other.related_id.as_deref() == Some(id))
                    }) {
                        return Err("KEEP_REFERENCE".into());
                    }
                }
                let path = item.relative.clone();
                let identity = s
                    .scan
                    .as_ref()
                    .ok_or("SCAN_REQUIRED")?
                    .items
                    .iter()
                    .find(|i| i.id == id)
                    .ok_or("ITEM_NOT_FOUND")?
                    .identity
                    .clone();
                s.decisions.insert(path, (identity, decision.into()));
                s.advice.as_mut().unwrap().items[index].decision = decision.into();
                self.record("decisions-summary.json",&json!({"consider":s.advice.as_ref().unwrap().items.iter().filter(|i|i.decision=="consider").count(),
                    "keep":s.advice.as_ref().unwrap().items.iter().filter(|i|i.decision=="keep").count(),"file_actions":0}))?;
                Ok(json!({"decision":decision,"file_actions":0}))
            }
            "review" => {
                let s = self.session.lock().map_err(|_| "SESSION_FAILED")?;
                let report = s.advice.as_ref().ok_or("SCAN_REQUIRED")?;
                let chosen = report
                    .items
                    .iter()
                    .filter(|i| i.decision == "consider")
                    .collect::<Vec<_>>();
                Ok(
                    json!({"items":chosen,"count":chosen.len(),"bytes":chosen.iter().map(|i|i.bytes).sum::<u64>(),
                    "execute_available":false,"file_actions":0}),
                )
            }
            "close" => self.close(),
            "quit" => {
                let result = self.close()?;
                self.record(
                    "exit.json",
                    &json!({"pid":std::process::id(),"scope_revoked":true,"file_actions":0}),
                )?;
                Ok(result)
            }
            _ => Err("READ_ONLY_MODE".into()),
        };
        if command != "status" {
            // Do not persist filenames, selected paths, arguments, or full scan results.
            let mut log = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(self.data_dir.join("events.jsonl"))
                .map_err(|_| "EVIDENCE_WRITE_FAILED")?;
            writeln!(log,"{}",json!({"command":command,"ok":result.is_ok(),"error":result.as_ref().err(),"file_actions":0}))
                .map_err(|_|"EVIDENCE_WRITE_FAILED")?;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_rejects_broader_or_relative_scopes() {
        assert!(registered_downloads(Path::new("/Users/test/Downloads")));
        for p in [
            "/Users/test",
            "/Users/test/Documents",
            "Downloads",
            "/Users/test/Downloads/sub",
            "/Users/test/../Downloads",
        ] {
            assert!(!registered_downloads(Path::new(p)), "{p}");
        }
    }
    #[test]
    fn action_commands_have_no_backend_even_with_plausible_arguments() {
        let dir = std::env::temp_dir().join(format!("mac001-readonly-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let app = Desktop {
            root: PathBuf::from("/Users/test/Downloads"),
            data_dir: dir.clone(),
            session: Mutex::new(Session {
                grant: None,
                scan: None,
                advice: None,
                decisions: BTreeMap::new(),
            }),
            _instance_lock: File::open(&dir).unwrap(),
        };
        for command in [
            "preview", "confirm", "undo", "trash", "delete", "restore", "cancel",
        ] {
            assert_eq!(
                app.dispatch(
                    command,
                    &json!({"confirm":true,"version":1,"plan_id":"p","receipt_id":"r"})
                )
                .unwrap_err(),
                "READ_ONLY_MODE"
            );
        }
        assert_eq!(
            app.dispatch("scan", &json!({"scope_id":"fake"}))
                .unwrap_err(),
            "SCOPE_REQUIRED"
        );
        assert_eq!(
            app.dispatch("status", &json!({})).unwrap()["file_actions"],
            0
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn comparison_detects_metadata_changes_additions_and_missing_files() {
        let dir = std::env::temp_dir().join(format!("mac001-readonly-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("same"), "one").unwrap();
        fs::write(dir.join("changed"), "one").unwrap();
        fs::write(dir.join("missing"), "one").unwrap();
        let before = scope::enumerate_read_only(&dir, "before").unwrap();
        fs::write(dir.join("changed"), "different length").unwrap();
        fs::rename(dir.join("missing"), dir.join("added")).unwrap();
        let after = scope::enumerate_read_only(&dir, "after").unwrap();
        let result = comparison(&before, &after);
        for key in ["unchanged", "changed", "missing", "added"] {
            assert_eq!(result[key], 1, "{key}");
        }
        assert_eq!(result["content_integrity_verified"], false);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn decisions_and_preview_never_touch_files_and_protected_items_cannot_enter_preview() {
        let dir = std::env::temp_dir().join(format!("mac001-advice-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        for name in ["Tool.dmg", "Tool (1).dmg", "合同.pdf"] {
            fs::write(dir.join(name), "fixture").unwrap();
        }
        let scan = scope::enumerate_read_only(&dir, "s").unwrap();
        let report = advice::analyze(&scan, i64::MAX / 2);
        let duplicate = report
            .items
            .iter()
            .find(|i| i.name == "Tool (1).dmg")
            .unwrap()
            .id
            .clone();
        let protected = report
            .items
            .iter()
            .find(|i| i.name == "合同.pdf")
            .unwrap()
            .id
            .clone();
        let data = dir.join("app-data");
        fs::create_dir(&data).unwrap();
        let app = Desktop {
            root: dir.clone(),
            data_dir: data,
            _instance_lock: File::open(&dir).unwrap(),
            session: Mutex::new(Session {
                grant: None,
                scan: Some(scan.clone()),
                advice: Some(report),
                decisions: BTreeMap::new(),
            }),
        };
        assert_eq!(app.dispatch("review", &json!({})).unwrap()["count"], 0);
        assert_eq!(
            app.dispatch(
                "decide",
                &json!({"item_id":protected,"decision":"consider"})
            )
            .unwrap_err(),
            "ADVICE_PROTECTED"
        );
        app.dispatch(
            "decide",
            &json!({"item_id":duplicate,"decision":"consider"}),
        )
        .unwrap();
        let review = app.dispatch("review", &json!({})).unwrap();
        assert_eq!(review["count"], 1);
        assert_eq!(review["execute_available"], false);
        assert_eq!(
            app.dispatch("confirm", &json!({"confirm":true}))
                .unwrap_err(),
            "READ_ONLY_MODE"
        );
        app.dispatch("decide", &json!({"item_id":duplicate,"decision":"keep"}))
            .unwrap();
        assert_eq!(app.dispatch("review", &json!({})).unwrap()["count"], 0);
        for item in &scan.items {
            assert_eq!(
                Identity::at(&dir.join(&item.relative)).unwrap(),
                item.identity
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
