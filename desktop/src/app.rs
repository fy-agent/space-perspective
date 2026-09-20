use crate::scope::{self, Identity, Item, Scan};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::Write,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

unsafe extern "C" {
    fn sp_pick(expected: *const libc::c_char) -> *mut libc::c_char;
    fn sp_close_scope();
    fn sp_trash(
        path: *const libc::c_char,
        dev: u64,
        ino: u64,
        size: u64,
        mtime: i64,
        mtime_nsec: i64,
        ctime: i64,
        ctime_nsec: i64,
    ) -> *mut libc::c_char;
}
fn native_json(ptr: *mut libc::c_char) -> Result<Value, String> {
    if ptr.is_null() {
        return Err("NATIVE_FAILED".into());
    }
    let text = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe {
        libc::free(ptr.cast());
    }
    serde_json::from_str(&text).map_err(|_| "NATIVE_FAILED".into())
}
fn nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[derive(Clone, Deserialize)]
struct FixtureConfig {
    fixture_root: PathBuf,
    outside_root: PathBuf,
    expected_files: usize,
}
#[derive(Clone)]
struct Grant {
    id: String,
    root: PathBuf,
    dev: u64,
    ino: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Plan {
    id: String,
    version: u32,
    scope_id: String,
    item: Item,
    action: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Receipt {
    id: String,
    plan: Plan,
    fixture_root: PathBuf,
    root_dev: u64,
    root_ino: u64,
    status: String,
    trash_path: Option<PathBuf>,
    #[serde(default)]
    trash_identity: Option<Identity>,
    error: Option<String>,
    restore_status: String,
    evidence_level: String,
}
struct Session {
    grant: Option<Grant>,
    scan: Option<Scan>,
    plan: Option<Plan>,
    receipts: BTreeMap<String, Receipt>,
}
pub struct Desktop {
    fixture: FixtureConfig,
    session: Mutex<Session>,
    data_dir: PathBuf,
    _instance_lock: File,
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let tmp = path.with_extension(format!("{}.tmp", nonce()));
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "RECEIPT_SERIALIZE_FAILED")?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|_| "RECEIPT_WRITE_FAILED")?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| "RECEIPT_WRITE_FAILED")?;
    fs::rename(&tmp, path).map_err(|_| "RECEIPT_WRITE_FAILED")?;
    File::open(path.parent().ok_or("RECEIPT_WRITE_FAILED")?)
        .and_then(|d| d.sync_all())
        .map_err(|_| "RECEIPT_WRITE_FAILED".into())
}
fn live_grant(session: &Session, id: &str) -> Result<Grant, String> {
    let grant = session.grant.as_ref().ok_or("SCOPE_REQUIRED")?;
    if id != grant.id {
        return Err("SCOPE_EXPIRED".into());
    }
    let m = grant
        .root
        .symlink_metadata()
        .map_err(|_| "SCOPE_UNAVAILABLE")?;
    if !m.is_dir() || m.file_type().is_symlink() || m.dev() != grant.dev || m.ino() != grant.ino {
        return Err("SCOPE_DRIFT".into());
    }
    Ok(grant.clone())
}

pub fn desktop_status(state: &Desktop) -> Result<Value, String> {
    let s = state.session.lock().map_err(|_| "SESSION_FAILED")?;
    Ok(
        json!({"fixture_only":true,"expected_files":state.fixture.expected_files,
        "receipts":s.receipts.values().collect::<Vec<_>>(),"scope_id":s.grant.as_ref().map(|g| &g.id),
        "scan":s.scan,"plan":s.plan,"scan_profile":"inventory_metadata","compute_hash":false,
        "unresolved":has_unresolved(&s)}),
    )
}

fn choose_fixture(state: &Desktop) -> Result<Value, String> {
    let result = choose_fixture_inner(state);
    if result.is_err() {
        close_scope(state)?;
    }
    result
}

fn choose_fixture_inner(state: &Desktop) -> Result<Value, String> {
    close_scope(state)?;
    let expected = CString::new(state.fixture.fixture_root.to_string_lossy().as_bytes())
        .map_err(|_| "INVALID_PATH")?;
    let result = native_json(unsafe { sp_pick(expected.as_ptr()) })?;
    write_json(&state.data_dir.join("picker-attempt.json"), &result)?;
    if let Some(error) = result["error"].as_str() {
        return Err(error.into());
    }
    if result["path"].as_str() != state.fixture.fixture_root.to_str()
        || result["bookmark_resolved"] != true
        || result["started_access"] != true
    {
        unsafe {
            sp_close_scope();
        }
        return Err("BOOKMARK_INVALID".into());
    }
    let root = state.fixture.fixture_root.clone();
    let m = root.symlink_metadata().map_err(|_| "SCOPE_UNAVAILABLE")?;
    if !m.is_dir() || m.file_type().is_symlink() {
        unsafe {
            sp_close_scope();
        }
        return Err("UNSAFE_SCOPE".into());
    }
    let id = nonce();
    state.session.lock().map_err(|_| "SESSION_FAILED")?.grant = Some(Grant {
        id: id.clone(),
        root,
        dev: m.dev(),
        ino: m.ino(),
    });
    let result = json!({"scope_id":id,"bookmark_created":true,"bookmark_resolved":true,
        "selected":directory_probe(&state.fixture.fixture_root),"outside":directory_probe(&state.fixture.outside_root)});
    write_json(&state.data_dir.join("picker.json"), &result)?;
    Ok(result)
}

fn scan_fixture(scope_id: String, state: &Desktop) -> Result<Scan, String> {
    let mut s = state.session.lock().map_err(|_| "SESSION_FAILED")?;
    let grant = live_grant(&s, &scope_id)?;
    let scan = scope::enumerate(&grant.root, &grant.id)?;
    live_grant(&s, &scope_id)?;
    write_json(&state.data_dir.join("scan.json"), &scan)?;
    s.scan = Some(scan.clone());
    s.plan = None;
    Ok(scan)
}

fn preview_item(scope_id: String, item_id: String, state: &Desktop) -> Result<Plan, String> {
    let mut s = state.session.lock().map_err(|_| "SESSION_FAILED")?;
    if has_unresolved(&s) {
        return Err("RECONCILIATION_REQUIRED".into());
    }
    let grant = live_grant(&s, &scope_id)?;
    s.plan = None;
    let item = s
        .scan
        .as_ref()
        .ok_or("SCAN_REQUIRED")?
        .items
        .iter()
        .find(|i| i.id == item_id)
        .ok_or("ITEM_NOT_FOUND")?
        .clone();
    if item.protected {
        return Err("PROTECTED_ITEM".into());
    }
    let path = grant.root.join(scope::relative_file(&item.relative)?);
    if Identity::at(&path)? != item.identity {
        return Err("FILE_DRIFT".into());
    }
    let plan = Plan {
        id: nonce(),
        version: 1,
        scope_id,
        item,
        action: "system_trash".into(),
    };
    s.plan = Some(plan.clone());
    Ok(plan)
}

fn validate_confirmation(plan: &Plan, id: &str, version: u32, confirm: bool) -> Result<(), String> {
    if !confirm {
        return Err("CONFIRM_REQUIRED".into());
    }
    if plan.id != id || plan.version != version {
        return Err("PLAN_VERSION_MISMATCH".into());
    }
    Ok(())
}

fn confirm_plan(
    plan_id: String,
    version: u32,
    confirm: bool,
    state: &Desktop,
) -> Result<Receipt, String> {
    let mut s = state.session.lock().map_err(|_| "SESSION_FAILED")?;
    if has_unresolved(&s) {
        return Err("RECONCILIATION_REQUIRED".into());
    }
    let plan = s.plan.as_ref().ok_or("PREVIEW_REQUIRED")?.clone();
    validate_confirmation(&plan, &plan_id, version, confirm)?;
    let grant = live_grant(&s, &plan.scope_id)?;
    let source = grant.root.join(scope::relative_file(&plan.item.relative)?);
    if Identity::at(&source)? != plan.item.identity {
        s.plan = None;
        return Err("FILE_DRIFT".into());
    }
    let mut receipt = Receipt {
        id: nonce(),
        plan: plan.clone(),
        fixture_root: grant.root.clone(),
        root_dev: grant.dev,
        root_ino: grant.ino,
        status: "prepared".into(),
        trash_path: None,
        trash_identity: None,
        error: None,
        restore_status: "not_attempted".into(),
        evidence_level: "local_runtime_fixture".into(),
    };
    let receipt_file = state.data_dir.join(format!("receipt-{}.json", receipt.id));
    // Persist intent before touching the source. A crash leaves explicit unresolved intent.
    write_json(&receipt_file, &receipt)?;
    s.plan = None;
    s.scan = None;
    let p = CString::new(source.to_string_lossy().as_bytes()).map_err(|_| "INVALID_PATH")?;
    let i = &plan.item.identity;
    let result = native_json(unsafe {
        sp_trash(
            p.as_ptr(),
            i.dev,
            i.ino,
            i.size,
            i.mtime,
            i.mtime_ns,
            i.ctime,
            i.ctime_ns,
        )
    });
    match result {
        Ok(value) if value["status"] == "trashed" => {
            receipt.trash_path = value["trash_path"]
                .as_str()
                .filter(|p| !p.is_empty())
                .map(PathBuf::from);
            receipt.status = "trashed".into();
            if receipt.trash_path.is_none() {
                receipt.error = Some("TRASH_LOCATION_UNAVAILABLE".into());
            } else if let Some(path) = &receipt.trash_path {
                match Identity::at(path) {
                    Ok(identity) if i.same_payload_metadata(&identity) => {
                        receipt.trash_identity = Some(identity)
                    }
                    _ => receipt.error = Some("TRASH_IDENTITY_UNAVAILABLE".into()),
                }
            }
        }
        Ok(value) => {
            receipt.status = "failed".into();
            receipt.error = Some(value["error"].as_str().unwrap_or("TRASH_FAILED").into());
        }
        Err(e) => {
            receipt.status = "outcome_unknown".into();
            receipt.error = Some(e);
        }
    }
    s.receipts.insert(receipt.id.clone(), receipt.clone());
    if let Err(error) = write_json(&receipt_file, &receipt) {
        if let Some(r) = s.receipts.get_mut(&receipt.id) {
            r.status = "outcome_unknown".into();
            r.error = Some(error.clone());
        }
        return Err(error);
    }
    Ok(receipt)
}

fn undo_receipt(receipt_id: String, scope_id: String, state: &Desktop) -> Result<Receipt, String> {
    let mut s = state.session.lock().map_err(|_| "SESSION_FAILED")?;
    let grant = live_grant(&s, &scope_id)?;
    let mut receipt = s
        .receipts
        .get(&receipt_id)
        .ok_or("RECEIPT_REQUIRED")?
        .clone();
    if receipt.status != "trashed"
        || receipt.fixture_root != grant.root
        || receipt.root_dev != grant.dev
        || receipt.root_ino != grant.ino
        || receipt.restore_status == "restored"
    {
        return Err("RESTORE_NOT_AVAILABLE".into());
    }
    let dest = grant
        .root
        .join(scope::relative_file(&receipt.plan.item.relative)?);
    if receipt.restore_status == "outcome_unknown" || receipt.restore_status == "restoring" {
        return Err("RECONCILIATION_REQUIRED".into());
    }
    receipt.restore_status = "restoring".into();
    write_json(
        &state.data_dir.join(format!("receipt-{}.json", receipt.id)),
        &receipt,
    )?;
    s.receipts.insert(receipt.id.clone(), receipt.clone());
    let outcome = (|| {
        let src = receipt
            .trash_path
            .as_ref()
            .ok_or("TRASH_LOCATION_UNAVAILABLE")?;
        let expected = receipt
            .trash_identity
            .as_ref()
            .ok_or("TRASH_IDENTITY_UNAVAILABLE")?;
        if expected != &Identity::at(src)? {
            return Err("TRASH_FILE_DRIFT".into());
        }
        live_grant(&s, &scope_id)?;
        scope::restore_verified(src, &dest, expected, grant.dev, grant.ino)
    })();
    match outcome {
        Ok(()) => {
            receipt.restore_status = "restored".into();
            receipt.error = None;
        }
        Err(e) => {
            receipt.restore_status = if e == "RESTORE_OUTCOME_UNKNOWN" {
                "outcome_unknown"
            } else {
                "failed"
            }
            .into();
            receipt.error = Some(e);
        }
    }
    write_json(
        &state.data_dir.join(format!("receipt-{}.json", receipt.id)),
        &receipt,
    )?;
    s.receipts.insert(receipt.id.clone(), receipt.clone());
    Ok(receipt)
}

fn directory_probe(path: &Path) -> Value {
    match fs::read_dir(path) {
        Ok(entries) => json!({"allowed":true,"entries":entries.count()}),
        Err(e) => json!({"allowed":false,"errno":e.raw_os_error()}),
    }
}
fn has_unresolved(s: &Session) -> bool {
    s.receipts.values().any(|r| {
        matches!(r.status.as_str(), "prepared" | "outcome_unknown")
            || matches!(r.restore_status.as_str(), "restoring" | "outcome_unknown")
    })
}
fn close_scope(state: &Desktop) -> Result<Value, String> {
    let mut s = state.session.lock().map_err(|_| "SESSION_FAILED")?;
    s.grant = None;
    s.scan = None;
    s.plan = None;
    unsafe {
        sp_close_scope();
    }
    Ok(
        json!({"scope_revoked":true,"selected_after_stop":directory_probe(&state.fixture.fixture_root),"outside_after_stop":directory_probe(&state.fixture.outside_root)}),
    )
}
fn cancel_preview(state: &Desktop) -> Result<Value, String> {
    state.session.lock().map_err(|_| "SESSION_FAILED")?.plan = None;
    Ok(json!({"cancelled":true}))
}
impl Desktop {
    pub fn open(resources: &Path, data_dir: PathBuf) -> Result<Self, String> {
        let fixture: FixtureConfig = serde_json::from_slice(
            &fs::read(resources.join("fixture.json"))
                .map_err(|_| "FIXTURE_REGISTRATION_REQUIRED")?,
        )
        .map_err(|_| "FIXTURE_REGISTRATION_INVALID")?;
        let base = fixture
            .fixture_root
            .parent()
            .ok_or("FIXTURE_REGISTRATION_INVALID")?;
        if base.parent() != Some(Path::new("/Users/Shared"))
            || !base
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("space-perspective-mac001-"))
            || fixture.fixture_root.file_name().and_then(|n| n.to_str()) != Some("selected-fixture")
            || fixture.outside_root != base.join("outside-fixture")
            || fixture.expected_files != 1000
        {
            return Err("FIXTURE_REGISTRATION_INVALID".into());
        }
        fs::create_dir_all(&data_dir).map_err(|_| "RECEIPT_STORE_UNAVAILABLE")?;
        let instance_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data_dir.join("session.lock"))
            .map_err(|_| "RECEIPT_STORE_UNAVAILABLE")?;
        if unsafe { libc::flock(instance_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("ALREADY_RUNNING".into());
        }
        let mut receipts = BTreeMap::new();
        for entry in fs::read_dir(&data_dir).map_err(|_| "RECEIPT_STORE_UNAVAILABLE")? {
            let entry = entry.map_err(|_| "RECEIPT_STORE_UNAVAILABLE")?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("receipt-") || !name.ends_with(".json") {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|_| "RECEIPT_STORE_UNAVAILABLE")?
                .is_file()
            {
                return Err("RECEIPT_STORE_INVALID".into());
            }
            let mut r: Receipt = serde_json::from_slice(
                &fs::read(entry.path()).map_err(|_| "RECEIPT_STORE_INVALID")?,
            )
            .map_err(|_| "RECEIPT_STORE_INVALID")?;
            if name != format!("receipt-{}.json", r.id) || r.fixture_root != fixture.fixture_root {
                return Err("RECEIPT_STORE_INVALID".into());
            }
            if r.status == "prepared" {
                r.status = "outcome_unknown".into();
                r.error = Some("RECONCILIATION_REQUIRED".into());
            }
            if r.restore_status == "restoring" {
                r.restore_status = "outcome_unknown".into();
                r.error = Some("RECONCILIATION_REQUIRED".into());
            }
            write_json(&entry.path(), &r)?;
            receipts.insert(r.id.clone(), r);
        }
        write_json(
            &data_dir.join("startup.json"),
            &json!({"pid":std::process::id(),"fixture_only":true,
            "pre_picker_selected":directory_probe(&fixture.fixture_root),"pre_picker_outside":directory_probe(&fixture.outside_root),
            "shell":"AppKit","helper_processes":0,"architecture":std::env::consts::ARCH}),
        )?;
        Ok(Self {
            fixture,
            session: Mutex::new(Session {
                grant: None,
                scan: None,
                plan: None,
                receipts,
            }),
            data_dir,
            _instance_lock: instance_lock,
        })
    }
    pub fn dispatch(&self, command: &str, args: &Value) -> Result<Value, String> {
        let string = |key: &str| {
            args[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "INVALID_ARGUMENT".to_string())
        };
        let result = match command {
            "status" => desktop_status(self),
            "choose" => choose_fixture(self),
            "scan" => scan_fixture(string("scope_id")?, self)
                .and_then(|v| serde_json::to_value(v).map_err(|_| "SERIALIZE_FAILED".into())),
            "preview" => preview_item(string("scope_id")?, string("item_id")?, self)
                .and_then(|v| serde_json::to_value(v).map_err(|_| "SERIALIZE_FAILED".into())),
            "confirm" => confirm_plan(
                string("plan_id")?,
                args["version"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("INVALID_ARGUMENT")?,
                args["confirm"] == true,
                self,
            )
            .and_then(|v| serde_json::to_value(v).map_err(|_| "SERIALIZE_FAILED".into())),
            "undo" => undo_receipt(string("receipt_id")?, string("scope_id")?, self)
                .and_then(|v| serde_json::to_value(v).map_err(|_| "SERIALIZE_FAILED".into())),
            "cancel" => cancel_preview(self),
            "close" => close_scope(self),
            "quit" => {
                close_scope(self)?;
                write_json(
                    &self.data_dir.join("exit.json"),
                    &json!({"scope_revoked":true,"helper_processes":0,"pid":std::process::id()}),
                )?;
                Ok(json!({"quit":true}))
            }
            _ => Err("COMMAND_NOT_ALLOWED".into()),
        };
        if command != "status" {
            let record =
                json!({"command":command,"args":args,"result":result,"pid":std::process::id()});
            let mut log = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.data_dir.join("events.jsonl"))
                .map_err(|_| "EVIDENCE_WRITE_FAILED")?;
            writeln!(log, "{record}").map_err(|_| "EVIDENCE_WRITE_FAILED")?;
            log.sync_all().map_err(|_| "EVIDENCE_WRITE_FAILED")?;
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_confirm_and_exact_plan_version_required() {
        let plan:Plan=serde_json::from_value(json!({"id":"p1","version":1,"scope_id":"s1","action":"system_trash","item":{"id":"f","name":"x","relative":"x","bytes":1,"reason":"fixture","protected":false,"selected":false,"identity":{"dev":1,"ino":2,"size":1,"mtime":1,"mtime_ns":0,"ctime":1,"ctime_ns":0,"links":1}}})).unwrap();
        assert_eq!(
            validate_confirmation(&plan, "p1", 1, false).unwrap_err(),
            "CONFIRM_REQUIRED"
        );
        assert!(validate_confirmation(&plan, "p1", 2, true).is_err());
        assert!(validate_confirmation(&plan, "p2", 1, true).is_err());
        assert!(validate_confirmation(&plan, "p1", 1, true).is_ok());
    }
    struct Fixture {
        root: PathBuf,
        state: Desktop,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("mac001-state-{}", nonce()));
            fs::create_dir(&root).unwrap();
            let selected = root.join("selected");
            fs::create_dir(&selected).unwrap();
            fs::write(selected.join("sample.txt"), "controlled fixture").unwrap();
            fs::write(selected.join("合同.txt"), "protected fixture").unwrap();
            let data = root.join("receipts");
            fs::create_dir(&data).unwrap();
            let m = selected.metadata().unwrap();
            let state = Desktop {
                fixture: FixtureConfig {
                    fixture_root: selected.clone(),
                    outside_root: root.join("outside"),
                    expected_files: 1000,
                },
                _instance_lock: File::create(data.join("session.lock")).unwrap(),
                data_dir: data,
                session: Mutex::new(Session {
                    grant: Some(Grant {
                        id: "g".into(),
                        root: selected,
                        dev: m.dev(),
                        ino: m.ino(),
                    }),
                    scan: None,
                    plan: None,
                    receipts: BTreeMap::new(),
                }),
            };
            Self { root, state }
        }
        fn plan(&self) -> Plan {
            let scan = scan_fixture("g".into(), &self.state).unwrap();
            let id = scan
                .items
                .iter()
                .find(|i| i.name == "sample.txt")
                .unwrap()
                .id
                .clone();
            preview_item("g".into(), id, &self.state).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn cancel_rescan_and_close_invalidate_plan_without_file_actions() {
        let f = Fixture::new();
        let p = f.plan();
        cancel_preview(&f.state).unwrap();
        assert_eq!(
            confirm_plan(p.id, p.version, true, &f.state).unwrap_err(),
            "PREVIEW_REQUIRED"
        );
        let p = f.plan();
        scan_fixture("g".into(), &f.state).unwrap();
        assert_eq!(
            confirm_plan(p.id, p.version, true, &f.state).unwrap_err(),
            "PREVIEW_REQUIRED"
        );
        let p = f.plan();
        close_scope(&f.state).unwrap();
        assert_eq!(
            confirm_plan(p.id, p.version, true, &f.state).unwrap_err(),
            "PREVIEW_REQUIRED"
        );
        assert_eq!(
            scan_fixture("g".into(), &f.state).unwrap_err(),
            "SCOPE_REQUIRED"
        );
        assert!(f.state.session.lock().unwrap().receipts.is_empty());
        assert_eq!(
            fs::read_to_string(f.state.fixture.fixture_root.join("sample.txt")).unwrap(),
            "controlled fixture"
        );
    }
    #[test]
    fn protected_items_and_drift_are_rejected_before_trash() {
        let f = Fixture::new();
        let scan = scan_fixture("g".into(), &f.state).unwrap();
        assert!(scan.items.iter().all(|i| !i.selected));
        let protected = scan.items.iter().find(|i| i.protected).unwrap();
        assert_eq!(
            preview_item("g".into(), protected.id.clone(), &f.state).unwrap_err(),
            "PROTECTED_ITEM"
        );
        assert_eq!(
            preview_item("outside".into(), protected.id.clone(), &f.state).unwrap_err(),
            "SCOPE_EXPIRED"
        );
        let p = f.plan();
        fs::write(
            f.state.fixture.fixture_root.join("sample.txt"),
            "changed fixture payload",
        )
        .unwrap();
        assert_eq!(
            confirm_plan(p.id, p.version, true, &f.state).unwrap_err(),
            "FILE_DRIFT"
        );
        assert!(f.state.session.lock().unwrap().receipts.is_empty());
    }
    #[test]
    fn unknown_intent_blocks_new_actions_and_cannot_be_restored() {
        let f = Fixture::new();
        let p = f.plan();
        let g = f.state.session.lock().unwrap().grant.clone().unwrap();
        let r = Receipt {
            id: nonce(),
            plan: p.clone(),
            fixture_root: g.root,
            root_dev: g.dev,
            root_ino: g.ino,
            status: "outcome_unknown".into(),
            trash_path: None,
            trash_identity: None,
            error: Some("RECONCILIATION_REQUIRED".into()),
            restore_status: "not_attempted".into(),
            evidence_level: "unit_fixture".into(),
        };
        f.state
            .session
            .lock()
            .unwrap()
            .receipts
            .insert(r.id.clone(), r.clone());
        assert_eq!(
            confirm_plan(p.id, p.version, true, &f.state).unwrap_err(),
            "RECONCILIATION_REQUIRED"
        );
        assert_eq!(
            preview_item("g".into(), p.item.id, &f.state).unwrap_err(),
            "RECONCILIATION_REQUIRED"
        );
        assert_eq!(
            undo_receipt(r.id, "g".into(), &f.state).unwrap_err(),
            "RESTORE_NOT_AVAILABLE"
        );
        assert_eq!(
            f.state
                .dispatch("arbitrary-path", &json!({"path":"/unapproved"}))
                .unwrap_err(),
            "COMMAND_NOT_ALLOWED"
        );
    }
    #[test]
    fn restart_preserves_unfinished_receipts_and_corruption_fails_closed() {
        let f = Fixture::new();
        let plan = f.plan();
        let resources = f.root.join("resources");
        fs::create_dir(&resources).unwrap();
        let base = Path::new("/Users/Shared")
            .join(format!("space-perspective-mac001-nonexistent-{}", nonce()));
        let selected = base.join("selected-fixture");
        write_json(&resources.join("fixture.json"),&json!({"fixture_root":selected,"outside_root":base.join("outside-fixture"),"expected_files":1000})).unwrap();
        let data = f.root.join("restart");
        fs::create_dir(&data).unwrap();
        for (id, status, restore_status) in [
            ("interrupted-trash", "prepared", "not_attempted"),
            ("interrupted-undo", "trashed", "restoring"),
        ] {
            let receipt = Receipt {
                id: id.into(),
                plan: plan.clone(),
                fixture_root: selected.clone(),
                root_dev: 1,
                root_ino: 2,
                status: status.into(),
                trash_path: None,
                trash_identity: None,
                error: None,
                restore_status: restore_status.into(),
                evidence_level: "unit_fixture".into(),
            };
            write_json(&data.join(format!("receipt-{id}.json")), &receipt).unwrap();
        }
        let reopened = Desktop::open(&resources, data.clone()).unwrap();
        let state = desktop_status(&reopened).unwrap();
        assert_eq!(state["unresolved"], true);
        assert!(state["scope_id"].is_null());
        let session = reopened.session.lock().unwrap();
        assert_eq!(
            session.receipts["interrupted-trash"].status,
            "outcome_unknown"
        );
        assert_eq!(
            session.receipts["interrupted-undo"].restore_status,
            "outcome_unknown"
        );
        drop(session);
        assert!(
            fs::read_to_string(data.join("receipt-interrupted-undo.json"))
                .unwrap()
                .contains("RECONCILIATION_REQUIRED")
        );
        assert!(matches!(Desktop::open(&resources,data.clone()),Err(e) if e=="ALREADY_RUNNING"));
        drop(reopened);
        fs::write(data.join("receipt-corrupted.json"), "broken receipt").unwrap();
        assert!(matches!(Desktop::open(&resources,data),Err(e) if e=="RECEIPT_STORE_INVALID"));
    }
}
