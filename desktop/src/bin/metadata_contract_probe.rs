//! External verifier only; excluded from the .app and normal builds.
#[path = "../scope.rs"]
mod scope;
fn main() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../resources/native-fixture.json")).unwrap();
    let root = std::path::Path::new(fixture["fixture_root"].as_str().unwrap());
    let scan = scope::enumerate(root, "external-contract-verifier").expect("metadata enumeration");
    assert_eq!(scan.items.len(), 1000);
    assert_eq!(
        (scan.content_reads, scan.hashes, scan.network_calls),
        (0, 0, 0)
    );
    println!(
        "{}",
        serde_json::json!({"items":scan.items.len(),"skipped":scan.skipped.len(),"content_reads":0,"hashes":0,"network_calls":0,"kind":"external_verifier_under_payload_read_and_network_deny_policy"})
    );
}
