"""Build the fixture app or the separate Downloads read-only trial. No real-file content reads."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output/mac-001-native-20260919"
CONFIG = ROOT / "desktop/resources/native-fixture.json"
APP = OUT / "build/Space Perspective Native.app"
BUNDLE_ID = "dev.spaceperspective.mac001.native20260919"

def command(args, *, cwd=ROOT):
    print("RUN", " ".join(map(str,args)), flush=True)
    subprocess.run(list(map(str,args)),cwd=cwd,check=True,timeout=300)

def prepare():
    if CONFIG.exists():
        raise SystemExit("Fixture registration already exists; reuse it. No fixture overwrite.")
    base = Path("/Users/Shared") / f"space-perspective-mac001-{uuid.uuid4()}"
    selected = base / "selected-fixture"
    selected.mkdir(parents=True, mode=0o700)
    outside = base / "outside-fixture"
    outside.mkdir(mode=0o700)
    (outside / "out-of-scope.txt").write_text("verifier-only sentinel\n")
    manifest = {}
    for i in range(1000):
        name = f"sample-{i:04d}.txt" if i < 999 else "合同-保留.txt"
        p = selected / name
        p.write_text(f"MAC-001 controlled fixture {i}\n", encoding="utf-8")
        os.utime(p, (1577836800, 1577836800))
        manifest[name] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "size": p.stat().st_size, "mtime_ns": p.stat().st_mtime_ns}
    (selected / "escape-link").symlink_to(outside, target_is_directory=True)
    (selected / ".hidden-fixture").write_text("hidden verifier payload")
    package = selected / "Fixture.app"
    package.mkdir()
    (package / "package-payload").write_text("package verifier payload")
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    config = {"fixture_root": str(selected), "outside_root": str(outside), "expected_files": 1000}
    CONFIG.write_text(json.dumps(config, indent=2) + "\n")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "fixture-registration.json").write_text(json.dumps(config, indent=2) + "\n")
    (OUT / "fixture-integrity-before.json").write_text(json.dumps({"verifier_hashes": 1000, "files": manifest}, ensure_ascii=False, indent=2) + "\n")
    print("Created registered temporary fixture:", selected)


def build(read_only=False):
    out = OUT / "downloads-read-only" if read_only else OUT
    app = out / "Space Perspective Read Only.app" if read_only else APP
    bundle_id = "dev.spaceperspective.mac001.downloads.readonly" if read_only else BUNDLE_ID
    entitlements_path = ROOT / ("desktop/entitlements-read-only.plist" if read_only else "desktop/entitlements.plist")
    if not read_only and not CONFIG.exists():
        raise SystemExit("Run --prepare once first")
    args = ["cargo","build","--locked","--offline","--release","--manifest-path",ROOT / "desktop/Cargo.toml","--bin","space-perspective-desktop"]
    if read_only: args += ["--features","read-only-downloads"]
    command(args)
    if app.exists():
        shutil.rmtree(app)  # Only this script's disposable build staging app.
    contents = app / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Resources").mkdir()
    shutil.copy2(ROOT / "desktop/target/release/space-perspective-desktop",contents / "MacOS/space-perspective-desktop")
    if read_only:
        (contents / "Resources/read-only.json").write_text(json.dumps({"root":str(Path.home() / "Downloads")})+"\n")
    else:
        shutil.copy2(CONFIG,contents / "Resources/fixture.json")
    shutil.copy2(ROOT / "desktop/icons/icon.icns",contents / "Resources/icon.icns")
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier":bundle_id,"CFBundleName":app.stem,"CFBundleDisplayName":"空间透视只读测试" if read_only else "空间透视",
        "CFBundleExecutable":"space-perspective-desktop","CFBundlePackageType":"APPL","CFBundleVersion":"1",
        "CFBundleShortVersionString":"0.1.0","CFBundleIconFile":"icon","LSMinimumSystemVersion":"13.0",
        "NSHighResolutionCapable":True,"NSPrincipalClass":"NSApplication"
    }))
    command(["codesign","--force","--sign","-","--timestamp=none","--options","runtime","--entitlements",entitlements_path,app])
    command(["codesign","--verify","--strict","--deep",app])
    result=subprocess.run(["codesign","-d","--entitlements",":-",str(app)],check=True,capture_output=True)
    entitlements=plistlib.loads(result.stdout)
    expected=plistlib.loads(entitlements_path.read_bytes())
    assert entitlements == expected
    dependencies=subprocess.check_output(["otool","-L",str(contents / "MacOS/space-perspective-desktop")],text=True)
    assert "WebKit" not in dependencies and not (contents / "Helpers").exists()
    if read_only:
        symbols=subprocess.check_output(["nm",str(contents / "MacOS/space-perspective-desktop")],text=True)
        assert "_sp_trash" not in symbols and "_renameatx_np" not in symbols
        assert "com.apple.security.files.user-selected.read-write" not in entitlements
    (out / "build-readback.json").write_text(json.dumps({"app":str(app),"bundle_id":bundle_id,"shell":"AppKit","read_only":read_only,
        "signing":"ad-hoc local only","hardened_runtime":True,"entitlements":entitlements,"helper_processes":0,
        "notarized":False,"uat":False,"artifact_bytes":sum(p.stat().st_size for p in app.rglob("*") if p.is_file()),
        "executable_sha256":hashlib.sha256((contents / "MacOS/space-perspective-desktop").read_bytes()).hexdigest(),
        "linked_libraries":dependencies.splitlines()[1:]},indent=2)+"\n")
    print("Built local app:",app)

def package():
    stage=OUT / "dmg-stage"
    stage.mkdir(exist_ok=True)
    target=stage / APP.name
    if target.exists():
        shutil.rmtree(target)
    command(["ditto",APP,target])
    command(["hdiutil","create","-ov","-volname","SpacePerspective Native MAC001","-srcfolder",stage,"-format","UDZO",OUT / "SpacePerspective-Native-MAC001-arm64.dmg"])

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--prepare",action="store_true")
    parser.add_argument("--build",action="store_true")
    parser.add_argument("--package",action="store_true")
    parser.add_argument("--read-only-downloads",action="store_true",help="Build a separate app with no file-action backend and read-only user-selected permission")
    args=parser.parse_args()
    if args.read_only_downloads and (args.prepare or args.package or not args.build):
        parser.error("--read-only-downloads requires --build alone")
    for enabled,fn in ((args.prepare,prepare),(args.build,lambda:build(args.read_only_downloads)),(args.package,package)):
        if enabled: fn()
