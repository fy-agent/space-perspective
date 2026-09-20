from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_TARGET = Path(__file__).parent / "generated" / "demo-corpus"
SAMPLES: dict[str, bytes] = {
    "Downloads/repeat-a.txt": b"artificial duplicate sample\n",
    "Desktop/archive/repeat-b.txt": b"artificial duplicate sample\n",
    "Downloads/same-name/note.txt": b"first artificial note\n",
    "Documents/same-name/note.txt": b"different artificial note\n",
    "Downloads/old_installer.exe": b"artificial installer placeholder\n",
    "Desktop/temp-screenshot.png": b"artificial screenshot placeholder\n",
    "Documents/合同-样本.txt": "人工构造的合同文件名占位，不包含真实合同信息。\n".encode(),
    "Documents/发票-样本.pdf": b"%PDF-1.4\n% artificial invoice placeholder only\n",
    "Pictures/家庭照片-placeholder.jpg": b"artificial family photo placeholder\n",
    "WeChat Files/group/video.mp4": b"artificial wechat video placeholder\n",
    "Downloads/large-file-placeholder.bin": b"artificial large-file placeholder\n",
}
SIMULATED_SIZES = {
    "Downloads/large-file-placeholder.bin": 1_500_000_000,
}
EXPECTED_DUPLICATE_GROUPS = [
    ["Downloads/repeat-a.txt", "Desktop/archive/repeat-b.txt"],
]


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def generate(target: Path = DEFAULT_TARGET) -> dict[str, Any]:
    if target.is_symlink():
        raise ValueError("fixtures 输出目录不能是符号链接")
    target = target.resolve()
    target.mkdir(parents=True, exist_ok=True)

    files: list[dict[str, Any]] = []
    for relative_path, content in sorted(SAMPLES.items()):
        destination = target / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        item: dict[str, Any] = {
            "path": relative_path,
            "sha256": _sha256(content),
            "size_bytes": len(content),
        }
        if relative_path in SIMULATED_SIZES:
            item["simulated_size_bytes"] = SIMULATED_SIZES[relative_path]
        files.append(item)

    manifest: dict[str, Any] = {
        "fixture_kind": "artificial_non_sensitive",
        "files": files,
        "expected_exact_duplicate_groups": EXPECTED_DUPLICATE_GROUPS,
    }
    (target / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="生成资料管家安全测试样本")
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    args = parser.parse_args()
    manifest = generate(args.target)
    print(f"generated {len(manifest['files'])} artificial files in {args.target.resolve()}")


if __name__ == "__main__":
    main()
