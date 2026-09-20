from pathlib import Path, PureWindowsPath

from core.domain.rules import assess_risk, infer_source_hint, is_hidden


def test_workspace_ancestor_does_not_taint_authorized_relative_path() -> None:
    root = Path("/Users/example/Documents/project/runtime-corpus")
    duplicate = root / "Downloads" / "repeat-a.txt"

    risk, flags = assess_risk(duplicate.relative_to(root), has_exact_duplicate=True)

    assert risk == "low"
    assert flags == ["exact_duplicate"]
    assert infer_source_hint(duplicate, root) == "downloads"


def test_authorized_documents_child_still_receives_protection() -> None:
    relative = Path("Documents/合同-样本.txt")

    risk, flags = assess_risk(relative)

    assert risk == "high"
    assert any("合同" in flag for flag in flags)


def test_windows_paths_keep_source_and_risk_semantics() -> None:
    root = PureWindowsPath(r"C:\Users\Tester\资料")

    assert infer_source_hint(root / "Downloads" / "安装包.exe", root) == "downloads"
    assert infer_source_hint(root / "WeChat Files" / "wxid" / "记录.pdf", root) == "wechat"
    assert infer_source_hint(root / "Desktop" / "note.txt", root) == "desktop"

    risk, flags = assess_risk(PureWindowsPath(r"Documents\合同-样本.txt"))
    assert risk == "high"
    assert any("合同" in flag for flag in flags)


def test_windows_hidden_attribute_is_respected(monkeypatch) -> None:
    class FakeStat:
        st_file_attributes = 2

    class FakePath:
        name = "visible-name.txt"

        def stat(self, *, follow_symlinks: bool):
            assert follow_symlinks is False
            return FakeStat()

    monkeypatch.setattr("core.domain.rules.stat.FILE_ATTRIBUTE_HIDDEN", 2, raising=False)

    assert is_hidden(FakePath()) is True
