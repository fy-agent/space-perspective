from __future__ import annotations

from pathlib import Path, PurePath
import stat

from core.app.models import AssetCategory, RiskLevel, SourceHint


CATEGORY_EXTENSIONS: dict[AssetCategory, set[str]] = {
    "photo": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".tif", ".tiff"},
    "video": {".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v", ".wmv", ".flv"},
    "archive": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"},
    "installer": {".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".appimage"},
    "document": {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".md", ".csv", ".rtf"},
    "pdf": {".pdf"},
    "audio": {".mp3", ".wav", ".aac", ".flac", ".m4a", ".ogg", ".wma"},
    "other": set(),
}

HIGH_RISK_KEYWORDS = {
    "身份证", "idcard", "id card", "居民身份证", "护照", "passport", "签证", "visa",
    "银行卡", "bank card", "信用卡", "储蓄卡", "卡号", "合同", "协议", "contract",
    "agreement", "签约", "用印", "发票", "invoice", "增值税", "专票", "普票", "收据",
    "receipt", "付款凭证", "账单", "bill", "statement", "对账单", "流水", "医疗", "病历",
    "处方", "检查报告", "体检", "医院", "医保", "财务", "报销", "税务", "纳税", "工资",
    "薪资", "客户", "client", "customer", "crm", "联系人", "交付", "简历", "resume", "cv",
    "候选人", "报价", "quotation", "家庭", "孩子", "宝宝", "亲子", "家人", "相册", "dcim",
    "camera", "原件", "唯一", "final", "最终版", "扫描件", "盖章", "签字", "正本",
}


def classify_category(path: PurePath) -> AssetCategory:
    suffix = path.suffix.lower()
    for category, extensions in CATEGORY_EXTENSIONS.items():
        if suffix in extensions:
            return category
    return "other"


def infer_source_hint(path: PurePath, root: PurePath, override: SourceHint | None = None) -> SourceHint:
    if override is not None:
        return override
    try:
        relative_parts = path.relative_to(root).parts
        parts = [root.name.casefold(), *(part.casefold() for part in relative_parts)]
    except ValueError:
        parts = [part.casefold() for part in path.parts]
    joined = "/".join(parts)
    if any(marker in joined for marker in ("wechat files", "weixin files", "微信文件")):
        return "wechat"
    if any(marker in joined for marker in ("wechat", "weixin", "wechatwork", "wxwork", "微信")):
        return "suspected_wechat"
    if any(part in {"downloads", "download", "下载", "下载文件"} for part in parts):
        return "downloads"
    if any(part in {"desktop", "桌面"} for part in parts):
        return "desktop"
    if any(part in {"screenshots", "screenshot", "截图", "屏幕快照"} for part in parts):
        return "screenshots"
    if any(part in {"pictures", "photos", "图片", "照片", "相册"} for part in parts):
        return "pictures"
    if any(part in {"documents", "document", "文档", "我的文档"} for part in parts):
        return "documents"
    try:
        path.relative_to(root)
        return "manual_folder"
    except ValueError:
        return "unknown"


def assess_risk(path: PurePath, *, has_exact_duplicate: bool = False) -> tuple[RiskLevel, list[str]]:
    text = str(path).casefold()
    matched = sorted(keyword for keyword in HIGH_RISK_KEYWORDS if keyword.casefold() in text)
    flags = [f"sensitive_keyword:{keyword}" for keyword in matched[:8]]
    if matched:
        return "high", flags
    important_parts = {"documents", "document", "文档", "客户", "财务", "法务", "交付物"}
    if any(part.casefold() in important_parts for part in path.parts):
        return "high", ["important_directory"]
    if has_exact_duplicate:
        return "low", ["exact_duplicate"]
    return "medium", ["needs_confirmation"]


def is_hidden(path: Path) -> bool:
    if path.name.startswith("."):
        return True
    hidden_flag = getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0)
    if not hidden_flag:
        return False
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & hidden_flag)
