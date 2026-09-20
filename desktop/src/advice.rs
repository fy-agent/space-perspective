//! Metadata-only suggestions. Classification and a user decision never authorize a file action.
use crate::scope::Scan;
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Serialize)]
pub struct Suggestion {
    pub id: String,
    pub name: String,
    pub relative: String,
    pub bytes: u64,
    pub modified_at: i64,
    pub category: String,
    pub category_label: String,
    pub purpose: String,
    pub group: String,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<String>,
    pub caution: String,
    pub next_step: String,
    pub confidence: String,
    pub related_id: Option<String>,
    pub can_consider_cleanup: bool,
    pub decision: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Group {
    pub id: String,
    pub label: String,
    pub count: usize,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Advice {
    pub rules_version: &'static str,
    pub basis: &'static str,
    pub headline: String,
    pub groups: Vec<Group>,
    pub categories: Vec<Group>,
    pub items: Vec<Suggestion>,
}

fn category(name: &str) -> (&'static str, &'static str) {
    match Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "dmg" | "pkg" | "msi" | "apk" | "deb" | "rpm" => ("installer", "安装包"),
        "exe" | "appimage" => ("program", "可执行程序"),
        "zip" | "rar" | "7z" | "tar" | "gz" | "tgz" | "bz2" | "xz" => ("archive", "压缩包"),
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "key" | "pages" | "numbers"
        | "csv" | "rtf" | "txt" | "md" => ("document", "工作文档"),
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "bmp" | "tif" | "tiff" | "svg" => {
            ("image", "图片与截图")
        }
        "mp4" | "mov" | "mkv" | "avi" | "webm" | "m4v" | "wmv" | "flv" => ("video", "视频"),
        "mp3" | "wav" | "aac" | "flac" | "m4a" | "ogg" | "wma" => ("audio", "音频"),
        "py" | "js" | "ts" | "tsx" | "jsx" | "rs" | "swift" | "c" | "h" | "cpp" | "java" | "cs"
        | "go" | "json" | "yaml" | "yml" | "toml" | "lock" | "sh" | "html" | "css" => {
            ("project", "项目与代码")
        }
        _ => ("other", "其他文件"),
    }
}
fn keyword_match(text: &str, word: &str) -> bool {
    if !word.is_ascii() {
        return text.contains(word);
    }
    text.match_indices(word).any(|(start, _)| {
        let end = start + word.len();
        !text[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric())
            && !text[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
    })
}
fn copy_key(name: &str) -> (String, bool) {
    let path = Path::new(name);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if let Some((base, suffix)) = stem.rsplit_once(" (") {
        if suffix
            .strip_suffix(')')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            return (format!("{}.{}", base.to_lowercase(), ext), true);
        }
    }
    (name.to_lowercase(), false)
}
// Keep platform/channel tokens in the family. Ignore only trailing hexadecimal build IDs.
fn version_key(name: &str) -> Option<(String, Vec<u64>)> {
    let p = Path::new(name);
    let stem = p.file_stem()?.to_str()?.to_lowercase();
    let ext = p.extension()?.to_str()?.to_lowercase();
    for (start, c) in stem.char_indices() {
        if !c.is_ascii_digit() {
            continue;
        }
        let prefix = &stem[..start];
        if prefix.is_empty()
            || prefix
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() && c != 'v')
        {
            continue;
        }
        let len = stem[start..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .map(char::len_utf8)
            .sum::<usize>();
        let text = stem[start..start + len].trim_end_matches('.');
        let pieces: Vec<_> = text.split('.').collect();
        if pieces.len() < 2 || pieces.len() > 5 || pieces.iter().any(|v| v.is_empty()) {
            continue;
        }
        let version: Option<Vec<u64>> = pieces.iter().map(|v| v.parse().ok()).collect();
        let mut version = version?;
        version.resize(5, 0);
        let suffix = &stem[start + text.len()..];
        let tail = suffix
            .split(['-', '_', ' '])
            .filter(|t| !t.is_empty())
            .filter(|t| !(t.len() >= 7 && t.bytes().all(|c| c.is_ascii_hexdigit())))
            .collect::<Vec<_>>()
            .join("-");
        return Some((
            format!(
                "{}|{}|{}",
                prefix.trim_end_matches(['-', '_', ' ', 'v']),
                tail,
                ext
            ),
            version,
        ));
    }
    None
}
fn parent(relative: &str) -> String {
    Path::new(relative)
        .parent()
        .unwrap_or(Path::new(""))
        .to_string_lossy()
        .into_owned()
}
fn purpose(name: &str, label: &str) -> String {
    let lower = name.to_lowercase();
    if name.contains("交接") {
        return "交接资料（名称线索）".into();
    }
    if name.contains("简历")
        || (name.contains('【')
            && name.contains('】')
            && (name.contains("应届") || name.contains('年')))
    {
        return "疑似招聘简历".into();
    }
    for (words, meaning) in [
        (&["合同", "协议"][..], "合同或协议（名称线索）"),
        (&["发票", "收据", "账单"][..], "财务凭证（名称线索）"),
        (
            &["课件", "课程", "教材", "讲义"][..],
            "课程资料（名称线索）",
        ),
        (&["会议", "纪要"][..], "会议资料（名称线索）"),
        (
            &["截图", "screenshot", "screen shot"][..],
            "截图（名称线索）",
        ),
    ] {
        if words.iter().any(|w| lower.contains(w)) {
            return meaning.into();
        }
    }
    match Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "apk" => "Android 安装包".into(),
        "dmg" => "Mac 软件分发镜像".into(),
        "exe" => "Windows 可执行程序".into(),
        "appimage" => "Linux 可执行程序".into(),
        "msi" => "Windows 安装包".into(),
        "pdf" => "PDF 文档".into(),
        _ => label.into(),
    }
}
fn set(
    s: &mut Suggestion,
    group: &str,
    title: &str,
    explanation: &str,
    caution: &str,
    next: &str,
    confidence: &str,
) {
    s.group = group.into();
    s.title = title.into();
    s.explanation = explanation.into();
    s.caution = caution.into();
    s.next_step = next.into();
    s.confidence = confidence.into();
    s.can_consider_cleanup = group == "cleanup";
}
pub fn analyze(scan: &Scan, now: i64) -> Advice {
    let keywords: Vec<String> =
        serde_json::from_str(include_str!("../rules/high-risk-keywords.json"))
            .expect("bundled rules");
    let mut copies = BTreeMap::<(String, String, u64), Vec<usize>>::new();
    let mut versions = BTreeMap::<(String, String), Vec<(usize, Vec<u64>)>>::new();
    for (i, item) in scan.items.iter().enumerate() {
        let (key, _) = copy_key(&item.name);
        copies
            .entry((parent(&item.relative), key, item.bytes))
            .or_default()
            .push(i);
        if category(&item.name).0 == "installer" {
            if let Some((family, version)) = version_key(&item.name) {
                versions
                    .entry((parent(&item.relative), family))
                    .or_default()
                    .push((i, version));
            }
        }
    }
    let mut repeat = BTreeMap::<usize, usize>::new();
    let mut copy_anchors = BTreeMap::<usize, usize>::new();
    for members in copies.values().filter(|m| m.len() > 1) {
        if !members.iter().any(|i| copy_key(&scan.items[*i].name).1) {
            continue;
        }
        let anchor = *members
            .iter()
            .min_by_key(|i| (copy_key(&scan.items[**i].name).1, &scan.items[**i].name))
            .unwrap();
        for i in members.iter().filter(|i| **i != anchor) {
            repeat.insert(*i, anchor);
        }
        copy_anchors.insert(anchor, members.len());
    }
    let mut older = BTreeMap::<usize, usize>::new();
    let mut newer = BTreeMap::<usize, usize>::new();
    for members in versions.values().filter(|m| m.len() > 1) {
        let (anchor, highest) = members.iter().max_by(|a, b| a.1.cmp(&b.1)).unwrap();
        for (i, v) in members.iter().filter(|(_, v)| v < highest) {
            older.insert(*i, *anchor);
            let _ = v;
        }
        if members.iter().any(|(_, v)| v < highest) {
            newer.insert(*anchor, members.len());
        }
    }
    let mut items = Vec::new();
    for (i, item) in scan.items.iter().enumerate() {
        let (kind, label) = category(&item.name);
        let text = item.relative.to_lowercase();
        let purpose = purpose(&item.name, label);
        let matched = keywords
            .iter()
            .find(|word| keyword_match(&text, word))
            .map(String::as_str)
            .or_else(|| {
                if purpose == "疑似招聘简历" {
                    Some("招聘简历命名形式")
                } else if item.relative.contains("交接") {
                    Some("交接")
                } else {
                    None
                }
            });
        let age = (now - item.identity.mtime).max(0) / 86400;
        let mut s = Suggestion {
            id: item.id.clone(),
            name: item.name.clone(),
            relative: item.relative.clone(),
            bytes: item.bytes,
            modified_at: item.identity.mtime,
            category: kind.into(),
            category_label: label.into(),
            purpose,
            group: "confirm".into(),
            title: "用途还不明确".into(),
            explanation: "仅凭当前名称和后缀，无法可靠判断用途或清理价值。".into(),
            evidence: vec![
                format!("类型依据：文件后缀；分类为{label}"),
                format!("来源：本次授权的 Downloads；距修改时间 {age} 天"),
            ],
            caution: "没有读取正文或核验其他副本；大小和时间都不能单独证明文件无用。".into(),
            next_step: "先确认用途；有用的文件按项目或资料类别归档。".into(),
            confidence: "较低：用途未知".into(),
            related_id: None,
            can_consider_cleanup: false,
            decision: "none".into(),
        };
        if let Some(word) = matched {
            set(
                &mut s,
                "protected",
                "重要资料，建议保留",
                "名称或所在路径含重要资料线索，清理优先级应让位于保留和归档。",
                "这是名称线索，不代表已阅读内容；即使同名或大小相同，也不建议直接清理。",
                "先保留，核对后归入对应项目、财务、人事或个人资料目录。",
                "中等：名称线索",
            );
            s.evidence.push(if word == "招聘简历命名形式" {
                "命名线索：职位括号与经历年限，疑似招聘导出的资料；未读取正文".into()
            } else {
                format!("保护依据：名称或路径含「{word}」")
            });
        } else if kind == "program" {
            set(
                &mut s,
                "confirm",
                "可执行程序，不能当作安装残留",
                "这个后缀既可能是安装工具，也可能是直接运行的软件或工具本体。",
                "没有运行或检查程序，不能依据时间判断它已无用。",
                "先确认用途与是否仍需运行；便携程序应作为应用保留。",
                "较低：程序用途待确认",
            );
        } else if kind == "project" {
            set(
                &mut s,
                "keep",
                "项目文件，建议整体保留",
                "代码、配置或项目资源可能被同一项目中的其他文件引用。",
                "不能用文件大小或修改时间判断依赖是否失效。",
                "按整个项目归档；不要零散清理配置或源文件。",
                "中等：文件类型",
            );
        } else if let Some(anchor) = repeat.get(&i) {
            let related = &scan.items[*anchor];
            if kind == "installer" || kind == "archive" {
                set(
                    &mut s,
                    "cleanup",
                    "疑似重复下载，优先核对",
                    "同一目录中存在名称仅差下载编号、且字节大小相同的文件。",
                    "尚未核验内容，不能称为精确重复；确认两份可互相替代后才考虑清理副本。",
                    "先保留下方对照文件，核对用途与内容；确认相同后可清理当前下载副本。",
                    "中等：名称与大小一致",
                );
            } else {
                set(
                    &mut s,
                    "confirm",
                    "疑似副本，需要比较",
                    "名称仅差下载编号且大小相同，但资料内容仍可能不同。",
                    "未做内容比对，不能据此删除文档或照片。",
                    "比较两份内容，确认哪份是原件；这次先保留。",
                    "中等：名称与大小一致",
                );
            }
            s.evidence.push(format!(
                "对照文件：{}；与当前文件均为 {} 字节",
                related.relative, item.bytes
            ));
            s.related_id = Some(related.id.clone());
        } else if let Some(anchor) = older.get(&i) {
            let related = &scan.items[*anchor];
            set(
                &mut s,
                "cleanup",
                "发现较新版本，可核对旧安装包",
                "同一目录中，同一软件与平台的安装包名称包含更高版本号。",
                "没有检查应用是否已安装，也未核验包内容；旧版本可能仍用于回退或兼容。",
                "优先保留较新安装包；确认不需要旧版本安装或回退后，可清理当前旧包。",
                "中等：文件名版本号",
            );
            s.evidence
                .push(format!("较新版本对照：{}", related.relative));
            s.related_id = Some(related.id.clone());
        } else if newer.contains_key(&i) || copy_anchors.contains_key(&i) {
            set(
                &mut s,
                "keep",
                "对照保留项",
                "这是同组中版本较新或下载编号较少的一份，先留作核对依据。",
                "推荐保留不代表已证明它是最新版本、唯一原件或内容最完整。",
                "先保留这份，对照其他旧版本或疑似副本。",
                "中等：组内比较",
            );
        } else if kind == "installer" && age >= 30 {
            let android = item.name.to_lowercase().ends_with(".apk");
            set(
                &mut s,
                "cleanup",
                if android {
                    "Android 安装包，可核对清理"
                } else {
                    "较旧安装包，可核对清理"
                },
                if android {
                    "按 .apk 后缀判断，这是 Android 安装包，用于安卓设备安装或分发。"
                } else {
                    "安装包用于安装或重装；完成安装后，通常不参与应用的日常运行。"
                },
                "修改时间不等于最后使用时间；未检查安装状态、下载来源或离线重装需求。",
                if android {
                    "如果已不需要给安卓设备安装或分发，可考虑清理。"
                } else {
                    "确认已完成安装、无需重装或留存这个版本后，可考虑清理。"
                },
                "中等：类型与修改时间",
            );
        } else if kind == "installer" {
            set(
                &mut s,
                "keep",
                "近期安装包，先保留",
                "近期有修改记录，可能仍处于安装或测试阶段。",
                "修改时间不是下载时间或使用记录。",
                "完成安装或测试后，再决定是否需要保留安装包。",
                "中等：类型与修改时间",
            );
        } else if kind == "archive" {
            set(
                &mut s,
                "confirm",
                "压缩包，先确认是否已解压",
                "压缩包可能是安装分发包，也可能是项目、交接资料或唯一备份。",
                "未打开压缩包，也未检查解压后的内容是否完整。",
                "如果已完整解压且原包无备份价值，可考虑清理；项目或交接包建议归档。",
                "较低：未检查包内内容",
            );
        } else if ["document", "image", "video", "audio"].contains(&kind) && age >= 90 {
            set(
                &mut s,
                "archive",
                "较早资料，建议分类归档",
                "修改时间较早，适合从下载目录移入长期保存的位置，便于以后查找。",
                "没有证据说明资料已无用；照片、文档或素材可能只有这一份。",
                match kind {
                    "document" => "按项目或年份归入文档资料；不建议直接清理。",
                    "image" => "区分照片、截图与工作素材，按用途归档并保留原件。",
                    "video" => "确认所属项目，归档成片和源素材；不要只因体积大而清理。",
                    _ => "按录音、音乐或项目素材归档，确认有备份后再考虑处理。",
                },
                "中等：类型与修改时间",
            );
        } else if ["document", "image", "video", "audio"].contains(&kind) {
            set(
                &mut s,
                "keep",
                "近期资料，建议保留",
                "近期有修改记录，暂未发现可以清理的可靠依据。",
                "未判断内容价值，也没有证明另有副本。",
                "先保留，按项目或用途归类；以后再回顾是否需要归档。",
                "中等：类型与修改时间",
            );
        }
        items.push(s);
    }
    let specs = [
        ("cleanup", "建议清理"),
        ("archive", "建议归档"),
        ("protected", "重要资料"),
        ("keep", "建议保留"),
        ("confirm", "需要判断"),
    ];
    let groups = specs
        .iter()
        .map(|(id, label)| Group {
            id: (*id).into(),
            label: (*label).into(),
            count: items.iter().filter(|i| i.group == *id).count(),
            bytes: items
                .iter()
                .filter(|i| i.group == *id)
                .map(|i| i.bytes)
                .sum(),
        })
        .collect::<Vec<_>>();
    let mut categories = BTreeMap::<String, Group>::new();
    for i in &items {
        let g = categories.entry(i.category.clone()).or_insert(Group {
            id: i.category.clone(),
            label: i.category_label.clone(),
            count: 0,
            bytes: 0,
        });
        g.count += 1;
        g.bytes += i.bytes;
    }
    let mut categories = categories.into_values().collect::<Vec<_>>();
    categories.sort_by_key(|g| std::cmp::Reverse(g.bytes));
    items.sort_by(|a, b| {
        let rank = |s: &Suggestion| specs.iter().position(|(id, _)| *id == s.group).unwrap_or(5);
        rank(a)
            .cmp(&rank(b))
            .then(b.bytes.cmp(&a.bytes))
            .then(a.relative.cmp(&b.relative))
    });
    let headline = if groups[0].count > 0 {
        format!(
            "先核对 {} 个安装包或疑似下载副本；{} 项较早资料可归档，{} 项重要资料优先保留。",
            groups[0].count, groups[1].count, groups[2].count
        )
    } else {
        format!(
            "未发现明确的清理候选；{} 项资料可归档，{} 项重要资料优先保留。",
            groups[1].count, groups[2].count
        )
    };
    Advice {
        rules_version: "metadata-advice-v1",
        basis: "本地规则 · 依据名称、路径、类型与修改时间；未读取正文",
        headline,
        groups,
        categories,
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{Identity, Item};
    fn scan(entries: &[(&str, u64, i64)]) -> Scan {
        Scan {
            items: entries
                .iter()
                .enumerate()
                .map(|(i, (p, size, mtime))| Item {
                    id: i.to_string(),
                    name: Path::new(p).file_name().unwrap().to_str().unwrap().into(),
                    relative: (*p).into(),
                    bytes: *size,
                    reason: String::new(),
                    protected: false,
                    selected: false,
                    identity: Identity {
                        dev: 1,
                        ino: i as u64,
                        size: *size,
                        mtime: *mtime,
                        mtime_ns: 0,
                        ctime: 0,
                        ctime_ns: 0,
                        links: 1,
                    },
                })
                .collect(),
            complete: true,
            ..Default::default()
        }
    }
    #[test]
    fn sensitive_evidence_overrides_age_duplicates_and_size() {
        let s = scan(&[
            ("合同.dmg", 900_000_000, 0),
            ("合同 (1).dmg", 900_000_000, 0),
            ("客户交付/old.zip", 8, 0),
        ]);
        let a = analyze(&s, 200 * 86400);
        assert!(a
            .items
            .iter()
            .all(|i| i.group == "protected" && !i.can_consider_cleanup));
        assert!(a.items.iter().all(|i| i.decision == "none"));
    }
    #[test]
    fn modified_age_is_not_usage_and_large_documents_are_not_cleanup() {
        let a = analyze(
            &scan(&[
                ("movie.mp4", 8_000_000_000, 0),
                ("lesson.pdf", 2, 0),
                ("today.dmg", 3, 200 * 86400),
                ("unknown.bin", 9_000_000_000, 0),
            ]),
            200 * 86400,
        );
        assert!(a.items.iter().all(|i| !i.can_consider_cleanup));
        assert_eq!(
            a.items
                .iter()
                .find(|i| i.name == "movie.mp4")
                .unwrap()
                .group,
            "archive"
        );
        assert_eq!(
            a.items
                .iter()
                .find(|i| i.name == "today.dmg")
                .unwrap()
                .group,
            "keep"
        );
        assert_eq!(
            a.items
                .iter()
                .find(|i| i.name == "unknown.bin")
                .unwrap()
                .group,
            "confirm"
        );
    }
    #[test]
    fn duplicates_require_same_parent_normalized_name_and_size_and_keep_a_reference() {
        let a = analyze(
            &scan(&[
                ("Tool.dmg", 100, 0),
                ("Tool (1).dmg", 100, 0),
                ("Tool (2).dmg", 101, 0),
                ("sub/Tool (3).dmg", 100, 0),
            ]),
            10 * 86400,
        );
        let copies: Vec<_> = a
            .items
            .iter()
            .filter(|i| i.title.starts_with("疑似重复"))
            .collect();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].relative, "Tool (1).dmg");
        assert_eq!(copies[0].related_id.as_deref(), Some("0"));
        assert_eq!(a.items.iter().find(|i| i.id == "0").unwrap().group, "keep");
        assert!(copies[0].caution.contains("尚未核验内容"));
    }
    #[test]
    fn versions_compare_numbers_and_preserve_platform() {
        let a = analyze(
            &scan(&[
                ("Tool-arm64-5.9.0-aaaaaaa.dmg", 100, 0),
                ("Tool-arm64-5.10.0-bbbbbbb.dmg", 110, 0),
                ("Tool-x64-6.0.0-ccccccc.dmg", 111, 0),
            ]),
            10 * 86400,
        );
        let old = a.items.iter().find(|i| i.id == "0").unwrap();
        assert_eq!(old.related_id.as_deref(), Some("1"));
        assert_eq!(old.group, "cleanup");
        assert_eq!(a.items.iter().find(|i| i.id == "1").unwrap().group, "keep");
        assert_eq!(
            a.items.iter().find(|i| i.id == "2").unwrap().related_id,
            None
        );
    }
    #[test]
    fn summaries_partition_files_and_project_files_stay_out_of_cleanup() {
        let s = scan(&[
            ("app.apk", 100, 0),
            ("source/config.json", 30, 0),
            ("notes.xyz", 25, 0),
            ("old.zip", 50, 0),
        ]);
        let a = analyze(&s, 200 * 86400);
        assert_eq!(
            a.groups.iter().map(|g| g.count).sum::<usize>(),
            s.items.len()
        );
        assert_eq!(a.groups.iter().map(|g| g.bytes).sum::<u64>(), 205);
        assert!(a
            .items
            .iter()
            .find(|i| i.id == "0")
            .unwrap()
            .explanation
            .contains("Android"));
        assert_eq!(a.items.iter().find(|i| i.id == "1").unwrap().group, "keep");
        assert_eq!(
            a.items.iter().find(|i| i.id == "3").unwrap().group,
            "confirm"
        );
        assert!(a.items.iter().all(|i| !i.explanation.is_empty()
            && !i.evidence.is_empty()
            && !i.caution.is_empty()
            && !i.next_step.is_empty()));
    }
    #[test]
    fn english_risk_keywords_require_word_boundaries() {
        assert!(keyword_match("client/notes.pdf", "client"));
        assert!(!keyword_match("application.dmg", "cat"));
        assert!(!keyword_match("opencv.zip", "cv"));
    }
    #[test]
    fn executable_is_not_assumed_disposable_and_handoff_or_resume_names_are_protected() {
        let a = analyze(
            &scan(&[
                ("Portable Tool.exe", 100, 0),
                ("Example交接.zip", 100, 0),
                ("【测试岗位】样本 2年.pdf", 100, 0),
            ]),
            200 * 86400,
        );
        assert!(a.items.iter().all(|i| !i.can_consider_cleanup));
        assert_eq!(
            a.items.iter().find(|i| i.id == "0").unwrap().group,
            "confirm"
        );
        assert!(a
            .items
            .iter()
            .filter(|i| i.id != "0")
            .all(|i| i.group == "protected"));
    }
}
