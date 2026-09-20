# 原生 Mac 开发说明

空间透视采用 AppKit 窗口与 Rust 状态层。当前面向体验的是 Downloads 只读建议构建，
分类规则位于 `src/advice.rs`，不会调用模型、读取正文或处理真实文件。

## 构建并打开只读预览

需要 macOS 13+、Xcode Command Line Tools、Rust stable、Python 3.12+。
已在 Apple Silicon Mac 本地验证；Intel Mac 尚未单独验收。
从仓库根目录运行：

```bash
cargo fetch --locked --manifest-path desktop/Cargo.toml
python3 scripts/mac001_build.py --build --read-only-downloads
open "output/mac-001-native-20260919/downloads-read-only/Space Perspective Read Only.app"
```

构建器会登记当前账号的 Downloads 路径，生成独立 app bundle，并使用 ad-hoc 本地签名。
它不适合复制给另一个账号或另一台机器使用，也不是 Developer ID 签名、公证的正式分发包。
界面目前为中文。系统选择器只接受已登记的 Downloads 根目录。

首页按建议分为清理、归档、重要、保留、待判断五组，可继续按文件类型筛选。
点开一项可看用途线索、原因、证据、确认条件和下一步。记为保留与加入预览只改变内存状态，
没有执行入口；退出或重新选择范围会清除决定。

结束访问会比较扫描前后的文件路径与身份属性，结果保留在窗口；这不代表正文完整性核验。
文件明细不落盘，汇总与状态记录保存在独立 sandbox container 的应用数据目录。

## 编译时文件边界

`read-only-downloads` 替换默认状态层为 `src/read_only.rs`。最终应用不链接 `sp_trash`
或 `renameatx_np`；构建器同时检查无 WebKit、无 helper、无网络或用户文件读写 entitlement。
详见[隐私边界](../docs/privacy-invariants.md)与[架构](../docs/architecture.md)。

## 验证

```bash
cargo test --locked --manifest-path desktop/Cargo.toml --features read-only-downloads
cargo clippy --locked --manifest-path desktop/Cargo.toml --features read-only-downloads --all-targets -- -D warnings
cargo test --locked --manifest-path desktop/Cargo.toml
```

## 单独的 fixture 平台实验

默认构建用于平台能力验证，只接受构建器创建的临时样本范围，不接受真实用户目录。
它会测试单文件 Trash、收据和恢复，但延迟与重启后的 ctime 漂移仍可能拒绝恢复。
这条路径尚未通过完整验收，不能向真实文件处理开放。

```bash
# 只创建新临时样本；重复 prepare 会拒绝覆盖已有登记
python3 scripts/mac001_build.py --prepare
python3 scripts/mac001_build.py --build
```

临时样本创建于 /Users/Shared/space-perspective-mac001-<UUID>，配置与产物均在忽略目录。
不得移除范围、漂移、同名冲突或未解决收据检查来绕过恢复问题。
