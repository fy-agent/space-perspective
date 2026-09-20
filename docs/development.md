# 本地开发与验证

普通体验从 [README 的 Mac 只读构建](../README.md#快速开始)开始。下面的工作台和 fixture
入口用于开发，不作为真实文件清理工具使用。

## 工具链

- 原生 Mac：macOS 13+、Xcode Command Line Tools、Rust stable、Python 3.12+。
- Core / Web：Python 3.12+、uv、Node.js 20.19+ 和 npm。
- 依赖版本由 desktop/Cargo.lock、uv.lock 和 ui/package-lock.json 锁定。

## Core 与 Web 工作台

```bash
uv sync --locked
npm ci --prefix ui

# 终端 1
uv run uvicorn core.app.main:app --host 127.0.0.1 --port 8765

# 终端 2
npm --prefix ui run dev -- --host 127.0.0.1 --port 5173
```

打开 http://127.0.0.1:5173。默认“空间报告”运行受控 fixture，没有真实目录选择。
fake provider 与 synthetic consent 只演练本地协议，不调用真实模型或云服务。
Core 数据库可通过 DATA_BUTLER_DB_PATH 指向独立测试位置。

如需演示旧工作台的扫描与文件操作，请先阅读 [fixtures 说明](../fixtures/README.md)，
只对测试创建的临时副本操作。不要把用户真实目录用于隔离或恢复测试。

## 检查

在 Mac 上验证原生两种入口：

```bash
cargo test --locked --manifest-path desktop/Cargo.toml --features read-only-downloads
cargo clippy --locked --manifest-path desktop/Cargo.toml --features read-only-downloads --all-targets -- -D warnings
cargo test --locked --manifest-path desktop/Cargo.toml
```

安装 Core 与 Web 依赖后：

```bash
uv run python scripts/check_all.py
```

该命令包含 Python 测试、OpenAPI 约束、安全边界、临时样本业务流程、前端测试和构建。
报告与 Windows 平台的专项脚本见 [scripts](../scripts/README.md)。

GitHub Actions 的 Mac 检查验证源码、构建和权限声明；Windows 检查验证 Core 平台行为。
它们不代表用户验收、签名公证发行或 Windows 11/Office 的人工打开检查。

## 仓库结构

```text
desktop/      原生 Mac 窗口、Rust 状态层与规则
core/         本地 API、SQLite、扫描、报告和操作实验
ui/           React 开发工作台
shared/       OpenAPI 与 JSON Schema
fixtures/     人工构造的无敏感样本
tests/        跨模块与文件边界检查
scripts/      构建、验证、临时样本工具
docs/         产品范围、架构、隐私与开发文档
```

本地配置、运行日志、测试输出与私人工作记录不进入公开仓库。发布截图只能使用明确授权的
公开数据或虚构样例，不提交 Downloads 文件清单。
