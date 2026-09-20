# 构建与验证工具

从仓库根目录执行。原生 Mac 只读构建见 [desktop](../desktop/README.md)。

| 脚本 | 用途 |
| --- | --- |
| mac001_build.py | 独立的 Downloads 只读应用，或临时 fixture 平台实验 |
| check_all.py | Python、API 约束、安全边界、临时样本流程、前端测试与构建 |
| smoke_test.py | 临时样本扫描、预览、隔离与恢复 |
| inventory_api_smoke.py | 受控 fixture 的快照、规则/fake 报告、XLSX 与收据 |
| iteration4_synthetic_provider_smoke.py | 离线 consent、预算、缓存、降级与重启实验 |
| iteration5_scale_benchmark.py | 确定性 synthetic metadata 的规模与恢复实验 |
| windows_acceptance.py | Windows 原生文件属性、路径、隔离与恢复检查 |
| iteration6_windows_office_acceptance.py | Windows 报告与 Excel/WPS 人工验收材料 |

```bash
uv sync --locked
npm ci --prefix ui
uv run python scripts/check_all.py
```

Windows 专项脚本在其他平台会明确返回所需平台，不伪造通过。GitHub Windows runner 的
检查不能替代 Windows 11 用户设备或 Excel/WPS 的人工打开验证。所有文件动作测试使用
脚本自己创建的临时样本，产物放在被忽略的 output 目录。
