# 本地 Core 开发服务

FastAPI + SQLite 提供资产索引、扫描、精确内容去重、风险建议、操作计划、隔离收据、
撤销及结构化报告实验。这是开发工作台后端，能力范围不同于原生 Downloads 只读入口。

从仓库根目录运行：

```bash
uv sync --locked
uv run uvicorn core.app.main:app --host 127.0.0.1 --port 8765
```

API 契约见 [shared/openapi.yaml](../shared/openapi.yaml) 和
[接口说明](../docs/api-contract.md)。可用 DATA_BUTLER_DB_PATH 指向独立测试数据库；
默认数据库保存在系统应用数据目录，不写入扫描范围。

报告默认使用受控 fixture，fake provider 不调用真实模型。隔离、恢复和真实路径扫描仅供
开发验证，请使用测试自己创建的临时样例。完整[开发指南](../docs/development.md)与
[文件边界](../docs/privacy-invariants.md)说明了各入口区别。
