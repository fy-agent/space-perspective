# 空间透视 · Core 开发接口

本页说明 Python Core 与 React 开发工作台的接口，不是原生 Downloads 只读入口的权限。
机器可读契约见 [shared/openapi.yaml](../shared/openapi.yaml)，各入口区别见[架构](architecture.md)。

Core 包含 18 个文件治理接口，以及 10 个受控 fixture 报告接口。报告域仅接受固定 standard
样本、inventory_metadata 与 none/fake provider；不接受真实目录输入，不连接真实模型。
cloud_metadata_minimized 目前也只是 share_safe + fake 的离线 consent 协议实验，
真实云端能力保持关闭。下文保留实现中的阶段名，便于对应测试与协议版本。

## 一、契约原则

1. 前端不能直接凭路径执行文件动作；路径只能展示，文件动作必须使用 `asset_id`、`suggestion_id` 或 `operation_plan_id`。
2. 执行动作必须基于 `operation_plan_id`。
3. `POST /operations/execute` 必须带 `confirm=true`。
4. `permanent_delete` 不进入第一版契约，任何动作枚举都不包含它。
5. 高风险文件必须 `default_selected=false`。
6. 每条 `Suggestion` 必须包含 `reason`、`evidence`、`risk_level`、`proposed_action`、`reversible`。
7. 所有大小字段使用 bytes 整数，字段名使用 `*_bytes`。
8. 所有时间字段使用 ISO 8601 字符串。
9. SSE 事件使用 `ScanEvent` 结构，通过 `event: scan_event` 和 JSON `data` 传递。
10. mock provider 只服务前端联调，不能表示真实上传能力。
11. 文件上传能力与最小化元数据分析能力必须拆分；`file_upload_enabled=false` 永远不能被云分析开关覆盖。

### 报告域冻结路径（迭代 2 实现）

```text
POST /v1/inventory/scans
GET  /v1/inventory/scans/{scan_id}
POST /v1/inventory/snapshots
GET  /v1/inventory/snapshots/{snapshot_id}
POST /v1/inventory/analysis-packets/preview
POST /v1/inventory/analyses
GET  /v1/inventory/analyses/{analysis_id}
POST /v1/inventory/reports
GET  /v1/inventory/reports/{report_id}
GET  /v1/inventory/reports/{report_id}/download
```

这些路径只允许 additive 实现。旧 `/scan` 等 18 条 P0 paths 不删除、不改名，省略 profile 的旧行为保持不变。

## 二、接口说明

| 接口 | 用途 | 是否改变文件 | 安全检查 | 前端使用方式 | 第一版状态 |
|---|---|---:|---|---|---|
| `GET /health` | 检查本地 Core 服务、数据库状态和能力开关 | 否 | 必须返回 `real_upload_enabled=false`；契约不提供永久删除能力开关或动作 | 启动页或工作台初始化时调用 | P0 |
| `POST /scan` | 创建本地只读扫描任务 | 否 | 只接受用户授权目录；不得触发移动、删除、上传 | 用户选择目录后调用 | P0 |
| `GET /scan/{scan_session_id}` | 查询扫描状态 | 否 | 只能读取 scan session | 轮询状态或恢复页面状态 | P0 |
| `GET /scan/{scan_session_id}/stream` | 获取扫描进度 SSE | 否 | 事件 payload 必须匹配 `ScanEvent`；不得携带文件内容 | 扫描进度条和实时日志 | P0 |
| `POST /scan/{scan_session_id}/cancel` | 取消扫描任务 | 否 | 只更新扫描状态，不改文件 | 用户点击取消扫描 | P0 |
| `GET /assets` | 查询资产列表 | 否 | 路径仅展示，不可作为执行权限 | 体检报告、列表筛选、大文件页 | P0 |
| `GET /assets/{asset_id}` | 查看单个资产和元数据 | 否 | 不返回原文件内容 | 详情抽屉或证据查看 | P0 |
| `GET /fileintel/overview` | 获取体检报告聚合 | 否 | 只读数据库聚合 | 体检报告首页 | P0 |
| `GET /dups` | 查询精确重复组 | 否 | P0 只返回 `kind=exact` | 重复文件页 | P0 |
| `GET /suggestions` | 查询可解释建议 | 否 | 高风险建议必须 `default_selected=false` | AI 建议页、低风险全选 | P0 |
| `POST /operations/preview` | 创建操作预览和 plan | 否 | 只能用 `asset_ids` 或 `suggestion_ids`；不能用路径作为动作权限 | 用户点击批量处理前调用 | P0 |
| `POST /operations/execute` | 执行用户确认过的 plan | 是，只能进入 quarantine 或元数据忽略 | 必须有 `operation_plan_id`、`confirm=true`、plan 未过期、可回滚 | 用户在预览页确认后调用 | P0 |
| `GET /operations` | 查询操作收据列表 | 否 | 只读收据 | 操作历史页 | P0 |
| `GET /operations/{operation_id}` | 查看操作收据详情 | 否 | 只读收据和文件级结果 | 收据详情页、回滚入口 | P0 |
| `POST /operations/{operation_id}/undo` | 回滚一次可逆操作 | 是，只能从 quarantine 恢复 | 必须基于 receipt；遇到同名冲突不覆盖 | 用户点击一键回滚 | P0 |
| `GET /quarantine` | 查询隔离区文件 | 否 | 只读 quarantine 索引 | 隔离区页面 | P0 |
| `GET /providers` | 查询 Provider 能力 | 否 | P0 只能返回本地规则或 mock；不得返回真实上传能力 | UI 决定是否展示 mock 分析入口 | P0 stub |
| `POST /providers/mock/analyze` | 本地 mock 分析，辅助前端联调 | 否 | 不得上传；不得读远端服务；不得接收文件 bytes | 原型页或测试数据演示 | P0 stub |
| `POST/GET /v1/inventory/scans[/{scan_id}]` | 创建或读取固定 fixture 盘点 | 否 | 只接受 `standard + inventory_metadata + compute_hash=false` | 迭代 3 UI 的盘点入口 | 迭代 2 API / 迭代 3 UI |
| `POST/GET /v1/inventory/snapshots[/{snapshot_id}]` | 幂等发布或读取 canonical snapshot | 否 | 不重新扫描真实范围 | 报告链上游 | 迭代 2 API / 迭代 3 UI |
| `POST /v1/inventory/analysis-packets/preview` | 构建并持久化 local_full/share_safe packet；synthetic preset 返回 server-declared offer | 否 | `none|local_only|cloud_metadata_minimized`；第三种只允许 share-safe、privacy lint 和受控预算 | 分析预览与 consent 前披露 | 迭代 2 API / 迭代 3 UI / 迭代 4A |
| `POST/GET /v1/inventory/analyses[/{analysis_id}]` | 执行或读取 none/fake 分析、model receipt 与可选 consent receipt | 否 | `provider=none|fake`；synthetic 必须完整绑定并原子预留；网络调用为 0 | 报告分析 | 迭代 2 API / 迭代 3 UI / 迭代 4A |
| `POST/GET /v1/inventory/reports[/{report_id}]` | 生成或读取已验证五表 XLSX manifest | 只写应用报告目录 | 校验 snapshot→packet→analysis lineage | 报告状态 | 迭代 2 API / 迭代 3 UI |
| `GET /v1/inventory/reports/{report_id}/download` | 按 report ID 下载 XLSX | 否 | 服务端派生路径、拒绝 symlink/越界、下载前复核 SHA-256 | 报告下载 | 迭代 2 API / 迭代 3 UI |

## 三、关键流程

### 1. 扫描流程

1. 前端让用户选择授权目录。
2. 前端调用 `POST /scan`，传入 `paths`。
3. 后端创建 `ScanSession`，只读扫描目录。
4. 前端通过 `GET /scan/{id}/stream` 展示进度，或通过 `GET /scan/{id}` 轮询。
5. 扫描完成后，前端读取 `/fileintel/overview`、`/assets`、`/dups`、`/suggestions`。

安全要求：扫描流程不得改变文件，不得上传文件，不得解析微信聊天数据库。

### 2. 建议与预览流程

1. 前端通过 `GET /suggestions` 获取建议。
2. 前端默认只能勾选 `default_selected=true` 的低风险建议。
3. 用户选择后，前端调用 `POST /operations/preview`。
4. 请求体只能包含 `asset_ids` 或 `suggestion_ids`，不能传路径作为执行依据。
5. 后端返回 `OperationPlan`，包含汇总、风险、文件项和 warnings。

安全要求：preview 不改变文件；高风险文件默认不进入全选。

### 3. 执行流程

1. 用户在预览页确认。
2. 前端调用 `POST /operations/execute`。
3. 请求必须包含 `operation_plan_id`、`confirm=true`、`client_seen_plan_version`。
4. 后端复查 plan、文件状态和安全规则。
5. 后端只能执行 `quarantine` 或 `mark_ignored`。
6. 后端返回 `OperationReceipt`。

安全要求：没有 plan 不执行；没有 confirm 不执行；不支持 `permanent_delete`。

### 4. 回滚流程

1. 前端通过 `GET /operations` 或 `GET /operations/{operation_id}` 找到收据。
2. 前端调用 `POST /operations/{operation_id}/undo`，传 `confirm=true`。
3. 后端基于 receipt 和 quarantine item 恢复。
4. 如果原路径有同名文件，必须失败该文件并提示，不得覆盖。

安全要求：undo 必须基于 receipt；无 receipt 不回滚。

### 5. fixture-only 报告 API 流程

1. `POST /v1/inventory/scans` 请求体精确为
   `standard + inventory_metadata + compute_hash=false`，随后 GET 回读 scan。
2. `POST /v1/inventory/snapshots` 幂等返回已物化 snapshot，随后 GET 回读。
3. `POST /v1/inventory/analysis-packets/preview` 可选择
   `local_full + none`、`share_safe + local_only` 或
   `share_safe + cloud_metadata_minimized`。第三种返回 packet/字段、固定
   Provider/model、版本、预算和零网络/零外部计费披露；share-safe lint 失败时不签发
   offer/consent。切换 preset 必须使旧 packet、consent、analysis 和 report 失效。
4. `POST /v1/inventory/analyses` 仍只选择 `none` 或 `fake`。第三种 preset 额外携带
   完整版本化 `consent`，绑定 snapshot/packet/SHA/bytes、Provider/model、预算和版本；
   receipt 先 `reserved`，完成后 `consumed`。同 action 重试回读原结果；中断遗留的
   reserved action 返回 `ANALYSIS_CONSENT_IN_PROGRESS`，不得再次调用 Provider。
5. 新 consent + 相同 packet 可命中产品缓存，Provider 调用为 0；
   `max_provider_calls=1` 表示 primary call，最多一次 schema retry 单列，因此总
   attempts 最多 2。synthetic cost 固定为 0，非零请求在 schema 层拒绝。
6. `POST /v1/inventory/reports` 校验完整 lineage 后生成、重载并 hash XLSX，
   随后 GET 回读。
7. download 客户端只接受同源 `/v1/inventory/reports/{id}/download`，拒绝 query、
   fragment、userinfo 和非 XLSX MIME；客户端不能传磁盘路径。

迭代 4A 仍只证明 fixture E2E。真实 Provider 属于 4B 且
`BLOCKED_NOT_AUTHORIZED`；异步取消/恢复属于迭代 5。

## 四、SSE 事件结构

`GET /scan/{scan_session_id}/stream` 使用 `text/event-stream`。

事件格式：

```text
event: scan_event
data: {"event_id":"evt_001","scan_session_id":"scan_001","type":"progress","occurred_at":"2026-06-17T10:00:00Z","current_path":"C:\\Users\\me\\Downloads","files_seen":120,"files_indexed":118,"files_skipped":2,"bytes_seen":1048576}
```

`data` JSON 必须匹配 `ScanEvent` schema。`type` 只能是：

- `started`
- `progress`
- `skipped`
- `completed`
- `cancelled`
- `failed`

SSE 事件不得携带文件内容、缩略图、OCR 文本或 embedding。

## 五、stub 接口

第一版只有以下 stub：

| 接口 | stub 行为 | 不允许做什么 |
|---|---|---|
| `GET /providers` | 返回本地规则 provider 和 mock provider 能力 | 不得宣称真实云端上传能力 |
| `POST /providers/mock/analyze` | 返回本地 mock 文本，用于前端联调 | 不得上传文件，不得调用远端服务，不得接收文件 bytes |

OCR、自然语言搜索、相似图片、相似文档、人脸、成品相册、真实云增强、真实支付、SMB 后台都不进入第一版契约。

## 六、错误约定

所有错误使用 `ErrorResponse`：

- `code`：机器可读错误码。
- `message`：用户或前端可展示的短说明。
- `details`：可选结构化信息。
- `request_id`：可选请求 ID。

建议错误码：

- `SCAN_PATH_NOT_AUTHORIZED`
- `SCAN_SESSION_NOT_FOUND`
- `ASSET_NOT_FOUND`
- `OPERATION_PLAN_REQUIRED`
- `OPERATION_CONFIRM_REQUIRED`
- `OPERATION_PLAN_EXPIRED`
- `HIGH_RISK_DEFAULT_SELECTION_FORBIDDEN`
- `QUARANTINE_FAILED`
- `UNDO_CONFLICT`
- `PROVIDER_REAL_UPLOAD_DISABLED`
- `INVENTORY_SCAN_NOT_FOUND`
- `SNAPSHOT_NOT_FOUND`
- `ANALYSIS_PACKET_NOT_FOUND`
- `ANALYSIS_CONSENT_REQUIRED`
- `ANALYSIS_CONSENT_NOT_APPLICABLE`
- `ANALYSIS_CONSENT_MISMATCH`
- `ANALYSIS_CONSENT_REUSED`
- `ANALYSIS_CONSENT_IN_PROGRESS`
- `SYNTHETIC_PRIVACY_MODE_MISMATCH`
- `SYNTHETIC_PRIVACY_LINT_FAILED`
- `ANALYSIS_NOT_FOUND`
- `REPORT_LINEAGE_MISMATCH`
- `REPORT_NOT_FOUND`
- `REPORT_ARTIFACT_MISSING`
- `REPORT_ARTIFACT_HASH_MISMATCH`

## 七、前端使用注意

1. 展示路径可以使用 `abs_path` 或 `display_path`，但不得把路径传回后端作为动作权限。
2. 批量处理入口必须先调 `/operations/preview`。
3. 只有用户确认后才能调 `/operations/execute`。
4. `execute` 请求里的 `confirm` 必须是 `true`。
5. 高风险建议即使展示，也不能默认勾选。
6. 对 `providers/mock/analyze` 的结果必须标注为 mock，不得暗示真实 AI 云增强。
7. `/health` 的 `file_upload_enabled=false`、
   `cloud_metadata_analysis_available=false` 和
   `cloud_metadata_analysis_enabled=false` 表示没有文件上传或真实云分析；
   `controlled_synthetic_consent_available=true` 只表示 4A 离线 fake 门禁可用。兼容字段
   `real_upload_enabled=false` 继续保留。
8. 契约没有永久删除动作，UI 不得展示永久删除入口。
9. 默认报告页不得收集 path/scope，只能发固定 fixture 请求；`fake` 必须明示为本地模拟。
10. 报告页不得展示文件动作控件，进入该页时必须清除旧 P0 plan/receipt。
11. preset 切换与 Core 传输失败必须使下游 lineage 失效；旧异步响应不得回写新状态。
12. synthetic checkbox 必须默认未选；客户端 consent ID 使用冻结 UUID 形态，不得把
    路径、secret、用户自由文本或公式字符写入 receipt。
