# 架构与能力范围

空间透视把“发现事实、产生建议、用户决定、执行动作”分开。当前公开仓库包含三个入口，
它们的验证进度与文件权限不同。

| 入口 | 实现 | 当前用途 |
| --- | --- | --- |
| 原生 Downloads 预览 | AppKit + Rust，read-only-downloads feature | 系统选择器、只读元数据、五类建议、内存决定与不执行的预览 |
| 原生平台实验 | AppKit + Rust，默认 fixture 构建 | 在注册的临时样本目录验证 Trash、收据和恢复；恢复尚有阻塞 |
| 本地开发工作台 | React + FastAPI + SQLite | 研究资产索引、精确去重、建议、隔离收据、报告与受控 fake provider |

## 原生建议的数据流

```text
AppKit 系统目录选择器
    ↓ 只读 bookmark / 范围身份
Rust 元数据扫描器（scope.rs）
    ↓ 文件名、相对路径、类型、大小、修改时间
本地建议规则（advice.rs）
    ↓ 五类建议 / 原因 / 证据 / 条件 / 对照文件
只读状态层（read_only.rs）
    ↓ 本轮保留与预览决定
AppKit 窗口（window.m）
```

read-only-downloads 在编译时替换默认状态层，避免只靠隐藏按钮阻止文件动作。
此构建不连接 Trash 或 Rust restore 后端；签名声明只有 sandbox、用户选择的只读文件访问、
app-scoped bookmark。文件动作命令不会被分发到实现。

扫描与建议不打开正文、不计算内容 hash、不联网。文件明细只在内存，应用数据目录中的
记录只有汇总与状态。重新扫描时，只有路径与完整文件身份仍匹配的本轮决定才会保留。

## 规则如何保持可解释

规则先检查重要资料线索，再判断程序、项目文件、疑似编号副本、安装包版本和资料年龄。
版本与副本只在同一目录内比较；平台和渠道标记保留。相同大小不证明内容相同，
修改时间不证明文件已无用。每项结果包含证据、置信说明和用户仍需确认的条件。

## Core 与 Web 工作台

core 提供本地 HTTP API、SQLite 索引、文件元数据采集、精确 hash 去重、建议、
隔离操作与收据，以及结构化 XLSX 报告实验。shared 保存 OpenAPI 和 JSON Schema，
ui 是对应的开发工作台。

Web 默认报告页只使用仓库内受控 fixture；fake provider 是离线测试替身。
其他开发页面包含文件操作入口，测试必须使用临时样本；它们不是原生 Downloads 预览的权限。

## 尚未完成的部分

Mac Trash 在延迟或进程重启后可能产生 ctime 漂移，严格身份检查会拒绝恢复。
该问题仍阻止真实文件处理开放，不能通过移除漂移检查来宣称解决。
正文理解、OCR、已安装软件核验、原生精确去重、签名公证与 Windows 桌面版尚未交付。

[开发与检查](development.md) · [产品路线](roadmap.md) · [隐私边界](privacy-invariants.md)
