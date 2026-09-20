# 安全问题报告

当前仅提供开发预览，尚无受支持的稳定发行版。请通过本仓库的
[GitHub 私密漏洞报告](https://github.com/fy-agent/space-perspective/security/advisories/new)
报告越权读取、敏感日志、文件丢失或恢复缺陷，不要把漏洞细节和私人文件放入公开 Issue。

报告请包含：提交版本、操作系统、预期与实际行为，以及可以用虚构文件复现的最小步骤。
如果问题影响文件状态，请保留原始记录，停止继续处理受影响文件。

原生 Downloads 入口的承诺是：系统选择器授权、只读元数据、无正文读取、无网络与真实文件
动作。Python Core 与原生 fixture 工具是独立开发入口，权限范围见
[隐私与文件边界](docs/privacy-invariants.md)。
