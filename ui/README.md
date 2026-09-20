# React 开发工作台

工作台连接本机 Core。默认“空间报告”只使用固定 fixture，展示分类、占用、规则报告与 XLSX
导出。fake provider 和 synthetic consent 是离线协议实验，不代表真实 AI 分析或上传。

旧体检总览、重复文件、整理建议、隔离区与收据页面仍供开发者验证内核流程，文件操作只能
使用测试创建的临时副本。这不是原生 Mac Downloads 预览界面。

从仓库根目录启动 Core 后，在本目录运行：

```bash
npm ci
npm run dev -- --host 127.0.0.1
```

默认连接 http://127.0.0.1:8765，可通过 VITE_CORE_API_URL 指向另一个本地 Core 地址。

```bash
npm test
npm run build
```

详见[开发指南](../docs/development.md)与[产品路线](../docs/roadmap.md)。
