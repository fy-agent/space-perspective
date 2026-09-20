# 安全测试样本

本目录只定义人工构造的无敏感样本，不读取或复制任何用户文件。

生成样本：

```bash
uv run python fixtures/generate.py
```

默认输出到 `fixtures/generated/demo-corpus/`。脚本会生成：

- 两个内容相同但路径不同的精确重复文件；
- 同名但内容不同的误判保护样本；
- Downloads、Desktop、Documents、Pictures、WeChat Files 等目录结构；
- 仅文件名带“合同 / 发票 / 家庭照片”等风险关键词的占位样本；
- 小文件形式的大文件占位，以及单独的模拟大小记录；
- `manifest.json`，记录每个样本的 hash、大小和预期重复组。

所有移动或回滚测试必须先把这些样本复制到临时目录，不能在仓库样本或用户真实目录中执行。
