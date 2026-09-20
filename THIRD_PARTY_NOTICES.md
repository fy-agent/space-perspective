# 第三方依赖说明

空间透视自身源码与本项目绘制的图形按根目录 MIT 许可证发布。依赖包不因本项目的授权而
改变许可；第三方版权、许可全文与 NOTICE 以对应版本的上游分发包为准。

本次公开的是源码，不包含 node_modules、Python 虚拟环境、Rust registry 源码或预编译应用。
后续分发二进制时，需要同时打包该构建实际包含的依赖版权与许可文本。

## 直接运行依赖

| 组件 | 当前版本 | 上游声明 |
| --- | --- | --- |
| fastapi | 0.139.0 | MIT |
| openpyxl | 3.1.5 | MIT |
| uvicorn | 0.51.0 | BSD-3-Clause |
| react | 19.2.7 | MIT |
| react-dom | 19.2.7 | MIT |

Python 完整解析版本见 [uv.lock](uv.lock)，Web 与构建工具版本见
[ui/package-lock.json](ui/package-lock.json)。元数据来自本次锁定安装的包声明。

## Rust 锁定依赖

以下包含目标平台或构建条件下可能使用的传递依赖；并非每项都会进入 Mac 可执行文件。

| 组件 | 版本 | 上游声明 |
| --- | --- | --- |
| [bumpalo](https://github.com/fitzgen/bumpalo) | 3.20.3 | MIT OR Apache-2.0 |
| [cc](https://github.com/rust-lang/cc-rs) | 1.4.6 | MIT OR Apache-2.0 |
| [cfg-if](https://github.com/rust-lang/cfg-if) | 1.0.4 | MIT OR Apache-2.0 |
| [find-msvc-tools](https://github.com/rust-lang/cc-rs) | 0.1.12 | MIT OR Apache-2.0 |
| [futures-core](https://github.com/rust-lang/futures-rs) | 0.3.34 | MIT OR Apache-2.0 |
| [futures-task](https://github.com/rust-lang/futures-rs) | 0.3.34 | MIT OR Apache-2.0 |
| [futures-util](https://github.com/rust-lang/futures-rs) | 0.3.34 | MIT OR Apache-2.0 |
| [getrandom](https://github.com/rust-random/getrandom) | 0.4.3 | MIT OR Apache-2.0 |
| [itoa](https://github.com/dtolnay/itoa) | 1.0.18 | MIT OR Apache-2.0 |
| [js-sys](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) | 0.3.105 | MIT OR Apache-2.0 |
| [libc](https://github.com/rust-lang/libc) | 0.2.189 | MIT OR Apache-2.0 |
| [memchr](https://github.com/BurntSushi/memchr) | 2.8.3 | Unlicense OR MIT |
| [once_cell](https://github.com/matklad/once_cell) | 1.21.4 | MIT OR Apache-2.0 |
| [pin-project-lite](https://github.com/taiki-e/pin-project-lite) | 0.2.17 | Apache-2.0 OR MIT |
| [proc-macro2](https://github.com/dtolnay/proc-macro2) | 1.0.107 | MIT OR Apache-2.0 |
| [quote](https://github.com/dtolnay/quote) | 1.0.47 | MIT OR Apache-2.0 |
| [r-efi](https://github.com/r-efi/r-efi) | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| [rustversion](https://github.com/dtolnay/rustversion) | 1.0.23 | MIT OR Apache-2.0 |
| [serde](https://github.com/serde-rs/serde) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_core](https://github.com/serde-rs/serde) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_derive](https://github.com/serde-rs/serde) | 1.0.229 | MIT OR Apache-2.0 |
| [serde_json](https://github.com/serde-rs/json) | 1.0.151 | MIT OR Apache-2.0 |
| [shlex](https://github.com/comex/rust-shlex) | 2.0.1 | MIT OR Apache-2.0 |
| [slab](https://github.com/tokio-rs/slab) | 0.4.12 | MIT |
| [syn](https://github.com/dtolnay/syn) | 3.0.5 | MIT OR Apache-2.0 |
| [unicode-ident](https://github.com/dtolnay/unicode-ident) | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| [uuid](https://github.com/uuid-rs/uuid) | 1.26.1 | Apache-2.0 OR MIT |
| [wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen) | 0.2.128 | MIT OR Apache-2.0 |
| [wasm-bindgen-macro](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro) | 0.2.128 | MIT OR Apache-2.0 |
| [wasm-bindgen-macro-support](https://github.com/wasm-bindgen/wasm-bindgen/tree/main/crates/macro-support) | 0.2.128 | MIT OR Apache-2.0 |
| [wasm-bindgen-shared](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared) | 0.2.128 | MIT OR Apache-2.0 |
| [zmij](https://github.com/dtolnay/zmij) | 1.0.23 | MIT |

版本来源：[desktop/Cargo.lock](desktop/Cargo.lock)。Rust 依赖许可来自对应 crate 的元数据；
OR 与 AND 表达式按上游许可声明保留，不改写成单一 MIT。

## 系统与视觉资源

AppKit、Foundation 等为 macOS 系统框架，由系统提供。本仓库不重分发 Apple SDK 或字体。
应用图标与 README SVG 为项目自有图形；README 插画使用虚构文件，不含真实下载清单。
参考了 fy-agent 组织 README 的信息组织方式，没有复制其他项目的代码、品牌图形或许可证。
