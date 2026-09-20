<div align="center">
  <img src="desktop/icons/source.svg" width="88" alt="Space Perspective icon">
  <h1>Space Perspective · 空间透视</h1>
  <p><strong>Understand your files. Decide what stays.</strong></p>
  <p>A local-first file organization assistant from <a href="https://github.com/fy-agent">fy-agent</a>.</p>
  <p><a href="README.md">简体中文</a> · <a href="LICENSE">MIT License</a> · <a href="CONTRIBUTING.md">Contribute</a></p>
</div>

<p align="center"><img src="docs/assets/overview.svg" width="100%" alt="Illustration of files becoming explainable cleanup, archive and keep suggestions; all examples are fictional"></p>

## What is it for?

A Downloads folder can contain old installers, repeated attachments, important work, and files whose
purpose is no longer obvious. Space Perspective helps answer: **What is this? Why keep it? What should
I check before removing it?**

The goal is an explainable workflow from discovery and classification to suggestions, preview, and
eventually recoverable file operations. The current native Mac preview covers discovery through preview.

> **Early developer preview.** The native app reads metadata in your explicitly selected Downloads
> folder. It does not read file contents, hash contents, connect to the network, move files, or delete
> files. No signed and notarized distribution is available yet. The current interface is in Chinese.

## What works today

| Suggestion group | What it explains |
| --- | --- |
| Cleanup candidates | Older installers and possible numbered download copies that need checking |
| Archive | Older documents and media worth organizing by project or purpose |
| Important | Name or path clues suggesting contracts, finance, recruitment or handover material |
| Keep | Newer reference installers, comparison files, source code and configuration |
| Needs judgment | Unknown purpose, archives with unverified contents, and executable programs |

Each item provides its likely type or purpose, reasoning, evidence, caveats, and a suggested next step.
You can filter by file type, mark an item to keep, or add a candidate to a non-executing cleanup preview.
Decisions are kept in memory for the current session only.

Same-size numbered copies are **possible duplicates**, not verified exact matches. Modification time is
not last-use time, and candidate size is not confirmed reclaimable space.

## Build the native preview

Prerequisites: macOS 13+, Xcode Command Line Tools, stable Rust, and Python 3.12+.
Local runtime verification currently covers Apple Silicon; Intel Macs have not been separately accepted.
Dependency installation needs a network connection. The running native app does not.

```bash
git clone https://github.com/fy-agent/space-perspective.git
cd space-perspective
cargo fetch --locked --manifest-path desktop/Cargo.toml
python3 scripts/mac001_build.py --build --read-only-downloads
open "output/mac-001-native-20260919/downloads-read-only/Space Perspective Read Only.app"
```

Choose your Downloads folder through the system picker, then generate suggestions. The build uses
ad-hoc local signing and registers the build account's Downloads path; it is not a portable release.
See the [native development guide](desktop/README.md) for details.

## Scope and roadmap

Content understanding, OCR, semantic similarity, installed-app verification and native exact-content
deduplication are not implemented in this preview. Real file operations remain unavailable because
delayed and restarted recovery still has an unresolved identity-drift problem.

The repository also includes a Python Core and a React developer workbench for indexes, reports,
deduplication, and controlled quarantine experiments. Their capabilities must not be confused with
the native Downloads preview. See [architecture](docs/architecture.md), [development](docs/development.md),
[privacy boundaries](docs/privacy-invariants.md), and the [roadmap](docs/roadmap.md).

## Contribute

We welcome reproducible classification examples, clearer explanations, Mac permission and recovery
tests, and future Windows platform work. Use synthetic examples and remove private paths and contents.

[Issues](https://github.com/fy-agent/space-perspective/issues) · [Contribution guide](CONTRIBUTING.md) ·
[Security reports](SECURITY.md)

Released under the [MIT License](LICENSE). Dependencies retain their own licenses and notices; see
[third-party notices](THIRD_PARTY_NOTICES.md). Illustrations contain fictional examples and are not
runtime screenshots.
