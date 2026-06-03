# HAP Parser

A security analysis tool for HarmonyOS `.hap` and `.app` application packages. Parses the HAP signing block, extracts certificate chains, validates PKCS7 signatures, verifies code-signing integrity, and presents results through both a CLI and a native macOS GUI.

## Features

- **HAP / APP Package Parsing** — Reads the ZIP + signing block structure of HarmonyOS application packages
- **Certificate Chain Extraction** — Extracts and orders PKCS7 certificate chains (leaf → intermediate → root) from multiple signing sub-blocks
- **Chain Validation** — Validates issuer-subject links, cryptographic signatures, certificate expiry, and chain topology
- **Identity Chain Matching** — Matches the developer certificate against the profile to build a complete identity chain including system trust anchors
- **Provisioning Profile** — Parses profile metadata: bundle name, developer ID, app identifier, permissions, APL level, validity period
- **Code Signing Integrity** — Detects injected `.so` files not covered by the code-signing block, highlights missing libraries
- **SHA256 Hashing** — Computes per-file SHA256 hashes and compares against a reference manifest to detect tampering
- **Nested HAP Analysis** — Recursively analyzes inner `.hap` packages embedded in `.app` files
- **Bilingual UI** — English / Chinese toggle

## Project Structure

```
hap_parser/
├── hap_parser/          # Core parsing library (C++)
│   ├── hap_parser.h     #   Public API & data structures
│   ├── hap_parser.cpp   #   ZIP EOCD, signing block, PKCS7, profile parsing
│   └── hap_parser_main.cpp  # CLI entry point
├── gui/                 # macOS GUI (GLFW + ImGui)
│   ├── main.cpp         #   ImGui UI: tabs, tables, drag-drop
│   ├── HapAnalyzer.h    #   C API wrapping the parser
│   ├── HapAnalyzer.cpp  #   C API implementation
│   ├── macos_bridge.mm  #   macOS file dialog / open handler
│   ├── imgui/           #   Dear ImGui (vendored)
│   ├── fonts/           #   UI fonts
│   └── CMakeLists.txt   #   Build configuration
└── README.md
```

## Building

### Prerequisites

- **CMake** ≥ 3.20
- **OpenSSL** (macOS: `brew install openssl`)
- **GLFW** (auto-fetched if not found)
- **Xcode Command Line Tools** (macOS)

### CLI

```bash
cd hap_parser
clang++ -std=c++17 hap_parser.cpp hap_parser_main.cpp \
    -I/opt/homebrew/opt/openssl/include \
    -L/opt/homebrew/opt/openssl/lib \
    -lssl -lcrypto -o hap_parser
```

### GUI (macOS)

```bash
cd gui
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
open build/hap_analyzer_gui.app
```

## Usage

### CLI

```
hap_parser <file.hap|file.app> [options]

Options:
  -a, --all        Show all sections
  -l, --layout     Show file layout diagram
  -p, --profile    Show provision profile details
  -c, --codesign   Show code signing info
  -H, --hashes     Show file SHA256 hashes
  -i, --integrity  Show integrity verification table
  --expect <file>  Compare hashes against JSON manifest

Default: certificate verification graph only
```

### GUI

1. Launch `hap_analyzer_gui.app`
2. Drag a `.hap` or `.app` file onto the window (or use File → Open)
3. Browse tabs: **Summary**, **Certificates**, **Structure**

### Manifest Format

A JSON file mapping filenames to expected SHA256 hashes:

```json
{
  "files": {
    "entry-default-unsigned-so.hap": "ab12cd34...",
    "libs/arm64-v8a/libentry.so": "ef56gh78..."
  }
}
```

Load via **File → Load Manifest** or auto-generate from a trusted reference build via **File → Set as Reference**.

## How It Works

1. **Find ZIP EOCD** — Locate the End of Central Directory record at the end of the file
2. **Locate Signing Block** — The HAP signing footer sits between the last file entry and the central directory; it contains a magic string, version, block count, and total size
3. **Parse Sub-blocks** — Each sub-block header (type, length, offset) is read from the table at the start of the signing block:
   | Block Type | Name | Content |
   |---|---|---|
   | `0x20000000` | AppSignatureBlock | Main app CMS/PKCS7 signature |
   | `0x20000001` | ProofOfRotationBlock | Certificate rotation chain |
   | `0x20000002` | ProfileBlock | Provisioning profile (JSON) |
   | `0x20000003` | PropertyBlock | Code-sign metadata + reference to `0x30000001` |
4. **Extract Certificates** — PKCS7 signed-data blobs are DER-decoded via OpenSSL; certificates are deduplicated and ordered from leaf to root
5. **Validate Chain** — Issuer-Subject links, cryptographic signatures, expiry, and self-signed root checks
6. **Verify Code Signing** — Cross-reference `.so` files in the ZIP against the code-sign block list; flag injected or missing libraries

## License

MIT

---

# HAP Parser（中文）

一款面向 HarmonyOS `.hap` / `.app` 应用包的安全分析工具。解析 HAP 签名块、提取证书链、验证 PKCS7 签名、校验代码签名完整性，提供命令行和 macOS 原生 GUI 两种使用方式。

## 功能

- **HAP / APP 包解析** — 读取 HarmonyOS 应用包的 ZIP + 签名块结构
- **证书链提取** — 从多个签名子块中提取并排序 PKCS7 证书链（叶子证书 → 中间证书 → 根证书）
- **链验证** — 验证颁发者-主体关联、密码学签名、证书有效期及链拓扑结构
- **身份链匹配** — 将开发者证书与配置描述文件关联，构建包含系统信任锚点的完整身份链
- **配置描述文件** — 解析 profile 元数据：包名、开发者 ID、应用标识、权限、APL 级别、有效期
- **代码签名完整性** — 检测未受代码签名块保护的注入 `.so` 文件，高亮缺失的库文件
- **SHA256 哈希** — 逐文件计算 SHA256 并对比基准清单，检测篡改
- **嵌套 HAP 分析** — 递归分析 `.app` 文件中内嵌的子 `.hap` 包
- **双语界面** — 支持中英文切换

## 项目结构

```
hap_parser/
├── hap_parser/          # 核心解析库（C++）
│   ├── hap_parser.h     #   公共 API 与数据结构
│   ├── hap_parser.cpp   #   ZIP EOCD、签名块、PKCS7、profile 解析
│   └── hap_parser_main.cpp  # 命令行入口
├── gui/                 # macOS 图形界面（GLFW + ImGui）
│   ├── main.cpp         #   ImGui UI：标签页、表格、拖放
│   ├── HapAnalyzer.h    #   封装解析器的 C API
│   ├── HapAnalyzer.cpp  #   C API 实现
│   ├── macos_bridge.mm  #   macOS 文件对话框 / 打开事件
│   ├── imgui/           #   Dear ImGui（本地集成）
│   ├── fonts/           #   界面字体
│   └── CMakeLists.txt   #   构建配置
└── README.md
```

## 构建

### 前置依赖

- **CMake** ≥ 3.20
- **OpenSSL**（macOS：`brew install openssl`）
- **GLFW**（如未找到会自动下载）
- **Xcode Command Line Tools**（macOS）

### 命令行工具

```bash
cd hap_parser
clang++ -std=c++17 hap_parser.cpp hap_parser_main.cpp \
    -I/opt/homebrew/opt/openssl/include \
    -L/opt/homebrew/opt/openssl/lib \
    -lssl -lcrypto -o hap_parser
```

### GUI（macOS）

```bash
cd gui
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
open build/hap_analyzer_gui.app
```

## 使用方式

### 命令行

```
hap_parser <文件.hap|文件.app> [选项]

选项：
  -a, --all        显示所有内容
  -l, --layout     显示文件布局图
  -p, --profile    显示配置描述文件详情
  -c, --codesign   显示代码签名信息
  -H, --hashes     显示文件 SHA256 哈希
  -i, --integrity  显示完整性校验表
  --expect <文件>  对照 JSON 清单比对哈希

默认：仅输出证书验证图
```

### GUI

1. 启动 `hap_analyzer_gui.app`
2. 将 `.hap` 或 `.app` 文件拖放到窗口中（或通过 文件 → 打开）
3. 浏览标签页：**摘要（Summary）**、**证书（Certificates）**、**文件结构（Structure）**

### 基准清单格式

一个 JSON 文件，记录文件名与期望的 SHA256 哈希值：

```json
{
  "files": {
    "entry-default-unsigned-so.hap": "ab12cd34...",
    "libs/arm64-v8a/libentry.so": "ef56gh78..."
  }
}
```

通过 **文件 → 加载清单** 导入，或在可信基准版本上通过 **文件 → 设为基准** 自动生成。

## 工作原理

1. **定位 ZIP EOCD** — 在文件末尾找到中央目录结束记录
2. **定位签名块** — HAP 签名尾部位于最后一个文件条目与中央目录之间，包含魔数字符串、版本号、块数量及总大小
3. **解析子块** — 从签名块头部的表中读取每个子块头（类型、长度、偏移）：
   | 块类型 | 名称 | 内容 |
   |---|---|---|
   | `0x20000000` | AppSignatureBlock | 应用主签名（CMS/PKCS7） |
   | `0x20000001` | ProofOfRotationBlock | 证书轮换链 |
   | `0x20000002` | ProfileBlock | 配置描述文件（JSON） |
   | `0x20000003` | PropertyBlock | 代码签名元数据 + 指向 `0x30000001` 的引用 |
4. **提取证书** — 通过 OpenSSL DER 解码 PKCS7 签名数据，去重并从叶子到根排序
5. **验证链** — 检查颁发者-主体关联、密码学签名、有效期及自签名根证书
6. **校验代码签名** — 将 ZIP 中的 `.so` 文件与代码签名清单交叉比对，标记注入或缺失的库

## 许可证

MIT
