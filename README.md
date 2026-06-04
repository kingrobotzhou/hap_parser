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
- **Runtime Memory Integrity** — Verifies loaded `.so` segments and `.abc` bytecode in process memory at runtime via `/proc/self/maps` and `link_map` cross-reference
- **Nested HAP Analysis** — Recursively analyzes inner `.hap` packages embedded in `.app` files
- **Bilingual UI** — English / Chinese toggle

## Project Structure

```
hap_parser/
├── hap_parser/          # Core parsing library (C++)
│   ├── hap_parser.h     #   HapParser class + 15 data structures
│   ├── hap_parser.cpp   #   ZIP EOCD, signing block, PKCS7, profile parsing
│   ├── hap_parser_main.cpp  # CLI entry point
│   ├── byte_view.h      #   ByteView utility class (buffer + LE readers)
│   ├── runtime_verify.h #   RuntimeVerifier class + public types
│   └── runtime_verify.cpp   # ELF segment hashing, /proc/maps parsing, PANDA scanning
├── gui/                 # macOS GUI (GLFW + ImGui)
│   ├── AppState.h       #   UI state management class
│   ├── AppState.cpp     #   State management implementation
│   ├── main.cpp         #   ImGui UI: tabs, tables, drag-drop
│   ├── HapAnalyzer.h    #   C API bridging parser ↔ GUI
│   ├── HapAnalyzer.cpp  #   C API implementation
│   ├── macos_bridge.mm  #   macOS file dialog / open handler
│   ├── imgui/           #   Dear ImGui (vendored)
│   ├── fonts/           #   UI fonts
│   └── CMakeLists.txt   #   Build configuration
├── tests/               # Unit tests
│   └── test_runner.cpp  #   20 test cases
├── .github/workflows/   # CI/CD
│   └── build.yml        #   Build + Test + Release
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

## Testing

```bash
cd hap_parser
clang++ -std=c++17 ../tests/test_runner.cpp hap_parser.cpp runtime_verify.cpp \
    -I. -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib \
    -lssl -lcrypto -o test_runner && ./test_runner
```

20 test cases covering:

| Category | Tests |
|---|---|
| Parsing | Valid HAP, large HAP, empty file, tiny file, corrupted, garbage bytes |
| Certificates | Chain validation, field completeness, identity chain |
| Profile | Field extraction, bundle name, developer ID |
| Runtime | ELF segment hashing, ABC references, `/proc/maps` platform compatibility |
| Utilities | `ByteView` boundary checks, `RuntimeVerifyResult` helpers |

Tests also run automatically on every push via GitHub Actions.

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

## Runtime Verification

After parsing a HAP file, reference hashes for `.so` and `.abc` files are stored in the `Summary` struct. At runtime, call `HapParser::verifyRuntime()` to check loaded libraries against these references:

```cpp
HapParser parser;
auto summary = parser.parseFile("app.hap");
auto result  = HapParser::verifyRuntime(*summary);
// result.allPassed() → true if all .so segments and .abc files match
```

### .so Verification

1. Extract **ELF PT_LOAD segment hashes** from ZIP entries — only `p_filesz` (file-mapped portion), excluding `.bss`
2. Parse `/proc/self/maps` to locate loaded `.so` memory regions
3. Compute SHA256 of each segment in memory and compare against reference

### .abc Verification

1. Store the SHA256 from the signing block as reference
2. Scan process memory for `PANDA` magic bytes to locate loaded `.abc` files
3. Read `file_size` from the Panda header and compute SHA256 of the full data

### Anti-Tampering

- **link_map cross-reference**: Enumerates loaded libraries via `dl_iterate_phdr` (the runtime linker's internal chain) and compares against `/proc/self/maps`. If a library appears in `link_map` but is missing from `maps`, `/proc/self/maps` may have been tampered with.
- **Graceful fallback**: If `/proc/self/maps` is unavailable, falls back to `link_map` enumeration.

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
- **运行时内存校验** — 运行时通过 `/proc/self/maps` 和 `link_map` 交叉验证已加载 `.so` 段和 `.abc` 字节码的完整性
- **嵌套 HAP 分析** — 递归分析 `.app` 文件中内嵌的子 `.hap` 包
- **双语界面** — 支持中英文切换

## 项目结构

```
hap_parser/
├── hap_parser/          # 核心解析库（C++）
│   ├── hap_parser.h     #   HapParser 类 + 15 个数据结构
│   ├── hap_parser.cpp   #   ZIP EOCD、签名块、PKCS7、profile 解析
│   ├── hap_parser_main.cpp  # 命令行入口
│   ├── byte_view.h      #   ByteView 工具类（字节缓冲 + LE 读取）
│   ├── runtime_verify.h #   RuntimeVerifier 类 + 公共类型
│   └── runtime_verify.cpp   # ELF 段哈希、/proc/maps 解析、PANDA 扫描
├── gui/                 # macOS 图形界面（GLFW + ImGui）
│   ├── AppState.h       #   UI 状态管理类
│   ├── AppState.cpp     #   状态管理实现
│   ├── main.cpp         #   ImGui UI：标签页、表格、拖放
│   ├── HapAnalyzer.h    #   C API 桥接解析器 ↔ GUI
│   ├── HapAnalyzer.cpp  #   C API 实现
│   ├── macos_bridge.mm  #   macOS 文件对话框 / 打开事件
│   ├── imgui/           #   Dear ImGui（本地集成）
│   ├── fonts/           #   界面字体
│   └── CMakeLists.txt   #   构建配置
├── tests/               # 单元测试
│   └── test_runner.cpp  #   20 个测试用例
├── .github/workflows/   # CI/CD
│   └── build.yml        #   构建 + 测试 + 发布
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

## 测试

```bash
cd hap_parser
clang++ -std=c++17 ../tests/test_runner.cpp hap_parser.cpp runtime_verify.cpp \
    -I. -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib \
    -lssl -lcrypto -o test_runner && ./test_runner
```

20 个测试用例，覆盖：

| 分类 | 测试 |
|---|---|
| 解析 | 正常 HAP、大型 HAP、空文件、小文件、损坏文件、随机字节 |
| 证书 | 链校验、字段完整性、身份链 |
| Profile | 字段提取、包名、开发者 ID |
| 运行时 | ELF 段哈希、ABC 引用、`/proc/maps` 平台兼容 |
| 工具类 | `ByteView` 边界检查、`RuntimeVerifyResult` 辅助方法 |

每次 push 代码时 GitHub Actions 自动运行全部测试。

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

## 运行时校验

解析 HAP 后，`.so` 和 `.abc` 的参考哈希存储在 `Summary` 结构体中。运行时调用 `HapParser::verifyRuntime()` 即可检查内存中已加载库与参考值是否一致：

```cpp
HapParser parser;
auto summary = parser.parseFile("app.hap");
auto result  = HapParser::verifyRuntime(*summary);
// result.allPassed() → 所有 .so 段和 .abc 匹配则返回 true
```

### .so 校验

1. 从 ZIP 条目提取 **ELF PT_LOAD 段哈希** — 只计算 `p_filesz`（文件映射部分），排除 `.bss`
2. 解析 `/proc/self/maps` 定位已加载 `.so` 的内存区域
3. 计算内存中各段的 SHA256 并与参考值对比

### .abc 校验

1. 从签名块中获取 SHA256 作为参考值
2. 扫描进程内存中的 `PANDA` 魔数定位已加载的 `.abc` 文件
3. 从 Panda 头部读取 `file_size`，计算全文 SHA256 并对比

### 抗篡改

- **link_map 交叉验证**: 通过 `dl_iterate_phdr`（运行时链接器的内部链表）枚举已加载库，与 `/proc/self/maps` 对比。若 `link_map` 中有而 `maps` 中无，说明 `maps` 可能被篡改。
- **优雅降级**: 若 `/proc/self/maps` 不可用，自动回退到 `link_map` 枚举。

## 许可证

MIT
