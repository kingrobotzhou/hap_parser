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
