#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ── ELF constants ───────────────────────────────────────────────────────────

constexpr std::uint32_t kElfMagic         = 0x464C457F;  // "\x7FELF"
constexpr std::uint32_t kElfClass32       = 1;
constexpr std::uint32_t kElfClass64       = 2;
constexpr std::uint32_t kElfData2LSB      = 1;
constexpr std::uint32_t kElfData2MSB      = 2;

// e_type
constexpr std::uint16_t kEtNone           = 0;
constexpr std::uint16_t kEtRel            = 1;
constexpr std::uint16_t kEtExec           = 2;
constexpr std::uint16_t kEtDyn            = 3;
constexpr std::uint16_t kEtCore           = 4;

// p_type
constexpr std::uint32_t kPtNull           = 0;
constexpr std::uint32_t kPtLoad           = 1;
constexpr std::uint32_t kPtDynamic        = 2;
constexpr std::uint32_t kPtInterp         = 3;
constexpr std::uint32_t kPtNote           = 4;
constexpr std::uint32_t kPtPhdr           = 6;
constexpr std::uint32_t kPtGnuRelro       = 0x6474E552;
constexpr std::uint32_t kPtGnuEhFrame     = 0x6474E550;
constexpr std::uint32_t kPtGnuStack       = 0x6474E551;

// p_flags
constexpr std::uint32_t kPfX              = 1;
constexpr std::uint32_t kPfW              = 2;
constexpr std::uint32_t kPfR              = 4;

// ── ABC (ArkCompiler Bytecode) constants ────────────────────────────────────

constexpr std::uint64_t kAbcMagicPanda    = 0x41444E4150ULL;  // "PANDA\0\0\0"
constexpr std::uint32_t kAbcHeaderSize    = 32;                // PandaFileHeader size

// ── Data structures ─────────────────────────────────────────────────────────

/// Per-segment hash computed from the ELF file inside the ZIP.
struct ElfSegmentHash {
    std::uint32_t segmentType = 0;     // PT_LOAD, etc.
    std::uint32_t segmentFlags = 0;    // PF_R | PF_W | PF_X
    std::uint64_t fileOffset = 0;      // p_offset in ELF file
    std::uint64_t fileSize = 0;        // p_filesz — mapped portion excluding .bss
    std::uint64_t virtualAddr = 0;     // p_vaddr — relative to load base
    std::string   sha256;              // SHA256 of the p_filesz bytes from file
};

/// Reference hashes for one .so file, extracted from the ZIP entry at build time.
struct SoReferenceHash {
    std::string fileName;                     // e.g. "libs/arm64-v8a/libentry.so"
    std::vector<ElfSegmentHash> segments;     // one per PT_LOAD segment
    std::string fullFileSha256;               // SHA256 of the entire ZIP entry (for fallback)
};

/// Reference hash for one .abc file, from the ZIP entry.
struct AbcReferenceHash {
    std::string fileName;             // e.g. "ets/modules.abc"
    std::string sha256;               // SHA256 of the full ZIP entry
};

/// One line from /proc/self/maps.
struct MemoryMapping {
    std::uint64_t startAddr = 0;
    std::uint64_t endAddr   = 0;
    std::string   perms;          // e.g. "r-xp", "r--p", "rw-p"
    std::uint64_t fileOffset = 0;
    std::string   path;           // mapped file path, empty for [anon]
};

/// Loaded library info from the runtime linker's link_map chain.
/// Serves as a /proc/self/maps cross-reference: if a library appears here
/// but not in maps, /proc/self/maps may have been tampered with.
struct LoadedLibrary {
    std::string   name;
    std::uint64_t baseAddr = 0;    // l_addr — load base
    std::uint64_t virtSize = 0;    // total virtual size (sum of PT_LOAD memsz)
};

/// Result for one .so segment verification at runtime.
struct SoSegmentVerifyResult {
    std::string soFileName;
    std::string segmentInfo;       // "PT_LOAD PF_R|PF_X"
    std::uint64_t expectedOffset = 0;
    std::uint64_t expectedSize = 0;
    std::uint64_t actualStartAddr = 0;
    std::uint64_t actualSize = 0;
    std::string expectedSha256;
    std::string actualSha256;
    bool match = false;
    std::string error;            // "not-mapped", "size-mismatch", "hash-mismatch", or empty on ok
};

/// Result for one .abc file verification at runtime.
struct AbcVerifyResult {
    std::string abcFileName;
    std::string expectedSha256;
    std::string actualSha256;
    bool found = false;
    bool match = false;
    std::string error;
};

/// Top-level runtime verification result.
struct RuntimeVerifyResult {
    std::vector<SoSegmentVerifyResult> soResults;
    std::vector<AbcVerifyResult>       abcResults;
    std::vector<std::string>           warnings;

    bool allSoPassed() const;
    bool allAbcPassed() const;
    bool allPassed() const;
    int  totalSoSegments() const;
    int  passedSoSegments() const;
    int  totalAbc() const;
    int  passedAbc() const;
};

// ── Reference hash extraction (build-time, from ZIP entries) ────────────────

/// Parse an ELF file from raw bytes and extract PT_LOAD segment hashes.
/// Returns empty vector if data is not a valid ELF.
std::vector<ElfSegmentHash> extractElfSegmentHashes(const std::uint8_t* data,
                                                     std::size_t size);

/// Extract reference hashes for all .so files in the ZIP entries.
/// `fileHashes` should come from HapParser::Summary::fileHashes.
/// `getFileData(offset, size)` is a callback to read the raw ZIP entry data.
/// Returns one SoReferenceHash per .so file.
std::vector<SoReferenceHash> extractSoReferenceHashes(
    const std::vector<std::uint8_t>& hapBytes,
    const std::vector<std::string>&  soFileNames,
    const std::vector<std::pair<std::int64_t, std::int64_t>>& soOffsetsAndSizes);

/// Extract reference hashes for .abc files from the SHA256 values
/// already computed during ZIP traversal.
std::vector<AbcReferenceHash> extractAbcReferenceHashes(
    const std::vector<std::pair<std::string, std::string>>& abcNameAndSha256);

// ── Runtime verification ────────────────────────────────────────────────────

/// Parse /proc/self/maps and return all memory mappings.
std::vector<MemoryMapping> parseProcSelfMaps();

/// Enumerate loaded shared libraries via dl_iterate_phdr (link_map traversal).
/// Returns library name, base address, and total virtual size.
/// Independent of /proc/self/maps — provides cross-reference capability.
std::vector<LoadedLibrary> enumerateLoadedLibsViaLinkMap();

/// Parse ELF header from in-memory bytes at the given address.
/// Returns true and fills ehdr fields on success.
struct ElfIdent {
    bool is64Bit = false;
    bool isLE    = true;
    std::uint16_t type = 0;        // e_type (ET_DYN, ET_EXEC, ...)
    std::uint64_t entry = 0;
    std::uint64_t phoff = 0;       // program header table offset
    std::uint16_t phnum = 0;       // number of program headers
    std::uint16_t phentsize = 0;   // size of each program header entry
};

bool parseElfIdent(const std::uint8_t* addr, std::size_t rangeSize, ElfIdent& out);

/// Read a single ELF program header from memory at phdrAddr.
/// Returns p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz.
struct ElfPhdr {
    std::uint32_t type   = 0;
    std::uint32_t flags  = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr  = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz  = 0;
};

bool readElfPhdr(const std::uint8_t* elfBase, std::size_t rangeSize,
                 const ElfIdent& ident, std::uint16_t index, ElfPhdr& out);

/// Compute SHA256 of an in-memory range.
/// Returns empty string if the range is not readable.
std::string computeMemorySha256(const void* addr, std::size_t size);

/// Scan readable memory regions for ABC (PANDA) files.
/// Returns a list of {startAddr, size, sha256}.
struct ScannedAbc {
    std::uint64_t startAddr = 0;
    std::uint64_t size = 0;
    std::string   sha256;
};

std::vector<ScannedAbc> scanMemoryForAbcFiles();

/// Main runtime verification entry point.
/// Compares loaded .so segments and .abc data against reference hashes.
/// `soRefs` and `abcRefs` come from extractSoReferenceHashes / extractAbcReferenceHashes.
RuntimeVerifyResult verifyRuntimeIntegrity(
    const std::vector<SoReferenceHash>&  soRefs,
    const std::vector<AbcReferenceHash>& abcRefs);
