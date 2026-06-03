#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ── ELF constants ───────────────────────────────────────────────────────────

constexpr std::uint32_t kElfMagic         = 0x464C457F;
constexpr std::uint32_t kElfClass32       = 1;
constexpr std::uint32_t kElfClass64       = 2;
constexpr std::uint32_t kElfData2LSB      = 1;
constexpr std::uint32_t kElfData2MSB      = 2;

constexpr std::uint16_t kEtNone           = 0;
constexpr std::uint16_t kEtRel            = 1;
constexpr std::uint16_t kEtExec           = 2;
constexpr std::uint16_t kEtDyn            = 3;
constexpr std::uint16_t kEtCore           = 4;

constexpr std::uint32_t kPtNull           = 0;
constexpr std::uint32_t kPtLoad           = 1;
constexpr std::uint32_t kPtDynamic        = 2;
constexpr std::uint32_t kPtInterp         = 3;
constexpr std::uint32_t kPtNote           = 4;
constexpr std::uint32_t kPtPhdr           = 6;
constexpr std::uint32_t kPtGnuRelro       = 0x6474E552;
constexpr std::uint32_t kPtGnuEhFrame     = 0x6474E550;
constexpr std::uint32_t kPtGnuStack       = 0x6474E551;

constexpr std::uint32_t kPfX              = 1;
constexpr std::uint32_t kPfW              = 2;
constexpr std::uint32_t kPfR              = 4;

constexpr std::uint64_t kAbcMagicPanda    = 0x41444E4150ULL;
constexpr std::uint32_t kAbcHeaderSize    = 32;

// ── Public data types ───────────────────────────────────────────────────────

struct ElfSegmentHash {
    std::uint32_t segmentType = 0;
    std::uint32_t segmentFlags = 0;
    std::uint64_t fileOffset = 0;
    std::uint64_t fileSize = 0;
    std::uint64_t virtualAddr = 0;
    std::string   sha256;
};

struct SoReferenceHash {
    std::string fileName;
    std::vector<ElfSegmentHash> segments;
    std::string fullFileSha256;
};

struct AbcReferenceHash {
    std::string fileName;
    std::string sha256;
};

struct MemoryMapping {
    std::uint64_t startAddr = 0;
    std::uint64_t endAddr   = 0;
    std::string   perms;
    std::uint64_t fileOffset = 0;
    std::string   path;
};

struct LoadedLibrary {
    std::string   name;
    std::uint64_t baseAddr = 0;
    std::uint64_t virtSize = 0;
};

struct SoSegmentVerifyResult {
    std::string soFileName;
    std::string segmentInfo;
    std::uint64_t expectedOffset = 0;
    std::uint64_t expectedSize = 0;
    std::uint64_t actualStartAddr = 0;
    std::uint64_t actualSize = 0;
    std::string expectedSha256;
    std::string actualSha256;
    bool match = false;
    std::string error;
};

struct AbcVerifyResult {
    std::string abcFileName;
    std::string expectedSha256;
    std::string actualSha256;
    bool found = false;
    bool match = false;
    std::string error;
};

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

struct ElfIdent {
    bool is64Bit = false;
    bool isLE    = true;
    std::uint16_t type = 0;
    std::uint64_t entry = 0;
    std::uint64_t phoff = 0;
    std::uint16_t phnum = 0;
    std::uint16_t phentsize = 0;
};

struct ElfPhdr {
    std::uint32_t type   = 0;
    std::uint32_t flags  = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr  = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz  = 0;
};

struct ScannedAbc {
    std::uint64_t startAddr = 0;
    std::uint64_t size = 0;
    std::string   sha256;
};

// ── RuntimeVerifier class ───────────────────────────────────────────────────

class RuntimeVerifier {
public:
    RuntimeVerifier() = default;

    /// Populate reference hashes from pre-extracted data. Use the static
    /// extractSoRefs/extractAbcRefs methods during HAP parsing, then call
    /// load() with the results before verify().
    void load(const std::vector<SoReferenceHash>&  so,
              const std::vector<AbcReferenceHash>& abc);

    /// Run memory integrity check against the loaded reference hashes.
    RuntimeVerifyResult verify() const;

    const std::vector<SoReferenceHash>& soRefs()  const { return soRefs_; }
    const std::vector<AbcReferenceHash>& abcRefs() const { return abcRefs_; }

    // ── Build-time extraction (called during HAP parsing) ───────────────

    static std::vector<SoReferenceHash> extractSoRefs(
        const std::vector<std::uint8_t>& hapBytes,
        const std::vector<std::string>&  soNames,
        const std::vector<std::pair<std::int64_t, std::int64_t>>& soOffsetsSizes);

    static std::vector<AbcReferenceHash> extractAbcRefs(
        const std::vector<std::pair<std::string, std::string>>& abcNameSha256);

private:
    // ── Build-time helpers ──────────────────────────────────────────────

    static std::vector<ElfSegmentHash> extractElfSegments(const std::uint8_t* data,
                                                           std::size_t size);

    // ── Runtime helpers ─────────────────────────────────────────────────

    static std::vector<MemoryMapping> parseProcMaps();
    static std::vector<LoadedLibrary> enumerateLinkMap();

    static bool parseElfIdent(const std::uint8_t* addr, std::size_t range,
                              ElfIdent& out);
    static bool readPhdr(const std::uint8_t* base, std::size_t range,
                         const ElfIdent& ident, std::uint16_t idx, ElfPhdr& out);

    static std::string sha256(const void* addr, std::size_t size);

    static std::vector<ScannedAbc> scanAbcInMemory();

    // ── State ───────────────────────────────────────────────────────────

    std::vector<SoReferenceHash>  soRefs_;
    std::vector<AbcReferenceHash> abcRefs_;
};
