#include "runtime_verify.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>

#include <openssl/sha.h>

// ── Little-endian byte readers ──────────────────────────────────────────────

namespace {

std::uint16_t readU16LE(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) |
           (static_cast<std::uint16_t>(p[1]) << 8);
}

std::uint32_t readU32LE(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t readU64LE(const std::uint8_t* p) {
    return static_cast<std::uint64_t>(p[0]) |
           (static_cast<std::uint64_t>(p[1]) << 8) |
           (static_cast<std::uint64_t>(p[2]) << 16) |
           (static_cast<std::uint64_t>(p[3]) << 24) |
           (static_cast<std::uint64_t>(p[4]) << 32) |
           (static_cast<std::uint64_t>(p[5]) << 40) |
           (static_cast<std::uint64_t>(p[6]) << 48) |
           (static_cast<std::uint64_t>(p[7]) << 56);
}

std::string sha256Hex(const std::uint8_t* data, std::size_t size) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, size, hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// ── ELF parsing helpers (for build-time extraction from ZIP bytes) ──────────

struct ElfFileHeader {
    bool     is64 = false;
    bool     isLE = true;
    std::uint16_t type = 0;
    std::uint64_t phoff = 0;    // program header offset
    std::uint16_t phnum = 0;
    std::uint16_t phentsize = 0;
};

bool parseElfFileHeader(const std::uint8_t* data, std::size_t size, ElfFileHeader& ehdr) {
    if (size < 64) return false;   // enough for 64-bit ELF header

    // e_ident
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F')
        return false;

    ehdr.is64 = (data[4] == kElfClass64);
    if (data[4] != kElfClass32 && data[4] != kElfClass64) return false;

    ehdr.isLE = (data[5] == kElfData2LSB);
    if (data[5] != kElfData2LSB && data[5] != kElfData2MSB) return false;
    if (!ehdr.isLE) return false;   // big-endian not supported

    // e_type
    ehdr.type = readU16LE(data + 16);

    if (ehdr.is64) {
        ehdr.phoff     = readU64LE(data + 32);
        ehdr.phnum     = readU16LE(data + 56);
        ehdr.phentsize = readU16LE(data + 54);
    } else {
        ehdr.phoff     = readU32LE(data + 28);
        ehdr.phnum     = readU16LE(data + 44);
        ehdr.phentsize = readU16LE(data + 42);
    }

    return true;
}

}  // anonymous namespace

// ── Public: extract ELF segment hashes from raw bytes ───────────────────────

std::vector<ElfSegmentHash> extractElfSegmentHashes(const std::uint8_t* data,
                                                     std::size_t size) {
    std::vector<ElfSegmentHash> results;

    ElfFileHeader ehdr;
    if (!parseElfFileHeader(data, size, ehdr)) return results;

    for (std::uint16_t i = 0; i < ehdr.phnum; ++i) {
        std::uint64_t phdrOff = ehdr.phoff + static_cast<std::uint64_t>(i) * ehdr.phentsize;
        if (phdrOff + ehdr.phentsize > size) break;

        std::uint32_t pType  = readU32LE(data + phdrOff);
        if (pType != kPtLoad) continue;

        std::uint64_t pOffset = 0;
        std::uint64_t pVaddr  = 0;
        std::uint64_t pFilesz = 0;
        std::uint64_t pMemsz  = 0;
        std::uint32_t pFlags  = 0;

        if (ehdr.is64) {
            pFlags  = readU32LE(data + phdrOff + 4);
            pOffset = readU64LE(data + phdrOff + 8);
            pVaddr  = readU64LE(data + phdrOff + 16);
            pFilesz = readU64LE(data + phdrOff + 32);
            pMemsz  = readU64LE(data + phdrOff + 40);
        } else {
            pOffset = readU32LE(data + phdrOff + 4);
            pVaddr  = readU32LE(data + phdrOff + 8);
            pFilesz = readU32LE(data + phdrOff + 16);
            pMemsz  = readU32LE(data + phdrOff + 20);
            pFlags  = readU32LE(data + phdrOff + 24);
        }

        // Only hash the file-backed portion (p_filesz), excluding .bss (p_memsz - p_filesz)
        if (pFilesz == 0) continue;
        if (pOffset + pFilesz > size) break;

        ElfSegmentHash seg;
        seg.segmentType  = pType;
        seg.segmentFlags = pFlags;
        seg.fileOffset   = pOffset;
        seg.fileSize     = pFilesz;
        seg.virtualAddr  = pVaddr;
        seg.sha256       = sha256Hex(data + pOffset, static_cast<std::size_t>(pFilesz));
        results.push_back(std::move(seg));
    }

    return results;
}

// ── Public: extract .so reference hashes from HAP ZIP bytes ─────────────────

std::vector<SoReferenceHash> extractSoReferenceHashes(
    const std::vector<std::uint8_t>& hapBytes,
    const std::vector<std::string>&  soFileNames,
    const std::vector<std::pair<std::int64_t, std::int64_t>>& soOffsetsAndSizes)
{
    std::vector<SoReferenceHash> result;
    const std::size_t n = soFileNames.size();
    for (std::size_t i = 0; i < n && i < soOffsetsAndSizes.size(); ++i) {
        const std::int64_t offset = soOffsetsAndSizes[i].first;
        const std::int64_t size   = soOffsetsAndSizes[i].second;
        if (offset < 0 || size <= 0) continue;
        if (static_cast<std::size_t>(offset + size) > hapBytes.size()) continue;

        const std::uint8_t* data = hapBytes.data() + offset;
        const auto fileSize = static_cast<std::size_t>(size);

        SoReferenceHash ref;
        ref.fileName       = soFileNames[i];
        ref.fullFileSha256 = sha256Hex(data, fileSize);
        ref.segments       = extractElfSegmentHashes(data, fileSize);

        // Even if ELF parsing fails (non-ELF .so? corrupted?), keep the full-file hash
        result.push_back(std::move(ref));
    }
    return result;
}

// ── Public: extract .abc reference hashes ───────────────────────────────────

std::vector<AbcReferenceHash> extractAbcReferenceHashes(
    const std::vector<std::pair<std::string, std::string>>& abcNameAndSha256)
{
    std::vector<AbcReferenceHash> result;
    for (const auto& entry : abcNameAndSha256) {
        const auto& name = entry.first;
        if (name.size() < 4 || (name.substr(name.size() - 4) != ".abc" && name.find(".abc") == std::string::npos))
            continue;
        AbcReferenceHash ref;
        ref.fileName = name;
        ref.sha256   = entry.second;
        result.push_back(std::move(ref));
    }
    return result;
}

// ── Public: parse /proc/self/maps ───────────────────────────────────────────

std::vector<MemoryMapping> parseProcSelfMaps() {
    std::vector<MemoryMapping> result;

    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return result;

    std::string line;
    while (std::getline(maps, line)) {
        MemoryMapping m;
        // Format: "7f1234000000-7f123400b000 r-xp 00000000 fd:01 12345  /path/to/lib.so"
        char perms[8] = {};
        char path[1024] = {};
        unsigned long long start = 0, end = 0, fileOff = 0;
        unsigned int devMajor = 0, devMinor = 0;
        unsigned long long inode = 0;

        int n = std::sscanf(line.c_str(), "%llx-%llx %7s %llx %x:%x %llu %1023[^\n]",
                             &start, &end, perms, &fileOff,
                             &devMajor, &devMinor, &inode, path);

        if (n < 7) continue;   // minimum fields: addr range + perms + offset + dev + inode

        m.startAddr  = start;
        m.endAddr    = end;
        m.perms      = perms;
        m.fileOffset = fileOff;

        if (n >= 8) {
            // Trim leading spaces
            char* p = path;
            while (*p == ' ') ++p;
            m.path = p;
        }

        result.push_back(std::move(m));
    }

    return result;
}

// ── Public: enumerate loaded libs via dl_iterate_phdr (link_map) ─────────────

// dl_iterate_phdr is in <link.h> on Linux/glibc but not on macOS.
// Use dlsym to resolve it at runtime for cross-platform compatibility.
// Define the needed types locally since <link.h> may not be available.
namespace {

#pragma pack(push, 1)
struct LocalElf64Phdr {
    std::uint32_t p_type;
    std::uint32_t p_flags;
    std::uint64_t p_offset;
    std::uint64_t p_vaddr;
    std::uint64_t p_paddr;
    std::uint64_t p_filesz;
    std::uint64_t p_memsz;
    std::uint64_t p_align;
};
#pragma pack(pop)

// Mirror of struct dl_phdr_info — enough fields for our use.
struct PhdrInfo {
    std::uint64_t dlpi_addr;
    const char* dlpi_name;
    const LocalElf64Phdr* dlpi_phdr;
    std::uint16_t dlpi_phnum;
};

using DlIterateCallback = int (*)(PhdrInfo*, std::size_t, void*);
using DlIteratePhdrFn   = int (*)(DlIterateCallback, void*);

static DlIteratePhdrFn resolveDlIteratePhdr() {
    auto* fn = reinterpret_cast<DlIteratePhdrFn>(
        dlsym(RTLD_DEFAULT, "dl_iterate_phdr"));
    return fn;
}

int dlCallback(PhdrInfo* info, std::size_t /*size*/, void* data) {
    auto* libs = static_cast<std::vector<LoadedLibrary>*>(data);

    LoadedLibrary lib;
    lib.name     = (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "";
    lib.baseAddr = info->dlpi_addr;

    std::uint64_t maxVaddr = 0;
    std::uint64_t minVaddr = ~std::uint64_t{0};

    for (std::uint16_t i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type != kPtLoad) continue;
        const auto vaddr = info->dlpi_phdr[i].p_vaddr;
        const auto memsz = info->dlpi_phdr[i].p_memsz;
        if (vaddr < minVaddr) minVaddr = vaddr;
        if (vaddr + memsz > maxVaddr) maxVaddr = vaddr + memsz;
    }

    if (minVaddr < maxVaddr) {
        lib.virtSize = maxVaddr;
    }

    // Skip the main executable and vdso/vvar
    if (!lib.name.empty() && lib.name.find("linux-") == std::string::npos) {
        libs->push_back(std::move(lib));
    }

    return 0;
}

}  // namespace

std::vector<LoadedLibrary> enumerateLoadedLibsViaLinkMap() {
    std::vector<LoadedLibrary> result;
    auto dlIterate = resolveDlIteratePhdr();
    if (dlIterate) {
        dlIterate(dlCallback, &result);
    }
    return result;
}

// ── Public: parse ELF ident from memory ─────────────────────────────────────

bool parseElfIdent(const std::uint8_t* addr, std::size_t rangeSize, ElfIdent& out) {
    if (rangeSize < 64) return false;
    if (addr[0] != 0x7F || addr[1] != 'E' || addr[2] != 'L' || addr[3] != 'F')
        return false;

    out.is64Bit = (addr[4] == kElfClass64);
    if (addr[4] != kElfClass32 && addr[4] != kElfClass64) return false;
    if (addr[5] != kElfData2LSB) return false;   // LE only

    out.type  = readU16LE(addr + 16);
    if (out.is64Bit) {
        out.entry     = readU64LE(addr + 24);
        out.phoff     = readU64LE(addr + 32);
        out.phentsize = readU16LE(addr + 54);
        out.phnum     = readU16LE(addr + 56);
    } else {
        out.entry     = readU32LE(addr + 24);
        out.phoff     = readU32LE(addr + 28);
        out.phentsize = readU16LE(addr + 42);
        out.phnum     = readU16LE(addr + 44);
    }

    return true;
}

// ── Public: read ELF program header from memory ─────────────────────────────

bool readElfPhdr(const std::uint8_t* elfBase, std::size_t rangeSize,
                 const ElfIdent& ident, std::uint16_t index, ElfPhdr& out) {
    if (index >= ident.phnum) return false;
    const std::uint64_t offset = ident.phoff + static_cast<std::uint64_t>(index) * ident.phentsize;
    if (offset + ident.phentsize > rangeSize) return false;

    out.type = readU32LE(elfBase + offset);

    if (ident.is64Bit) {
        out.flags  = readU32LE(elfBase + offset + 4);
        out.offset = readU64LE(elfBase + offset + 8);
        out.vaddr  = readU64LE(elfBase + offset + 16);
        out.filesz = readU64LE(elfBase + offset + 32);
        out.memsz  = readU64LE(elfBase + offset + 40);
    } else {
        out.offset = readU32LE(elfBase + offset + 4);
        out.vaddr  = readU32LE(elfBase + offset + 8);
        out.filesz = readU32LE(elfBase + offset + 16);
        out.memsz  = readU32LE(elfBase + offset + 20);
        out.flags  = readU32LE(elfBase + offset + 24);
    }

    return true;
}

// ── Public: compute SHA256 of in-memory range ───────────────────────────────

std::string computeMemorySha256(const void* addr, std::size_t size) {
    if (addr == nullptr || size == 0) return {};
    return sha256Hex(static_cast<const std::uint8_t*>(addr), size);
}

// ── Public: scan memory for ABC (PANDA) files ───────────────────────────────

std::vector<ScannedAbc> scanMemoryForAbcFiles() {
    std::vector<ScannedAbc> result;
    const auto mappings = parseProcSelfMaps();

    for (const auto& m : mappings) {
        // Only scan readable regions
        if (m.perms.empty() || m.perms[0] != 'r') continue;
        if (m.endAddr <= m.startAddr) continue;

        const std::size_t rangeSize = static_cast<std::size_t>(m.endAddr - m.startAddr);
        if (rangeSize < kAbcHeaderSize) continue;

        const auto* base = reinterpret_cast<const std::uint8_t*>(m.startAddr);

        // Scan for PANDA magic. ABC files start with "PANDA\0\0\0" (8 bytes).
        // The magic is little-endian: bytes are 'P','A','N','D','A',0,0,0
        //
        // For file-backed mappings, PANDA magic is at offset 0.
        // For anonymous mappings, we need to scan.
        for (std::size_t off = 0; off + 8 <= rangeSize; off += 8) {
            if (base[off]     != 'P' || base[off + 1] != 'A' ||
                base[off + 2] != 'N' || base[off + 3] != 'D' ||
                base[off + 4] != 'A' || base[off + 5] != 0x00 ||
                base[off + 6] != 0x00 || base[off + 7] != 0x00) {
                continue;
            }

            // Found PANDA magic. Read file size from header.
            // PandaFileHeader: magic(8) + checksum(4) + version(4) + file_size(4) + ...
            // file_size is at offset 16 in the header (after the reserved field).
            // Actually, let's check the actual format:
            // offset 0:  magic (8 bytes)
            // offset 8:  checksum (4 bytes)  
            // offset 12: version (4 bytes) - actually let me be more careful
            //
            // From arkcompiler source: PandaFileHeader layout
            // uint32_t magic[2];   // 8 bytes - "PANDA\0\0\0"
            // uint32_t checksum;   // 4 bytes at offset 8
            // uint8_t  version[4]; // version bytes at offset 12
            // uint32_t file_size;  // at offset 16
            //
            // Let me just compute hash of a reasonable size. The file_size
            // in the header tells us the total size.

            if (off + 20 > rangeSize) continue;

            std::uint32_t fileSize = readU32LE(base + off + 16);
            if (fileSize == 0 || fileSize > rangeSize - off) {
                // file_size might be zero or invalid; skip
                continue;
            }

            ScannedAbc abc;
            abc.startAddr = m.startAddr + off;
            abc.size      = fileSize;
            abc.sha256    = computeMemorySha256(base + off,
                                                 static_cast<std::size_t>(fileSize));
            result.push_back(std::move(abc));
            break;   // one abc per mapped region
        }
    }

    return result;
}

// ── RuntimeVerifyResult helpers ─────────────────────────────────────────────

bool RuntimeVerifyResult::allSoPassed() const {
    for (const auto& r : soResults) {
        if (!r.match) return false;
    }
    return !soResults.empty();
}

bool RuntimeVerifyResult::allAbcPassed() const {
    for (const auto& r : abcResults) {
        if (!r.match) return false;
    }
    return !abcResults.empty();
}

bool RuntimeVerifyResult::allPassed() const {
    if (soResults.empty() && abcResults.empty()) return false;
    return allSoPassed() && allAbcPassed();
}

int RuntimeVerifyResult::totalSoSegments() const {
    return static_cast<int>(soResults.size());
}

int RuntimeVerifyResult::passedSoSegments() const {
    int n = 0;
    for (const auto& r : soResults) { if (r.match) ++n; }
    return n;
}

int RuntimeVerifyResult::totalAbc() const {
    return static_cast<int>(abcResults.size());
}

int RuntimeVerifyResult::passedAbc() const {
    int n = 0;
    for (const auto& r : abcResults) { if (r.match) ++n; }
    return n;
}

// ── Public: main runtime verification ───────────────────────────────────────

RuntimeVerifyResult verifyRuntimeIntegrity(
    const std::vector<SoReferenceHash>&  soRefs,
    const std::vector<AbcReferenceHash>& abcRefs)
{
    RuntimeVerifyResult result;
    const auto mappings = parseProcSelfMaps();

    if (mappings.empty()) {
        result.warnings.push_back("Failed to read /proc/self/maps — platform may not support runtime verification.");
        return result;
    }

    // ── Group mappings by path ──────────────────────────────────────────
    // For each mapped .so file, group all memory regions.
    struct MappedLib {
        std::string path;
        std::uint64_t baseAddr = 0;   // lowest start address (load base)
        std::vector<MemoryMapping> regions;
    };

    std::vector<MappedLib> mappedLibs;
    for (const auto& m : mappings) {
        if (m.path.empty()) continue;
        // Check if path ends with .so
        if (m.path.size() < 3 || m.path.substr(m.path.size() - 3) != ".so") {
            // Also check for .abc files
            if (m.path.size() >= 4 && m.path.substr(m.path.size() - 4) == ".abc") {
                // .abc files handled separately via scanMemoryForAbcFiles()
            }
            continue;
        }

        // Find existing entry or create new
        bool found = false;
        for (auto& lib : mappedLibs) {
            // Match by filename suffix (process might have different prefix paths)
            const auto& existing = lib.path;
            if (m.path.size() <= existing.size()) {
                if (existing.compare(existing.size() - m.path.size(), m.path.size(), m.path) == 0)
                    { lib.regions.push_back(m); found = true; break; }
            } else {
                if (m.path.compare(m.path.size() - existing.size(), existing.size(), existing) == 0)
                    { lib.regions.push_back(m); found = true; break; }
            }
        }
        if (!found) {
            MappedLib lib;
            lib.path = m.path;
            lib.regions.push_back(m);
            mappedLibs.push_back(std::move(lib));
        }
    }

    // Compute load base (lowest vaddr) for each mapped lib
    for (auto& lib : mappedLibs) {
        lib.baseAddr = ~std::uint64_t{0};
        for (const auto& r : lib.regions) {
            if (r.startAddr < lib.baseAddr) lib.baseAddr = r.startAddr;
        }
    }

    // ── Cross-reference with link_map ──────────────────────────────────
    const auto linkMapLibs = enumerateLoadedLibsViaLinkMap();

    // Build a set of .so basenames seen in /proc/maps
    std::set<std::string> mapsBasenames;
    for (const auto& lib : mappedLibs) {
        auto pos = lib.path.rfind('/');
        mapsBasenames.insert(pos != std::string::npos
                             ? lib.path.substr(pos + 1)
                             : lib.path);
    }

    // Flag any library in link_map that is absent from /proc/maps
    for (const auto& ll : linkMapLibs) {
        auto pos = ll.name.rfind('/');
        std::string basename = (pos != std::string::npos)
                               ? ll.name.substr(pos + 1)
                               : ll.name;
        if (!basename.empty() && mapsBasenames.find(basename) == mapsBasenames.end()) {
            result.warnings.push_back(
                "link_map reports '" + basename +
                "' but it is missing from /proc/self/maps — maps may have been tampered with.");
        }
    }

    // If /proc/maps yielded no .so mappings but link_map has them,
    // fall back to link_map for the mapped libraries.
    if (mappedLibs.empty() && !linkMapLibs.empty()) {
        for (const auto& ll : linkMapLibs) {
            MappedLib ml;
            ml.path     = ll.name;
            ml.baseAddr = ll.baseAddr;
            // Create a single synthetic region spanning the library
            MemoryMapping mm;
            mm.startAddr = ll.baseAddr;
            mm.endAddr   = ll.baseAddr + ll.virtSize;
            mm.perms     = "r--p";           // conservative: at least readable
            mm.fileOffset = 0;
            mm.path       = ll.name;
            ml.regions.push_back(std::move(mm));
            mappedLibs.push_back(std::move(ml));
        }
    }

    // ── Verify .so files ────────────────────────────────────────────────
    for (const auto& ref : soRefs) {
        // Find matching mapped library by filename suffix
        const MappedLib* mappedLib = nullptr;
        const auto refBasename = [&]() -> std::string {
            auto pos = ref.fileName.rfind('/');
            return (pos != std::string::npos) ? ref.fileName.substr(pos + 1) : ref.fileName;
        }();

        for (const auto& lib : mappedLibs) {
            if (lib.path.find(refBasename) != std::string::npos) {
                mappedLib = &lib;
                break;
            }
        }

        if (mappedLib == nullptr) {
            // .so not loaded in this process
            for (const auto& seg : ref.segments) {
                SoSegmentVerifyResult r;
                r.soFileName    = ref.fileName;
                r.segmentInfo   = "PT_LOAD";
                r.expectedOffset = seg.fileOffset;
                r.expectedSize   = seg.fileSize;
                r.expectedSha256 = seg.sha256;
                r.error          = "not-loaded";
                result.soResults.push_back(std::move(r));
            }
            continue;
        }

        // For each reference segment, find matching memory region and verify
        for (const auto& seg : ref.segments) {
            SoSegmentVerifyResult r;
            r.soFileName     = ref.fileName;
            r.expectedOffset = seg.fileOffset;
            r.expectedSize   = seg.fileSize;
            r.expectedSha256 = seg.sha256;

            // Build segment info string
            {
                std::ostringstream ss;
                ss << "PT_LOAD";
                if (seg.segmentFlags & kPfR) ss << " R";
                if (seg.segmentFlags & kPfW) ss << " W";
                if (seg.segmentFlags & kPfX) ss << " X";
                r.segmentInfo = ss.str();
            }

            // Find the memory region that covers vaddr .. vaddr+filesz
            const std::uint64_t segVaddr = mappedLib->baseAddr + seg.virtualAddr;
            const std::uint64_t segEnd   = segVaddr + seg.fileSize;

            const MemoryMapping* match = nullptr;
            for (const auto& region : mappedLib->regions) {
                if (region.startAddr <= segVaddr && region.endAddr >= segEnd) {
                    match = &region;
                    break;
                }
            }

            if (match == nullptr) {
                r.error = "segment-not-mapped";
                result.soResults.push_back(std::move(r));
                continue;
            }

            // Verify the segment is readable (we need 'r' permission)
            if (match->perms.empty() || match->perms[0] != 'r') {
                r.error = "segment-not-readable";
                result.soResults.push_back(std::move(r));
                continue;
            }

            // Compute runtime hash
            const auto* segData = reinterpret_cast<const std::uint8_t*>(segVaddr);
            r.actualStartAddr = segVaddr;
            r.actualSize      = seg.fileSize;
            r.actualSha256    = computeMemorySha256(segData, static_cast<std::size_t>(seg.fileSize));

            r.match = (r.expectedSha256 == r.actualSha256);
            if (!r.match) {
                r.error = "hash-mismatch";
            }

            result.soResults.push_back(std::move(r));
        }
    }

    // ── Verify .abc files ───────────────────────────────────────────────
    const auto scannedAbcs = scanMemoryForAbcFiles();

    for (const auto& ref : abcRefs) {
        AbcVerifyResult r;
        r.abcFileName   = ref.fileName;
        r.expectedSha256 = ref.sha256;

        bool foundMatch = false;
        for (const auto& scanned : scannedAbcs) {
            r.actualSha256 = scanned.sha256;
            r.found = true;
            if (scanned.sha256 == ref.sha256) {
                r.match = true;
                foundMatch = true;
                break;
            }
        }

        if (!r.found) {
            r.error = "not-found-in-memory";
        } else if (!foundMatch) {
            r.error = "hash-mismatch";
        }

        result.abcResults.push_back(std::move(r));
    }

    // If we have refs but found no mapped libs, warn
    if (!soRefs.empty() && mappedLibs.empty()) {
        result.warnings.push_back("No .so files found in process memory maps. "
                                  "Ensure /proc/self/maps is accessible.");
    }

    return result;
}
