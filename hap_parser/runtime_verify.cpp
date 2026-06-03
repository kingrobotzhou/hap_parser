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

// ── Anonymous helpers ───────────────────────────────────────────────────────

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

struct ElfFileHeader {
    bool     is64 = false;
    bool     isLE = true;
    std::uint16_t type = 0;
    std::uint64_t phoff = 0;
    std::uint16_t phnum = 0;
    std::uint16_t phentsize = 0;
};

bool parseElfFileHeader(const std::uint8_t* data, std::size_t size,
                         ElfFileHeader& ehdr) {
    if (size < 64) return false;
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F')
        return false;
    ehdr.is64 = (data[4] == kElfClass64);
    if (data[4] != kElfClass32 && data[4] != kElfClass64) return false;
    if (data[5] != kElfData2LSB) return false;
    ehdr.isLE = true;
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

struct PhdrInfo {
    std::uint64_t dlpi_addr;
    const char* dlpi_name;
    const LocalElf64Phdr* dlpi_phdr;
    std::uint16_t dlpi_phnum;
};

using DlCb  = int (*)(PhdrInfo*, std::size_t, void*);
using DlFn  = int (*)(DlCb, void*);

DlFn resolveDlIteratePhdr() {
    return reinterpret_cast<DlFn>(dlsym(RTLD_DEFAULT, "dl_iterate_phdr"));
}

int linkMapCallback(PhdrInfo* info, std::size_t, void* data) {
    auto* libs = static_cast<std::vector<LoadedLibrary>*>(data);
    LoadedLibrary lib;
    lib.name = (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "";
    lib.baseAddr = info->dlpi_addr;
    std::uint64_t maxV = 0, minV = ~std::uint64_t{0};
    for (std::uint16_t i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type != kPtLoad) continue;
        auto vaddr = info->dlpi_phdr[i].p_vaddr;
        auto memsz = info->dlpi_phdr[i].p_memsz;
        if (vaddr < minV) minV = vaddr;
        if (vaddr + memsz > maxV) maxV = vaddr + memsz;
    }
    if (minV < maxV) lib.virtSize = maxV;
    if (!lib.name.empty()) libs->push_back(std::move(lib));
    return 0;
}

}  // anonymous namespace

// ── Public: load reference hashes ───────────────────────────────────────────

void RuntimeVerifier::load(const std::vector<SoReferenceHash>&  so,
                            const std::vector<AbcReferenceHash>& abc) {
    soRefs_  = so;
    abcRefs_ = abc;
}

// ── Private static: ELF segment extraction from raw bytes ──────────────────

std::vector<ElfSegmentHash> RuntimeVerifier::extractElfSegments(
    const std::uint8_t* data, std::size_t size)
{
    std::vector<ElfSegmentHash> results;
    ElfFileHeader ehdr;
    if (!parseElfFileHeader(data, size, ehdr)) return results;

    for (std::uint16_t i = 0; i < ehdr.phnum; ++i) {
        std::uint64_t off = ehdr.phoff + static_cast<std::uint64_t>(i) * ehdr.phentsize;
        if (off + ehdr.phentsize > size) break;
        std::uint32_t pType = readU32LE(data + off);
        if (pType != kPtLoad) continue;

        std::uint64_t pOffset, pVaddr, pFilesz, pMemsz;
        std::uint32_t pFlags;
        if (ehdr.is64) {
            pFlags  = readU32LE(data + off + 4);
            pOffset = readU64LE(data + off + 8);
            pVaddr  = readU64LE(data + off + 16);
            pFilesz = readU64LE(data + off + 32);
            pMemsz  = readU64LE(data + off + 40);
        } else {
            pOffset = readU32LE(data + off + 4);
            pVaddr  = readU32LE(data + off + 8);
            pFilesz = readU32LE(data + off + 16);
            pMemsz  = readU32LE(data + off + 20);
            pFlags  = readU32LE(data + off + 24);
        }
        if (pFilesz == 0) continue;
        if (pOffset + pFilesz > size) break;

        ElfSegmentHash seg;
        seg.segmentType  = pType;
        seg.segmentFlags = pFlags;
        seg.fileOffset   = pOffset;
        seg.fileSize     = pFilesz;
        seg.virtualAddr  = pVaddr;
        seg.sha256       = sha256Hex(data + pOffset,
                                      static_cast<std::size_t>(pFilesz));
        results.push_back(std::move(seg));
    }
    return results;
}

// ── Private static: extract .so reference hashes ────────────────────────────

std::vector<SoReferenceHash> RuntimeVerifier::extractSoRefs(
    const std::vector<std::uint8_t>& hapBytes,
    const std::vector<std::string>&  soNames,
    const std::vector<std::pair<std::int64_t, std::int64_t>>& soOffsetsSizes)
{
    std::vector<SoReferenceHash> result;
    for (std::size_t i = 0; i < soNames.size() && i < soOffsetsSizes.size(); ++i) {
        auto offset = static_cast<std::size_t>(soOffsetsSizes[i].first);
        auto size   = static_cast<std::size_t>(soOffsetsSizes[i].second);
        if (offset + size > hapBytes.size()) continue;
        const auto* data = hapBytes.data() + offset;
        SoReferenceHash ref;
        ref.fileName       = soNames[i];
        ref.fullFileSha256 = sha256Hex(data, size);
        ref.segments       = extractElfSegments(data, size);
        result.push_back(std::move(ref));
    }
    return result;
}

// ── Private static: extract .abc reference hashes ───────────────────────────

std::vector<AbcReferenceHash> RuntimeVerifier::extractAbcRefs(
    const std::vector<std::pair<std::string, std::string>>& abcNameSha256)
{
    std::vector<AbcReferenceHash> result;
    for (const auto& entry : abcNameSha256) {
        const auto& name = entry.first;
        if (name.size() < 4) continue;
        if (name.substr(name.size() - 4) != ".abc"
            && name.find(".abc") == std::string::npos) continue;
        result.push_back({name, entry.second});
    }
    return result;
}

// ── Private static: /proc/self/maps parsing ─────────────────────────────────

std::vector<MemoryMapping> RuntimeVerifier::parseProcMaps() {
    std::vector<MemoryMapping> result;
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return result;

    std::string line;
    while (std::getline(maps, line)) {
        MemoryMapping m;
        char perms[8] = {};
        char path[1024] = {};
        unsigned long long start = 0, end = 0, fileOff = 0, inode = 0;
        unsigned int devMajor = 0, devMinor = 0;
        int n = std::sscanf(line.c_str(), "%llx-%llx %7s %llx %x:%x %llu %1023[^\n]",
                             &start, &end, perms, &fileOff,
                             &devMajor, &devMinor, &inode, path);
        if (n < 7) continue;
        m.startAddr  = start;
        m.endAddr    = end;
        m.perms      = perms;
        m.fileOffset = fileOff;
        if (n >= 8) {
            char* p = path; while (*p == ' ') ++p;
            m.path = p;
        }
        result.push_back(std::move(m));
    }
    return result;
}

// ── Private static: link_map enumeration ────────────────────────────────────

std::vector<LoadedLibrary> RuntimeVerifier::enumerateLinkMap() {
    std::vector<LoadedLibrary> result;
    auto fn = resolveDlIteratePhdr();
    if (fn) fn(linkMapCallback, &result);
    return result;
}

// ── Private static: ELF ident parsing from memory ──────────────────────────

bool RuntimeVerifier::parseElfIdent(const std::uint8_t* addr, std::size_t range,
                                     ElfIdent& out) {
    if (range < 64) return false;
    if (addr[0] != 0x7F || addr[1] != 'E' || addr[2] != 'L' || addr[3] != 'F')
        return false;
    out.is64Bit = (addr[4] == kElfClass64);
    if (addr[4] != kElfClass32 && addr[4] != kElfClass64) return false;
    if (addr[5] != kElfData2LSB) return false;
    out.type = readU16LE(addr + 16);
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

// ── Private static: ELF program header reading from memory ──────────────────

bool RuntimeVerifier::readPhdr(const std::uint8_t* base, std::size_t range,
                                const ElfIdent& ident, std::uint16_t idx,
                                ElfPhdr& out) {
    if (idx >= ident.phnum) return false;
    auto off = ident.phoff + static_cast<std::uint64_t>(idx) * ident.phentsize;
    if (off + ident.phentsize > range) return false;
    out.type = readU32LE(base + off);
    if (ident.is64Bit) {
        out.flags  = readU32LE(base + off + 4);
        out.offset = readU64LE(base + off + 8);
        out.vaddr  = readU64LE(base + off + 16);
        out.filesz = readU64LE(base + off + 32);
        out.memsz  = readU64LE(base + off + 40);
    } else {
        out.offset = readU32LE(base + off + 4);
        out.vaddr  = readU32LE(base + off + 8);
        out.filesz = readU32LE(base + off + 16);
        out.memsz  = readU32LE(base + off + 20);
        out.flags  = readU32LE(base + off + 24);
    }
    return true;
}

// ── Private static: SHA256 of in-memory range ──────────────────────────────

std::string RuntimeVerifier::sha256(const void* addr, std::size_t size) {
    if (!addr || !size) return {};
    return sha256Hex(static_cast<const std::uint8_t*>(addr), size);
}

// ── Private static: scan memory for ABC (PANDA) files ──────────────────────

std::vector<ScannedAbc> RuntimeVerifier::scanAbcInMemory() {
    std::vector<ScannedAbc> result;
    auto mappings = parseProcMaps();
    for (const auto& m : mappings) {
        if (m.perms.empty() || m.perms[0] != 'r') continue;
        if (m.endAddr <= m.startAddr) continue;
        auto rangeSize = static_cast<std::size_t>(m.endAddr - m.startAddr);
        if (rangeSize < kAbcHeaderSize) continue;
        auto* base = reinterpret_cast<const std::uint8_t*>(m.startAddr);
        for (std::size_t off = 0; off + 8 <= rangeSize; off += 8) {
            if (base[off] != 'P' || base[off+1] != 'A' ||
                base[off+2] != 'N' || base[off+3] != 'D' ||
                base[off+4] != 'A' || base[off+5] != 0 ||
                base[off+6] != 0   || base[off+7] != 0) continue;
            if (off + 20 > rangeSize) continue;
            auto fileSize = readU32LE(base + off + 16);
            if (fileSize == 0 || fileSize > rangeSize - off) continue;
            ScannedAbc abc;
            abc.startAddr = m.startAddr + off;
            abc.size      = fileSize;
            abc.sha256    = sha256(base + off, fileSize);
            result.push_back(std::move(abc));
            break;
        }
    }
    return result;
}

// ── RuntimeVerifyResult helpers ─────────────────────────────────────────────

bool RuntimeVerifyResult::allSoPassed() const {
    for (auto& r : soResults) if (!r.match) return false;
    return !soResults.empty();
}
bool RuntimeVerifyResult::allAbcPassed() const {
    for (auto& r : abcResults) if (!r.match) return false;
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
    int n = 0; for (auto& r : soResults) if (r.match) ++n; return n;
}
int RuntimeVerifyResult::totalAbc() const {
    return static_cast<int>(abcResults.size());
}
int RuntimeVerifyResult::passedAbc() const {
    int n = 0; for (auto& r : abcResults) if (r.match) ++n; return n;
}

// ── Public: main runtime verification ───────────────────────────────────────

RuntimeVerifyResult RuntimeVerifier::verify() const {
    RuntimeVerifyResult result;
    auto mappings = parseProcMaps();

    if (mappings.empty()) {
        result.warnings.push_back(
            "Failed to read /proc/self/maps — platform may not support runtime verification.");
        return result;
    }

    // ── Group mappings by path ──────────────────────────────────────────
    struct MappedLib {
        std::string path;
        std::uint64_t baseAddr = 0;
        std::vector<MemoryMapping> regions;
    };
    std::vector<MappedLib> mappedLibs;
    for (const auto& m : mappings) {
        if (m.path.empty()) continue;
        if (m.path.size() < 3 || m.path.substr(m.path.size() - 3) != ".so") continue;
        bool found = false;
        for (auto& lib : mappedLibs) {
            const auto& ex = lib.path;
            if (m.path.size() <= ex.size()) {
                if (ex.compare(ex.size() - m.path.size(), m.path.size(), m.path) == 0)
                    { lib.regions.push_back(m); found = true; break; }
            } else {
                if (m.path.compare(m.path.size() - ex.size(), ex.size(), ex) == 0)
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
    for (auto& lib : mappedLibs) {
        lib.baseAddr = ~std::uint64_t{0};
        for (auto& r : lib.regions)
            if (r.startAddr < lib.baseAddr) lib.baseAddr = r.startAddr;
    }

    // ── link_map cross-reference ────────────────────────────────────────
    auto linkMapLibs = enumerateLinkMap();
    std::set<std::string> mapsBasenames;
    for (auto& lib : mappedLibs) {
        auto pos = lib.path.rfind('/');
        mapsBasenames.insert(pos != std::string::npos ? lib.path.substr(pos+1) : lib.path);
    }
    for (auto& ll : linkMapLibs) {
        auto pos = ll.name.rfind('/');
        auto bn = pos != std::string::npos ? ll.name.substr(pos+1) : ll.name;
        if (!bn.empty() && mapsBasenames.find(bn) == mapsBasenames.end()) {
            result.warnings.push_back(
                "link_map reports '" + bn +
                "' but it is missing from /proc/self/maps — maps may have been tampered with.");
        }
    }
    if (mappedLibs.empty() && !linkMapLibs.empty()) {
        for (auto& ll : linkMapLibs) {
            MappedLib ml;
            ml.path = ll.name;
            ml.baseAddr = ll.baseAddr;
            MemoryMapping mm;
            mm.startAddr = ll.baseAddr;
            mm.endAddr   = ll.baseAddr + ll.virtSize;
            mm.perms     = "r--p";
            mm.path      = ll.name;
            ml.regions.push_back(std::move(mm));
            mappedLibs.push_back(std::move(ml));
        }
    }

    // ── Verify .so files ────────────────────────────────────────────────
    for (const auto& ref : soRefs_) {
        std::string refBn;
        { auto pos = ref.fileName.rfind('/');
          refBn = pos != std::string::npos ? ref.fileName.substr(pos+1) : ref.fileName; }
        const MappedLib* mappedLib = nullptr;
        for (auto& lib : mappedLibs) {
            if (lib.path.find(refBn) != std::string::npos) {
                mappedLib = &lib; break;
            }
        }
        if (!mappedLib) {
            for (auto& seg : ref.segments) {
                SoSegmentVerifyResult r;
                r.soFileName = ref.fileName;
                r.expectedOffset = seg.fileOffset;
                r.expectedSize   = seg.fileSize;
                r.expectedSha256 = seg.sha256;
                r.error = "not-loaded";
                result.soResults.push_back(std::move(r));
            }
            continue;
        }
        for (auto& seg : ref.segments) {
            SoSegmentVerifyResult r;
            r.soFileName     = ref.fileName;
            r.expectedOffset = seg.fileOffset;
            r.expectedSize   = seg.fileSize;
            r.expectedSha256 = seg.sha256;
            std::ostringstream ss;
            ss << "PT_LOAD";
            if (seg.segmentFlags & kPfR) ss << " R";
            if (seg.segmentFlags & kPfW) ss << " W";
            if (seg.segmentFlags & kPfX) ss << " X";
            r.segmentInfo = ss.str();
            auto segVaddr = mappedLib->baseAddr + seg.virtualAddr;
            auto segEnd   = segVaddr + seg.fileSize;
            const MemoryMapping* match = nullptr;
            for (auto& region : mappedLib->regions) {
                if (region.startAddr <= segVaddr && region.endAddr >= segEnd) {
                    match = &region; break;
                }
            }
            if (!match) {
                r.error = "segment-not-mapped";
                result.soResults.push_back(std::move(r));
                continue;
            }
            if (match->perms.empty() || match->perms[0] != 'r') {
                r.error = "segment-not-readable";
                result.soResults.push_back(std::move(r));
                continue;
            }
            r.actualStartAddr = segVaddr;
            r.actualSize      = seg.fileSize;
            r.actualSha256    = sha256(reinterpret_cast<const void*>(segVaddr),
                                       static_cast<std::size_t>(seg.fileSize));
            r.match = (r.expectedSha256 == r.actualSha256);
            if (!r.match) r.error = "hash-mismatch";
            result.soResults.push_back(std::move(r));
        }
    }

    // ── Verify .abc files ───────────────────────────────────────────────
    auto scannedAbcs = scanAbcInMemory();
    for (const auto& ref : abcRefs_) {
        AbcVerifyResult r;
        r.abcFileName   = ref.fileName;
        r.expectedSha256 = ref.sha256;
        for (auto& sc : scannedAbcs) {
            r.actualSha256 = sc.sha256;
            r.found = true;
            if (sc.sha256 == ref.sha256) { r.match = true; break; }
        }
        if (!r.found) r.error = "not-found-in-memory";
        else if (!r.match) r.error = "hash-mismatch";
        result.abcResults.push_back(std::move(r));
    }

    if (!soRefs_.empty() && mappedLibs.empty()) {
        result.warnings.push_back(
            "No .so files found in process memory maps.");
    }
    return result;
}
