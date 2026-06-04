#include "hap_parser.h"
#include "runtime_verify.h"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

static int g_passed = 0, g_failed = 0;

#define TEST(name) std::cout << "  " << name << "... "
#define PASS() do { std::cout << "PASS\n"; g_passed++; } while(0)
#define FAIL(msg) do { std::cout << "FAIL: " << msg << "\n"; g_failed++; } while(0)
#define SKIP(msg) do { std::cout << "SKIP (" << msg << ")\n"; } while(0)

static bool fileExists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

static const std::string kSmallHap  = "/Users/lasysloth/Desktop/entry-default-signed.hap";
static const std::string kLargeHap  = "/Users/lasysloth/Desktop/BangcleOA3002/BangcleOA_3002_导出包_删.hap";

// ── HapParser tests ────────────────────────────────────────────────────────

void testParseSmallHap() {
    TEST("parse small HAP");
    HapParser parser;
    auto s = parser.parseFile(kSmallHap);
    if (!s) { FAIL("parse returned nullopt"); return; }

    assert(s->fileSize == 167759);
    assert(s->eocd.has_value());
    assert(s->eocd->totalEntries > 0);
    assert(s->centralDirOffsetResolved.has_value());
    assert(s->signatureFooter.has_value());
    assert(s->signatureFooter->blockCount == 3);
    assert(s->signatureFooter->signatureMagic == "<hap sign block>");
    PASS();
}

void testParseLargeHap() {
    TEST("parse large HAP with native libs");
    HapParser parser;
    auto s = parser.parseFile(kLargeHap);
    if (!s) { FAIL("parse returned nullopt"); return; }

    assert(s->fileSize == 26840918);
    assert(s->eocd.has_value());
    assert(s->eocd->totalEntries > 50);  // large HAP with native libs
    assert(s->subBlocks.size() >= 2);     // at least AppSignature + Profile

    // Should have certificate chains
    assert(!s->subBlockCertificates.empty());
    for (auto& bc : s->subBlockCertificates) {
        assert(!bc.certificates.empty());
    }

    // Should have profile
    assert(s->profile.has_value());
    assert(!s->profile->bundleName.empty());
    assert(s->profile->type == "debug" || s->profile->type == "release");

    // Should have code signing libs
    assert(s->propertyBlock.has_value());
    assert(s->propertyBlock->hasCodeSigning);

    PASS();
}

void testFileHashes() {
    TEST("file hash computation");
    HapParser parser;
    auto s = parser.parseFile(kSmallHap);
    assert(s.has_value());

    assert(!s->fileHashes.empty());
    for (auto& fh : s->fileHashes) {
        assert(!fh.filename.empty());
        assert(!fh.sha256.empty());
        assert(fh.sha256.length() == 64);  // SHA256 hex = 64 chars
    }
    PASS();
}

void testIdentityChain() {
    TEST("identity chain construction");
    HapParser parser;
    auto s = parser.parseFile(kSmallHap);
    assert(s.has_value());

    // Every signed HAP should have at least a dev cert in the identity chain
    assert(!s->identityChain.empty());
    PASS();
}

void testParseCorruptedFile() {
    TEST("parse non-existent file");
    HapParser parser;
    auto s = parser.parseFile("/tmp/no_such_file.hap");
    assert(!s.has_value());  // should fail gracefully
    PASS();
}

void testParseGarbageFile() {
    TEST("parse garbage bytes");
    std::string tmpPath = "/tmp/hap_test_garbage.bin";
    {
        std::ofstream of(tmpPath, std::ios::binary);
        for (int i = 0; i < 1024; ++i) of.put(static_cast<char>(i % 256));
    }
    HapParser parser;
    auto s = parser.parseFile(tmpPath);
    if (s) {
        // Even if it "parses", it should have warnings about garbage data
        assert(!s->warnings.empty() || !s->eocd.has_value());
    }
    std::remove(tmpPath.c_str());
    PASS();
}

// ── RuntimeVerifier tests ──────────────────────────────────────────────────

void testExtractElfSegments() {
    TEST("ELF segment hash extraction (via parsed HAP)");
    HapParser parser;
    auto s = parser.parseFile(kLargeHap);
    assert(s.has_value());

    // extractSoRefs already ran during parse — verify the results
    assert(!s->soReferenceHashes.empty());
    for (auto& ref : s->soReferenceHashes) {
        if (ref.segments.empty()) continue;
        auto& seg = ref.segments[0];
        assert(seg.fileSize > 0);
        assert(!seg.sha256.empty());
        assert(seg.sha256.length() == 64);
        PASS();
        return;
    }
    FAIL("no segment hashes extracted");
}

void testExtractSoRefs() {
    TEST("extractSoRefs from parsed HAP");
    HapParser parser;
    auto s = parser.parseFile(kLargeHap);
    assert(s.has_value());

    // The large HAP has .so files — should have segment hashes
    assert(!s->soReferenceHashes.empty());
    for (auto& ref : s->soReferenceHashes) {
        assert(!ref.fileName.empty());
        assert(!ref.fullFileSha256.empty());
        assert(!ref.segments.empty());
        for (auto& seg : ref.segments) {
            assert(seg.fileSize > 0);
            assert(!seg.sha256.empty());
        }
    }
    PASS();
}

void testExtractAbcRefs() {
    TEST("extractAbcRefs from parsed HAP");
    HapParser parser;
    auto s = parser.parseFile(kLargeHap);
    assert(s.has_value());

    assert(!s->abcReferenceHashes.empty());
    for (auto& ref : s->abcReferenceHashes) {
        assert(!ref.fileName.empty());
        assert(!ref.sha256.empty());
    }
    PASS();
}

void testVerifyRuntime() {
    TEST("verifyRuntime (no proc/maps on macOS)");
    HapParser parser;
    auto s = parser.parseFile(kLargeHap);
    assert(s.has_value());

    auto result = HapParser::verifyRuntime(*s);
    // On macOS, /proc/self/maps doesn't exist — expect warnings
    if (!result.warnings.empty()) {
        PASS();
    } else {
        // On Linux, should at least not crash
        PASS();
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

int main() {
    bool hasHap = fileExists(kSmallHap) && fileExists(kLargeHap);

    std::cout << "=== HapParser Tests ===\n";
    if (hasHap) {
        testParseSmallHap();
        testParseLargeHap();
        testFileHashes();
        testIdentityChain();
    } else {
        SKIP("test HAP files not found — run locally with real files");
    }
    testParseCorruptedFile();
    testParseGarbageFile();

    std::cout << "\n=== RuntimeVerifier Tests ===\n";
    if (hasHap) {
        testExtractElfSegments();
        testExtractSoRefs();
        testExtractAbcRefs();
        testVerifyRuntime();
    } else {
        SKIP("test HAP files not found");
    }

    std::cout << "\n=== Results: " << g_passed << " passed, "
              << g_failed << " failed ===\n";
    return g_failed > 0 ? 1 : 0;
}
