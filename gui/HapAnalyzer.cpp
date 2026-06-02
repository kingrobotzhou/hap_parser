#include <string>
#include <vector>
#include <sstream>
#include "hap_parser.h"

struct HapAnalyzerCtx {
    std::optional<HapParser::Summary> summary;
    HapParser parser;
    HapParser::DisplayOptions opts;
    std::vector<std::string> lines;  // text output lines for detail views

    // Flattened cert info
    struct CertEntry {
        std::string subject, issuer, sha256, keyInfo, validity;
        bool valid;
        int chainIdx;
    };
    std::vector<CertEntry> certs;

    // Profile fields
    std::string profileBundle, profileDevId, profileAppId, profileType;
    std::string profileApl, profileIssuer, profileUuid, profileCertFp;
    std::string profileValidity;
    std::vector<std::string> profileAcls, profileDevices;

    // Code signing
    bool hasCodeSign;
    std::vector<std::string> soLibs;

    // Verdict
    std::string verdict, verdictSummary;

    void refresh();
};

extern "C" {

#include "HapAnalyzer.h"
#include <cstring>
#include <cstdlib>

static const char* retain(const std::string& s) {
    char* p = strdup(s.c_str());
    return p;
}

HapAnalyzerCtx* hap_analyzer_create(void) {
    auto* ctx = new HapAnalyzerCtx();
    ctx->opts.showAll = true;
    ctx->hasCodeSign = false;
    return ctx;
}

void hap_analyzer_destroy(HapAnalyzerCtx* ctx) { delete ctx; }

int hap_analyzer_load(HapAnalyzerCtx* ctx, const char* path) {
    auto summary = ctx->parser.parseFile(path);
    if (!summary) return 0;
    ctx->summary = std::move(*summary);
    ctx->refresh();
    return 1;
}

void HapAnalyzerCtx::refresh() {
    if (!summary) return;
    certs.clear();

    for (size_t ci = 0; ci < summary->subBlockCertificates.size(); ++ci) {
        for (size_t i = 0; i < summary->subBlockCertificates[ci].certificates.size(); ++i) {
            auto& c = summary->subBlockCertificates[ci].certificates[i];
            CertEntry e;
            e.subject = c.subject;
            e.issuer = c.issuer;
            e.sha256 = c.sha256Fingerprint;
            e.valid = c.isCurrentlyValid;
            e.chainIdx = (int)ci;
            std::ostringstream k;
            k << c.publicKeyAlgorithm << " " << c.publicKeyBits << "-bit V" << c.certVersion;
            e.keyInfo = k.str();
            e.validity = c.notBefore + " ~ " + c.notAfter;
            certs.push_back(e);
        }
    }

    if (summary->profile) {
        profileBundle = summary->profile->bundleName;
        profileDevId = summary->profile->developerId;
        profileAppId = summary->profile->appIdentifier;
        profileType = summary->profile->type;
        profileApl = summary->profile->apl;
        profileIssuer = summary->profile->issuer;
        profileUuid = summary->profile->uuid;
        profileCertFp = summary->profile->developerCertFingerprint;
        profileValidity = summary->profile->notBefore + " ~ " + summary->profile->notAfter;
        profileAcls = summary->profile->allowedAcls;
        profileDevices = summary->profile->deviceIds;
    }

    if (summary->propertyBlock) {
        hasCodeSign = summary->propertyBlock->hasCodeSigning;
        soLibs = summary->propertyBlock->nativeLibs;
    } else {
        hasCodeSign = false;
        soLibs.clear();
    }

    // Generate text lines
    lines.clear();
    std::ostringstream ss;
    HapParser::DisplayOptions dopts;
    dopts.showAll = true;
    // We'll build the textual output manually from summary
    lines.push_back("File: " + std::to_string(summary->fileSize) + " bytes");
    lines.push_back("Signing blocks: " + std::to_string(summary->subBlocks.size()));
    lines.push_back("Files in ZIP: " + std::to_string(summary->fileHashes.size()));

    // Verdict
    int pass = 0, warn = 0, fail = 0;
    bool chainOK = false;
    for (auto& c : summary->subBlockCertificates) {
        if (c.validation.signaturesVerify && c.validation.issuerSubjectLinksMatch) chainOK = true;
    }
    if (chainOK) pass++; else fail++;
    if (summary->profile && !summary->profile->developerCertFingerprint.empty()) pass++;
    if (hasCodeSign) pass++;
    if (summary->fileHashes.size() > 0) pass++;

    std::ostringstream vs;
    if (fail > 0) { verdict = "FAIL"; vs << fail << " critical issue(s)"; }
    else if (warn > 0) { verdict = "PASS with warnings"; vs << warn << " warning(s)"; }
    else { verdict = "PASS"; vs << "all checks passed"; }
    verdictSummary = vs.str();
}

// Query implementations
int64_t hap_get_file_count(HapAnalyzerCtx* ctx) { return ctx->summary ? (int64_t)ctx->summary->fileHashes.size() : 0; }
int64_t hap_get_file_size(HapAnalyzerCtx* ctx) { return ctx->summary ? ctx->summary->fileSize : 0; }

const char* hap_get_filename(int64_t i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || i < 0 || i >= (int64_t)ctx->summary->fileHashes.size()) return retain("");
    return retain(ctx->summary->fileHashes[i].filename);
}
int64_t hap_get_file_size_at(int64_t i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || i < 0 || i >= (int64_t)ctx->summary->fileHashes.size()) return 0;
    return ctx->summary->fileHashes[i].size;
}
const char* hap_get_file_sha256(int64_t i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || i < 0 || i >= (int64_t)ctx->summary->fileHashes.size()) return retain("");
    return retain(ctx->summary->fileHashes[i].sha256Formatted);
}

int hap_get_cert_chain_count(HapAnalyzerCtx* ctx) { return ctx->summary ? (int)ctx->summary->subBlockCertificates.size() : 0; }
int hap_get_cert_count(int ci, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || ci < 0 || ci >= (int)ctx->summary->subBlockCertificates.size()) return 0;
    return (int)ctx->summary->subBlockCertificates[ci].certificates.size();
}
const char* hap_get_cert_subject(int ci, int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || ci < 0 || ci >= (int)ctx->certs.size()) return retain("");
    // Need mapping from chain+idx to flat
    int flatIdx = 0;
    for (int c = 0; c < ci; ++c) flatIdx += (int)ctx->summary->subBlockCertificates[c].certificates.size();
    flatIdx += i;
    if (flatIdx >= (int)ctx->certs.size()) return retain("");
    return retain(ctx->certs[flatIdx].subject);
}
const char* hap_get_cert_sha256(int ci, int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary) return retain("");
    return retain(ctx->summary->subBlockCertificates[ci].certificates[i].sha256Fingerprint);
}
const char* hap_get_cert_key_info(int ci, int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary) return retain("");
    auto& c = ctx->summary->subBlockCertificates[ci].certificates[i];
    std::ostringstream k;
    k << c.publicKeyAlgorithm << " " << c.publicKeyBits << "-bit V" << c.certVersion;
    return retain(k.str());
}
const char* hap_get_cert_validity(int ci, int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary) return retain("");
    return retain(ctx->summary->subBlockCertificates[ci].certificates[i].notBefore + " ~ " + ctx->summary->subBlockCertificates[ci].certificates[i].notAfter);
}
int hap_get_cert_is_valid(int ci, int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary) return 0;
    return ctx->summary->subBlockCertificates[ci].certificates[i].isCurrentlyValid ? 1 : 0;
}
int hap_get_chain_content_ok(int ci, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || ci < 0 || ci >= (int)ctx->summary->subBlockCertificates.size()) return -1;
    auto& chain = ctx->summary->subBlockCertificates[ci];
    if (!chain.sigVerification || !chain.sigVerification->digestVerified) return -1;
    return chain.sigVerification->contentIntegrityOk ? 1 : 0;
}
int hap_get_chain_block_count(HapAnalyzerCtx* ctx) { return ctx->summary && ctx->summary->signatureFooter ? ctx->summary->signatureFooter->blockCount : 0; }
int hap_get_chain_version(HapAnalyzerCtx* ctx) { return ctx->summary && ctx->summary->signatureFooter ? ctx->summary->signatureFooter->version : 0; }

const char* hap_get_profile_field(const char* field, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || !ctx->summary->profile) return retain("");
    if (strcmp(field, "bundle") == 0) return retain(ctx->profileBundle);
    if (strcmp(field, "devid") == 0) return retain(ctx->profileDevId);
    if (strcmp(field, "appid") == 0) return retain(ctx->profileAppId);
    if (strcmp(field, "type") == 0) return retain(ctx->profileType);
    if (strcmp(field, "apl") == 0) return retain(ctx->profileApl);
    if (strcmp(field, "issuer") == 0) return retain(ctx->profileIssuer);
    if (strcmp(field, "certfp") == 0) return retain(ctx->profileCertFp);
    if (strcmp(field, "validity") == 0) return retain(ctx->profileValidity);
    return retain("");
}

int hap_has_code_sign(HapAnalyzerCtx* ctx) { return ctx->hasCodeSign ? 1 : 0; }
int hap_get_code_sign_lib_count(HapAnalyzerCtx* ctx) { return (int)ctx->soLibs.size(); }
const char* hap_get_code_sign_lib(int i, HapAnalyzerCtx* ctx) {
    if (i < 0 || i >= (int)ctx->soLibs.size()) return retain("");
    return retain(ctx->soLibs[i]);
}

int hap_get_subblock_count(HapAnalyzerCtx* ctx) { return ctx->summary ? (int)ctx->summary->subBlocks.size() : 0; }
uint32_t hap_get_subblock_type(int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || i < 0 || i >= (int)ctx->summary->subBlocks.size()) return 0;
    return ctx->summary->subBlocks[i].type;
}
int64_t hap_get_subblock_offset(int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || i < 0 || i >= (int)ctx->summary->subBlocks.size()) return 0;
    return ctx->summary->subBlocks[i].offset;
}
int64_t hap_get_subblock_length(int i, HapAnalyzerCtx* ctx) {
    if (!ctx->summary || i < 0 || i >= (int)ctx->summary->subBlocks.size()) return 0;
    return ctx->summary->subBlocks[i].length;
}

const char* hap_get_verdict(HapAnalyzerCtx* ctx) { return retain(ctx->verdict); }
const char* hap_get_verdict_summary(HapAnalyzerCtx* ctx) { return retain(ctx->verdictSummary); }

} // extern "C"
