#include "hap_parser.h"
#include "runtime_verify.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <vector>

#ifdef __OHOS__
#include <hilog/log.h>
#endif

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

using EocdInfo = HapParser::EocdInfo;
using SignatureFooterInfo = HapParser::SignatureFooterInfo;
using SubBlockHead = HapParser::SubBlockHead;
using CertificateInfo = HapParser::CertificateInfo;
using SignerInfo = HapParser::SignerInfo;
using ChainValidationInfo = HapParser::ChainValidationInfo;
using SubBlockCertificateInfo = HapParser::SubBlockCertificateInfo;
using SubBlockPayloadInfo = HapParser::SubBlockPayloadInfo;
using FileHashInfo = HapParser::FileHashInfo;
using PropertyBlockInfo = HapParser::PropertyBlockInfo;
using ProfileInfo = HapParser::ProfileInfo;
using Summary = HapParser::Summary;

#ifdef __OHOS__
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0x3200
#define LOG_TAG "HapParser"
#endif

/*
 * High-level logic graph
 * ----------------------
 * HapParser::parseFile(...)
 *   -> loadFile(...)
 *   -> ByteView
 *   -> summarizeHap(...)
 *      1. findBestEocd(...)
 *      2. resolveCentralDirectoryOffset(...)
 *      3. parseSignatureFooterAt(...)
 *      4. parseSubBlockHeads(...)
 *      5. parseSubBlockCertificates(...)
 *      6. validateCertificateChain(...)
 *   -> HapParser::printSummary(...)
 */

/*
 * HAP/ZIP signature block type identifiers.
 * 0x20000000–0x20000003 are subblocks inside the HAP signing block.
 * 0x30000001 is the external code-sign data block (referenced via PropertyBlock).
 */
constexpr std::uint32_t kZipEocdSig = 0x06054B50;
constexpr std::uint32_t kZipCentralDirSig = 0x02014B50;
constexpr std::uint32_t kHapSignatureSchemeV1BlockId = 0x20000000;
constexpr std::uint32_t kHapProofOfRotationBlockId = 0x20000001;
constexpr std::uint32_t kHapProfileBlockId = 0x20000002;
constexpr std::uint32_t kHapPropertyBlockId = 0x20000003;
constexpr std::uint32_t kHapCodeSignBlockId = 0x30000001;
constexpr std::int64_t kHapSignHeadSize = 32;
constexpr std::int64_t kHapSubBlockHeadSize = 12;
constexpr std::int64_t kMaxZipCommentLen = 65535;

enum class ParserLogLevel {
    Info,
    Warn,
    Error,
    Fatal,
};

/*
 * Lightweight read-only byte buffer with little-endian multi-byte readers.
 * All offsets are absolute. Returns std::nullopt on out-of-range access.
 */
class ByteView {
public:
    explicit ByteView(std::vector<std::uint8_t> bytes) : bytes_(std::move(bytes)) {}

    std::int64_t size() const {
        return static_cast<std::int64_t>(bytes_.size());
    }

    const std::vector<std::uint8_t>& data() const { return bytes_; }

    bool canRead(std::int64_t offset, std::int64_t length) const {
        return offset >= 0 && length >= 0 &&
               offset <= size() &&
               length <= size() - offset;
    }

    std::optional<std::uint16_t> readU16(std::int64_t offset) const {
        if (!canRead(offset, 2)) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(bytes_[offset]) |
               (static_cast<std::uint16_t>(bytes_[offset + 1]) << 8);
    }

    std::optional<std::uint32_t> readU32(std::int64_t offset) const {
        if (!canRead(offset, 4)) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(bytes_[offset]) |
               (static_cast<std::uint32_t>(bytes_[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(bytes_[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(bytes_[offset + 3]) << 24);
    }

    std::optional<std::int32_t> readI32(std::int64_t offset) const {
        const auto value = readU32(offset);
        if (!value) {
            return std::nullopt;
        }
        return static_cast<std::int32_t>(*value);
    }

    std::optional<std::int64_t> readI64(std::int64_t offset) const {
        if (!canRead(offset, 8)) {
            return std::nullopt;
        }
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(bytes_[offset + i]) << (8 * i);
        }
        return static_cast<std::int64_t>(value);
    }

    std::optional<std::vector<std::uint8_t>> slice(std::int64_t offset, std::int64_t length) const {
        if (!canRead(offset, length)) {
            return std::nullopt;
        }
        return std::vector<std::uint8_t>(bytes_.begin() + offset, bytes_.begin() + offset + length);
    }

private:
    std::vector<std::uint8_t> bytes_;
};

/*
 * Cross-platform logging: uses HiLog on OpenHarmony, stdout/stderr elsewhere.
 */
void logMessage(ParserLogLevel level, const std::string& message)
{
#ifdef __OHOS__
    switch (level) {
        case ParserLogLevel::Info:
            OH_LOG_INFO(LOG_APP, "%{public}s", message.c_str());
            break;
        case ParserLogLevel::Warn:
            OH_LOG_WARN(LOG_APP, "%{public}s", message.c_str());
            break;
        case ParserLogLevel::Error:
            OH_LOG_ERROR(LOG_APP, "%{public}s", message.c_str());
            break;
        case ParserLogLevel::Fatal:
            OH_LOG_FATAL(LOG_APP, "%{public}s", message.c_str());
            break;
    }
#else
    std::ostream& stream =
        (level == ParserLogLevel::Warn || level == ParserLogLevel::Error || level == ParserLogLevel::Fatal)
            ? std::cerr
            : std::cout;
    stream << message << '\n';
#endif
}

/* Maps a HAP block type ID to a human-readable display name. */
std::string blockTypeName(std::uint32_t type)
{
    switch (type) {
        case kHapSignatureSchemeV1BlockId:
            return "AppSignatureBlock";
        case kHapProofOfRotationBlockId:
            return "ProofOfRotationBlock";
        case kHapProfileBlockId:
            return "ProfileBlock";
        case kHapPropertyBlockId:
            return "PropertyBlock";
        case kHapCodeSignBlockId:
            return "CodeSignBlock";
        default:
            return "UnknownBlock";
    }
}

/* Converts an OpenSSL NID to its short name (e.g. NID_sha256 -> "SHA256"). */
std::string nidToShortName(int nid)
{
    if (nid == NID_undef) {
        return "NID_undef";
    }
    const char* name = OBJ_nid2sn(nid);
    return name != nullptr ? std::string(name) : std::to_string(nid);
}

/* Returns the top-level PKCS7 content type name (e.g. "pkcs7-signedData"). */
std::string pkcs7TypeName(PKCS7* pkcs7)
{
    if (pkcs7 == nullptr || pkcs7->type == nullptr) {
        return {};
    }
    const int nid = OBJ_obj2nid(pkcs7->type);
    return nidToShortName(nid);
}

/* Returns the embedded content type inside a signed PKCS7 (e.g. "pkcs7-data"). */
std::string pkcs7ContentTypeName(PKCS7* pkcs7)
{
    if (pkcs7 == nullptr || !PKCS7_type_is_signed(pkcs7) || pkcs7->d.sign == nullptr ||
        pkcs7->d.sign->contents == nullptr || pkcs7->d.sign->contents->type == nullptr) {
        return {};
    }
    const int nid = OBJ_obj2nid(pkcs7->d.sign->contents->type);
    return nidToShortName(nid);
}

/* Extracts the algorithm name from an X509_ALGOR structure. */
std::string x509AlgorithmName(const X509_ALGOR* algor)
{
    if (algor == nullptr || algor->algorithm == nullptr) {
        return {};
    }
    const int nid = OBJ_obj2nid(algor->algorithm);
    return nidToShortName(nid);
}

/* Formats an ASN1 signing-time attribute to a human-readable string. */
std::string signingTimeToString(ASN1_TYPE* signTime)
{
    if (signTime == nullptr) {
        return {};
    }

    if (signTime->type == V_ASN1_UTCTIME || signTime->type == V_ASN1_GENERALIZEDTIME) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (bio == nullptr) {
            return {};
        }
        ASN1_TIME_print(bio, signTime->value.asn1_string);
        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio, &mem);
        std::string value;
        if (mem != nullptr && mem->data != nullptr && mem->length > 0) {
            value.assign(mem->data, mem->length);
        }
        BIO_free(bio);
        return value;
    }
    return {};
}

/* Reads OpenSSL BIO content into a std::string. */
std::string bioToString(BIO* bio)
{
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (mem == nullptr || mem->data == nullptr || mem->length == 0) {
        return {};
    }
    return std::string(mem->data, mem->length);
}

std::string x509NameToString(X509_NAME* name)
{
    if (name == nullptr) {
        return {};
    }

    // Convert each RDN component to UTF-8 so localized issuer/subject names
    // print as normal text instead of escaped hex bytes.
    std::ostringstream out;
    const int entryCount = X509_NAME_entry_count(name);
    for (int i = 0; i < entryCount; ++i) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, i);
        if (entry == nullptr) {
            continue;
        }

        ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);

        char objBuf[128] = {0};
        const int objLen = OBJ_obj2txt(objBuf, sizeof(objBuf), object, 0);
        if (objLen <= 0) {
            continue;
        }

        unsigned char* utf8Data = nullptr;
        const int utf8Len = ASN1_STRING_to_UTF8(&utf8Data, data);
        std::string value;
        if (utf8Len >= 0 && utf8Data != nullptr) {
            value.assign(reinterpret_cast<char*>(utf8Data), utf8Len);
        }
        OPENSSL_free(utf8Data);

        if (!value.empty()) {
            std::string escaped;
            escaped.reserve(value.size());
            for (char ch : value) {
                if (ch == ',' || ch == '+' || ch == '"' || ch == '\\') {
                    escaped.push_back('\\');
                }
                escaped.push_back(ch);
            }
            value = std::move(escaped);
        }

        if (out.tellp() > 0) {
            out << ",";
        }
        out << objBuf << "=" << value;
    }

    return out.str();
}

std::string asn1TimeToString(const ASN1_TIME* time)
{
    if (time == nullptr) {
        return {};
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        return {};
    }
    ASN1_TIME_print(bio, time);
    std::string value = bioToString(bio);
    BIO_free(bio);
    return value;
}

std::string serialToString(const ASN1_INTEGER* serial)
{
    if (serial == nullptr) {
        return {};
    }
    // The certificate serial number uniquely identifies one issued certificate
    // under a given issuer. In practice, issuer + serial is the stable handle
    // used for revocation checks, logs, and certificate management.
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    if (bn == nullptr) {
        return {};
    }
    char* hex = BN_bn2hex(bn);
    std::string value = hex != nullptr ? std::string(hex) : std::string();
    OPENSSL_free(hex);
    BN_free(bn);
    return value;
}

std::string internalCertificateRole(std::size_t internalIndex, std::size_t count);

std::string x509ExtensionValueToString(X509_EXTENSION* ext)
{
    if (ext == nullptr) {
        return {};
    }
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        return {};
    }
    if (X509V3_EXT_print(bio, ext, 0, 0) != 1) {
        BIO_free(bio);
        return {};
    }
    std::string value = bioToString(bio);
    BIO_free(bio);
    return value;
}

std::string normalizeExtensionText(std::string value)
{
    std::replace(value.begin(), value.end(), '\n', ' ');
    std::replace(value.begin(), value.end(), '\r', ' ');
    return value;
}

/* Splits a comma-separated string into trimmed tokens (for X509 extension parsing). */
std::vector<std::string> splitCommaSeparated(const std::string& value)
{
    std::vector<std::string> results;
    std::stringstream ss(value);
    std::string item;
    while (std::getline(ss, item, ',')) {
        std::size_t start = item.find_first_not_of(' ');
        std::size_t end = item.find_last_not_of(' ');
        if (start == std::string::npos || end == std::string::npos) {
            continue;
        }
        results.push_back(item.substr(start, end - start + 1));
    }
    return results;
}

std::vector<std::string> attributeStackToStrings(STACK_OF(X509_ATTRIBUTE)* attrs)
{
    std::vector<std::string> results;
    if (attrs == nullptr) {
        return results;
    }

    const int count = sk_X509_ATTRIBUTE_num(attrs);
    results.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(attrs, i);
        if (attr == nullptr) {
            continue;
        }
        ASN1_OBJECT* object = X509_ATTRIBUTE_get0_object(attr);
        if (object == nullptr) {
            continue;
        }
        results.push_back(nidToShortName(OBJ_obj2nid(object)));
    }
    return results;
}

/* Extracts signer info (subject, algorithm, attributes) from a PKCS7 signer stack. */
std::vector<SignerInfo> extractSignerInfos(PKCS7* pkcs7)
{
    std::vector<SignerInfo> signers;
    STACK_OF(PKCS7_SIGNER_INFO)* signerInfos = PKCS7_get_signer_info(pkcs7);
    if (signerInfos == nullptr) {
        return signers;
    }

    const int count = sk_PKCS7_SIGNER_INFO_num(signerInfos);
    signers.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        PKCS7_SIGNER_INFO* signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfos, i);
        if (signerInfo == nullptr) {
            continue;
        }

        SignerInfo info;
        info.digestAlgorithm = x509AlgorithmName(signerInfo->digest_alg);
        info.signatureAlgorithm = x509AlgorithmName(signerInfo->digest_enc_alg);
        info.signingTime = signingTimeToString(PKCS7_get_signed_attribute(signerInfo, NID_pkcs9_signingTime));
        info.signedAttributes = attributeStackToStrings(signerInfo->auth_attr);
        info.unsignedAttributes = attributeStackToStrings(signerInfo->unauth_attr);

        X509* cert = PKCS7_cert_from_signer_info(pkcs7, signerInfo);
        if (cert != nullptr) {
            info.subject = x509NameToString(X509_get_subject_name(cert));
            info.issuer = x509NameToString(X509_get_issuer_name(cert));
            info.serial = serialToString(X509_get_serialNumber(cert));
        }

        signers.push_back(std::move(info));
    }
    return signers;
}

/* Builds a composite key (issuer + serial) for deduplicating certificates. */
std::string certificateKey(X509* cert)
{
    if (cert == nullptr) {
        return {};
    }
    return x509NameToString(X509_get_issuer_name(cert)) + "#" + serialToString(X509_get_serialNumber(cert));
}

bool isCertificateCurrentlyValid(X509* cert, bool* isExpired, bool* isNotYetValid)
{
    const int notBeforeCmp = X509_cmp_current_time(X509_get0_notBefore(cert));
    const int notAfterCmp = X509_cmp_current_time(X509_get0_notAfter(cert));
    const bool notYetValid = notBeforeCmp > 0;
    const bool expired = notAfterCmp < 0;

    if (isExpired != nullptr) {
        *isExpired = expired;
    }
    if (isNotYetValid != nullptr) {
        *isNotYetValid = notYetValid;
    }
    return !expired && !notYetValid;
}

CertificateInfo extractCertificateInfo(X509* cert)
{
    CertificateInfo info;
    info.subject = x509NameToString(X509_get_subject_name(cert));
    info.issuer = x509NameToString(X509_get_issuer_name(cert));
    info.serial = serialToString(X509_get_serialNumber(cert));
    info.notBefore = asn1TimeToString(X509_get0_notBefore(cert));
    info.notAfter = asn1TimeToString(X509_get0_notAfter(cert));

    const X509_ALGOR* sigAlg = nullptr;
    X509_get0_signature(nullptr, &sigAlg, cert);
    info.certificateSignatureAlgorithm = x509AlgorithmName(sigAlg);

    EVP_PKEY* publicKey = X509_get_pubkey(cert);
    if (publicKey != nullptr) {
        info.publicKeyAlgorithm = nidToShortName(EVP_PKEY_id(publicKey));
        info.publicKeyBits = EVP_PKEY_bits(publicKey);
    }
    EVP_PKEY_free(publicKey);

    BASIC_CONSTRAINTS* basicConstraints = static_cast<BASIC_CONSTRAINTS*>(
        X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr));
    if (basicConstraints != nullptr) {
        info.isCA = basicConstraints->ca != 0;
        BASIC_CONSTRAINTS_free(basicConstraints);
    }

    const int keyUsageIndex = X509_get_ext_by_NID(cert, NID_key_usage, -1);
    if (keyUsageIndex >= 0) {
        X509_EXTENSION* ext = X509_get_ext(cert, keyUsageIndex);
        info.keyUsage = splitCommaSeparated(normalizeExtensionText(x509ExtensionValueToString(ext)));
    }

    const int extKeyUsageIndex = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
    if (extKeyUsageIndex >= 0) {
        X509_EXTENSION* ext = X509_get_ext(cert, extKeyUsageIndex);
        info.extendedKeyUsage = splitCommaSeparated(normalizeExtensionText(x509ExtensionValueToString(ext)));
    }

    const int skiIndex = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);
    if (skiIndex >= 0) {
        X509_EXTENSION* ext = X509_get_ext(cert, skiIndex);
        info.subjectKeyIdentifier = normalizeExtensionText(x509ExtensionValueToString(ext));
    }

    const int akiIndex = X509_get_ext_by_NID(cert, NID_authority_key_identifier, -1);
    if (akiIndex >= 0) {
        X509_EXTENSION* ext = X509_get_ext(cert, akiIndex);
        info.authorityKeyIdentifier = normalizeExtensionText(x509ExtensionValueToString(ext));
    }

    info.isCurrentlyValid = isCertificateCurrentlyValid(cert, &info.isExpired, &info.isNotYetValid);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    if (X509_digest(cert, EVP_sha256(), md, &mdLen) == 1 && mdLen > 0) {
        std::ostringstream fp;
        for (unsigned int i = 0; i < mdLen; ++i) {
            if (i > 0) fp << ":";
            fp << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<int>(md[i]);
        }
        info.sha256Fingerprint = fp.str();
    }

    long version = X509_get_version(cert);
    info.certVersion = static_cast<std::int32_t>(version + 1);

    info.signatureAlgorithm = info.certificateSignatureAlgorithm;
    return info;
}

/* Validates chain shape (2 or 3 levels), issuer-subject links, and cryptographic signatures. */
ChainValidationInfo validateCertificateChain(const std::vector<X509*>& certs)
{
    ChainValidationInfo result;
    // These are initial states, not final verdicts.
    // - hasThreeLevelChain checks the expected HAP chain shape: leaf/intermediate/root.
    // - allCertificatesCurrentlyValid starts true when there is at least one cert,
    //   then each cert can turn it false if it is expired or not yet valid.
    // - issuerSubjectLinksMatch only makes sense when we have adjacent pairs to compare.
    // - signaturesVerify only makes sense when we have adjacent pairs to verify.
    result.hasThreeLevelChain = certs.size() == 3;
    result.hasTwoLevelChain = certs.size() == 2;
    result.hasFullChain = result.hasThreeLevelChain;
    result.allCertificatesCurrentlyValid = !certs.empty();
    result.issuerSubjectLinksMatch = certs.size() > 1;
    result.signaturesVerify = certs.size() > 1;

    for (std::size_t i = 0; i < certs.size(); ++i) {
        bool expired = false;
        bool notYetValid = false;
        const bool currentlyValid = isCertificateCurrentlyValid(certs[i], &expired, &notYetValid);
        const std::string role = internalCertificateRole(i, certs.size());
        result.allCertificatesCurrentlyValid &= currentlyValid;
        if (expired) {
            result.issues.push_back(role + " certificate is expired.");
        }
        if (notYetValid) {
            result.issues.push_back(role + " certificate is not yet valid.");
        }
    }

    // The common HAP chain layout is leaf -> intermediate -> root.
    for (std::size_t i = 0; i + 1 < certs.size(); ++i) {
        const std::string role = internalCertificateRole(i, certs.size());
        const std::string issuerRole = internalCertificateRole(i + 1, certs.size());
        if (X509_NAME_cmp(X509_get_issuer_name(certs[i]), X509_get_subject_name(certs[i + 1])) != 0) {
            result.issuerSubjectLinksMatch = false;
            result.issues.push_back(role + " issuer does not match " +
                                    issuerRole + " subject.");
        }

        EVP_PKEY* issuerKey = X509_get_pubkey(certs[i + 1]);
        if (issuerKey == nullptr || X509_verify(certs[i], issuerKey) != 1) {
            result.signaturesVerify = false;
            result.issues.push_back(role + " signature verification failed against " +
                                    issuerRole + ".");
        }
        EVP_PKEY_free(issuerKey);
    }

    if (certs.size() >= 3) {
        X509* root = certs.back();
        result.rootIncluded = true;
        result.rootLooksSelfSigned =
            X509_NAME_cmp(X509_get_subject_name(root), X509_get_issuer_name(root)) == 0;

        EVP_PKEY* rootKey = X509_get_pubkey(root);
        if (rootKey != nullptr && X509_verify(root, rootKey) == 1) {
            result.rootLooksSelfSigned = result.rootLooksSelfSigned && true;
        } else {
            result.rootLooksSelfSigned = false;
            result.issues.push_back("Root certificate does not verify as self-signed.");
        }
        EVP_PKEY_free(rootKey);
    }

    if (!result.hasThreeLevelChain && !result.hasTwoLevelChain) {
        result.issues.push_back("Certificate chain does not contain exactly three certificates.");
    }

    return result;
}

/*
 * Orders certificate chain from leaf to root. Uses issuer-subject relationships
 * to find the correct order when the input list is not pre-ordered.
 */
std::vector<X509*> orderCertificateChain(const std::vector<X509*>& certs)
{
    if (certs.size() <= 1) {
        return certs;
    }

    std::vector<X509*> ordered;
    std::vector<bool> used(certs.size(), false);

    // Pick the leaf first: it is usually the certificate whose subject is not
    // used as the issuer name of another certificate in the same set.
    for (std::size_t i = 0; i < certs.size(); ++i) {
        bool issuedAnother = false;
        for (std::size_t j = 0; j < certs.size(); ++j) {
            if (i == j) {
                continue;
            }
            if (X509_NAME_cmp(X509_get_subject_name(certs[i]), X509_get_issuer_name(certs[j])) == 0) {
                issuedAnother = true;
                break;
            }
        }
        if (!issuedAnother) {
            ordered.push_back(certs[i]);
            used[i] = true;
            break;
        }
    }

    if (ordered.empty()) {
        return certs;
    }

    while (ordered.size() < certs.size()) {
        X509* current = ordered.back();
        bool foundNext = false;
        for (std::size_t i = 0; i < certs.size(); ++i) {
            if (used[i]) {
                continue;
            }
            if (X509_NAME_cmp(X509_get_issuer_name(current), X509_get_subject_name(certs[i])) == 0) {
                ordered.push_back(certs[i]);
                used[i] = true;
                foundNext = true;
                break;
            }
        }
        if (!foundNext) {
            break;
        }
    }

    for (std::size_t i = 0; i < certs.size(); ++i) {
        if (!used[i]) {
            ordered.push_back(certs[i]);
        }
    }

    return ordered;
}

/* Attempts to extract a certificate chain from a subblock's PKCS7 payload. */
std::optional<SubBlockCertificateInfo> parsePkcs7Certificates(const SubBlockHead& head,
                                                              const std::vector<std::uint8_t>& bytes)
{
    std::vector<CertificateInfo> certificates;
    std::vector<X509*> rawCerts;
    std::vector<X509*> ownedCerts;
    std::unordered_set<std::string> seenCerts;

    auto appendCert = [&](X509* cert) {
        if (cert == nullptr) {
            return;
        }
        const std::string key = certificateKey(cert);
        if (!key.empty() && seenCerts.find(key) != seenCerts.end()) {
            return;
        }
        if (!key.empty()) {
            seenCerts.insert(key);
        }
        X509* certCopy = X509_dup(cert);
        if (certCopy == nullptr) {
            return;
        }
        rawCerts.push_back(certCopy);
        ownedCerts.push_back(certCopy);
    };

    auto collectPkcs7Certs = [&](const unsigned char* begin, long length) {
        const unsigned char* ptr = begin;
        PKCS7* pkcs7 = d2i_PKCS7(nullptr, &ptr, length);
        if (pkcs7 == nullptr) {
            return;
        }

        STACK_OF(X509)* certStack = nullptr;
        if (PKCS7_type_is_signed(pkcs7) && pkcs7->d.sign != nullptr) {
            certStack = pkcs7->d.sign->cert;
        } else if (PKCS7_type_is_signedAndEnveloped(pkcs7) && pkcs7->d.signed_and_enveloped != nullptr) {
            certStack = pkcs7->d.signed_and_enveloped->cert;
        }

        if (certStack != nullptr) {
            const int count = sk_X509_num(certStack);
            for (int i = 0; i < count; ++i) {
                appendCert(sk_X509_value(certStack, i));
            }
        }

        PKCS7_free(pkcs7);
    };

    // HAP signature payloads are not all PKCS7. Try DER decode and simply skip
    // the subblock when it is some other payload type.
    collectPkcs7Certs(bytes.data(), static_cast<long>(bytes.size()));

    // Some HAP payloads embed DER objects with a small wrapper. If the direct
    // PKCS7 decode did not recover a full chain, scan for additional PKCS7 or
    // X509 objects at later offsets and merge any unique certificates found.
    if (rawCerts.size() < 3) {
        for (std::size_t offset = 1; offset + 8 < bytes.size(); ++offset) {
            const unsigned char* start = bytes.data() + offset;
            if (*start != 0x30) {
                continue;
            }

            collectPkcs7Certs(start, static_cast<long>(bytes.size() - offset));

            const unsigned char* certPtr = start;
            X509* cert = d2i_X509(nullptr, &certPtr, static_cast<long>(bytes.size() - offset));
            if (cert != nullptr) {
                appendCert(cert);
                X509_free(cert);
            }

            if (rawCerts.size() >= 3) {
                break;
            }
        }
    }

    certificates.reserve(rawCerts.size());
    std::vector<X509*> orderedCerts = orderCertificateChain(rawCerts);
    certificates.clear();
    certificates.reserve(orderedCerts.size());
    for (X509* cert : orderedCerts) {
        if (cert != nullptr) {
            certificates.push_back(extractCertificateInfo(cert));
        }
    }

    ChainValidationInfo validation = validateCertificateChain(orderedCerts);
    for (X509* cert : ownedCerts) {
        X509_free(cert);
    }
    if (certificates.empty()) {
        return std::nullopt;
    }
    const bool isAppSignatureBlock = head.type == kHapSignatureSchemeV1BlockId;
    const bool isProfileBlock = head.type == kHapProfileBlockId;
    return SubBlockCertificateInfo{
        head, std::move(certificates), std::move(validation), isAppSignatureBlock, isProfileBlock};
}

std::optional<EocdInfo> parseEocdAt(const ByteView& view, std::int64_t offset)
{
    if (!view.canRead(offset, 22)) {
        return std::nullopt;
    }
    const auto sig = view.readU32(offset);
    if (!sig || *sig != kZipEocdSig) {
        return std::nullopt;
    }

    EocdInfo eocd;
    eocd.offset = offset;
    eocd.diskNumber = *view.readU16(offset + 4);
    eocd.centralDirDiskNumber = *view.readU16(offset + 6);
    eocd.entriesThisDisk = *view.readU16(offset + 8);
    eocd.totalEntries = *view.readU16(offset + 10);
    eocd.centralDirSize = *view.readU32(offset + 12);
    eocd.centralDirOffsetRaw = *view.readU32(offset + 16);
    eocd.commentLength = *view.readU16(offset + 20);
    return eocd;
}

std::optional<SignatureFooterInfo> parseSignatureFooterAt(const ByteView& view,
                                                          std::int64_t footerOffset)
{
    if (!view.canRead(footerOffset, kHapSignHeadSize)) {
        return std::nullopt;
    }

    SignatureFooterInfo footer;
    const auto blockCount = view.readI32(footerOffset);
    const auto signatureBlockSize = view.readI64(footerOffset + 4);
    const auto version = view.readI32(footerOffset + 28);
    if (!blockCount || !signatureBlockSize || !version) {
        return std::nullopt;
    }

    footer.blockCount = *blockCount;
    footer.signatureBlockSize = *signatureBlockSize;
    footer.version = *version;

    const auto magicBytes = view.slice(footerOffset + 12, 16);
    if (magicBytes) {
        std::string magic;
        magic.reserve(16);
        for (const auto byte : *magicBytes) {
            if (byte >= 0x20 && byte <= 0x7E) {
                magic.push_back(static_cast<char>(byte));
            }
        }
        footer.signatureMagic = magic;
    }

    return footer;
}

bool hasPlausibleSignatureFooter(const ByteView& view, std::int64_t centralDirOffset)
{
    // The HAP signing footer is expected to sit immediately before the ZIP
    // central directory. This helper answers: "does that area look structurally
    // like a real HAP signing block footer?"
    const auto footer = parseSignatureFooterAt(view, centralDirOffset - kHapSignHeadSize);
    if (!footer) {
        return false;
    }

    const std::int64_t signatureStart = centralDirOffset - footer->signatureBlockSize;
    if (footer->signatureBlockSize < kHapSignHeadSize) {
        return false;
    }
    if (signatureStart < 0) {
        return false;
    }
    if (signatureStart + footer->signatureBlockSize != centralDirOffset) {
        return false;
    }
    if (footer->blockCount < 0 || footer->blockCount > 4096) {
        return false;
    }
    if (signatureStart + static_cast<std::int64_t>(footer->blockCount) * kHapSubBlockHeadSize >
        centralDirOffset - kHapSignHeadSize) {
        return false;
    }
    return true;
}

int scoreEocdCandidate(const ByteView& view, std::int64_t offset)
{
    const auto eocd = parseEocdAt(view, offset);
    if (!eocd) {
        return -1;
    }

    // Score candidates instead of trusting the first EOCD marker we see.
    // Real HAP files can contain EOCD-like byte patterns inside payload data.
    int score = 1;
    const std::int64_t fileSize = view.size();
    const std::int64_t eocdEnd = offset + 22 + eocd->commentLength;
    if (eocdEnd == fileSize) {
        score += 4;
    } else if (eocdEnd < fileSize) {
        score += 2;
    }

    if (static_cast<std::int64_t>(eocd->centralDirOffsetRaw) <= offset &&
        static_cast<std::int64_t>(eocd->centralDirOffsetRaw) + eocd->centralDirSize <= offset) {
        score += 2;
    }

    if (view.canRead(eocd->centralDirOffsetRaw, 4)) {
        const auto sig = view.readU32(eocd->centralDirOffsetRaw);
        if (sig && *sig == kZipCentralDirSig) {
            score += 8;
        }
    }

    if (hasPlausibleSignatureFooter(view, eocd->centralDirOffsetRaw)) {
        score += 16;
    }

    return score;
}

std::optional<EocdInfo> findBestEocd(const ByteView& view)
{
    const std::int64_t size = view.size();
    std::int64_t start = size - 22 - kMaxZipCommentLen;
    if (start < 0) {
        start = 0;
    }

    int bestScore = -1;
    std::optional<EocdInfo> best;

    // Walk backwards because EOCD lives near the end of ZIP/HAP files.
    for (std::int64_t pos = size - 22; pos >= start; --pos) {
        const int score = scoreEocdCandidate(view, pos);
        if (score <= bestScore) {
            continue;
        }
        auto eocd = parseEocdAt(view, pos);
        if (!eocd) {
            continue;
        }
        bestScore = score;
        best = *eocd;
        if (score >= 31) {
            break;
        }
    }

    return best;
}

std::optional<std::int64_t> resolveCentralDirectoryOffset(const ByteView& view,
                                                          const EocdInfo& eocd)
{
    std::optional<std::int64_t> fallback;

    auto consider = [&](std::int64_t offset) -> std::optional<std::int64_t> {
        if (!view.canRead(offset, 4)) {
            return std::nullopt;
        }
        const auto sig = view.readU32(offset);
        if (!sig || *sig != kZipCentralDirSig) {
            return std::nullopt;
        }
        if (hasPlausibleSignatureFooter(view, offset)) {
            return offset;
        }
        if (!fallback) {
            fallback = offset;
        }
        return std::nullopt;
    };

    // Prefer the explicit EOCD hint first, then a size-derived fallback, then a
    // narrow local scan when the metadata is close but not exact.
    if (auto exact = consider(eocd.centralDirOffsetRaw)) {
        return exact;
    }

    const std::int64_t derived = eocd.offset - eocd.centralDirSize;
    if (auto exact = consider(derived)) {
        return exact;
    }

    std::int64_t scanStart = derived - 4096;
    std::int64_t scanEnd = derived + 4096;
    if (scanStart < 0) {
        scanStart = 0;
    }
    if (scanEnd > eocd.offset - 4) {
        scanEnd = eocd.offset - 4;
    }

    for (std::int64_t pos = scanStart; pos <= scanEnd; ++pos) {
        if (auto exact = consider(pos)) {
            return exact;
        }
    }

    return fallback;
}

std::vector<SubBlockHead> parseSubBlockHeads(const ByteView& view,
                                             std::int64_t signatureStart,
                                             std::int32_t blockCount)
{
    std::vector<SubBlockHead> blocks;
    if (blockCount < 0 || blockCount > 4096) {
        return blocks;
    }
    blocks.reserve(static_cast<std::size_t>(blockCount));

    // The signing block starts with a flat table of subblock descriptors:
    // [type][length][offset] repeated blockCount times.
    for (std::int32_t i = 0; i < blockCount; ++i) {
        const std::int64_t offset = signatureStart + static_cast<std::int64_t>(i) * kHapSubBlockHeadSize;
        const auto type = view.readU32(offset);
        const auto length = view.readU32(offset + 4);
        const auto subOffset = view.readU32(offset + 8);
        if (!type || !length || !subOffset) {
            break;
        }
        blocks.push_back(SubBlockHead{*type, *length, *subOffset, blockTypeName(*type)});
    }
    return blocks;
}

std::vector<SubBlockCertificateInfo> parseSubBlockCertificates(const ByteView& view,
                                                               std::int64_t signatureStart,
                                                               std::int64_t centralDirOffset,
                                                               const std::vector<SubBlockHead>& subBlocks)
{
    std::vector<SubBlockCertificateInfo> results;
    const std::int64_t payloadLimit = centralDirOffset - kHapSignHeadSize;
    // Only PKCS7-capable block types may contain certificate chains.
    // PropertyBlock (0x20000003) is binary code-sign/property data, not PKCS7.
    // Scanning it for DER objects would produce false positives.
    for (const auto& block : subBlocks) {
        if (block.type != kHapSignatureSchemeV1BlockId &&
            block.type != kHapProfileBlockId &&
            block.type != kHapProofOfRotationBlockId) {
            continue;
        }

        const std::int64_t dataOffset = signatureStart + block.offset;
        const std::int64_t dataEnd = dataOffset + block.length;
        if (block.length == 0 || dataOffset < signatureStart || dataEnd > payloadLimit || dataEnd < dataOffset) {
            continue;
        }

        const auto bytes = view.slice(dataOffset, block.length);
        if (!bytes) {
            continue;
        }

        auto certificates = parsePkcs7Certificates(block, *bytes);
        if (!certificates) {
            continue;
        }

        results.push_back(std::move(*certificates));
    }
    return results;
}

std::vector<SubBlockPayloadInfo> parseSubBlockPayloads(const ByteView& view,
                                                       std::int64_t signatureStart,
                                                       std::int64_t centralDirOffset,
                                                       const std::vector<SubBlockHead>& subBlocks)
{
    std::vector<SubBlockPayloadInfo> results;
    const std::int64_t payloadLimit = centralDirOffset - kHapSignHeadSize;
    results.reserve(subBlocks.size());

    for (const auto& block : subBlocks) {
        const std::int64_t dataOffset = signatureStart + block.offset;
        const std::int64_t dataEnd = dataOffset + block.length;
        if (block.length == 0 || dataOffset < signatureStart || dataEnd > payloadLimit || dataEnd < dataOffset) {
            results.push_back(SubBlockPayloadInfo{
                block,
                block.type == kHapSignatureSchemeV1BlockId,
                block.type == kHapProfileBlockId,
                block.type == kHapPropertyBlockId,
                block.type == kHapProofOfRotationBlockId,
                false,
                {},
                {},
                0,
                0,
                {},
                {},
                {},
                {},
                false,
                0,
                0,
                0,
                {"invalid-range"}});
            continue;
        }

        const auto bytes = view.slice(dataOffset, block.length);
        if (!bytes) {
            results.push_back(SubBlockPayloadInfo{
                block,
                block.type == kHapSignatureSchemeV1BlockId,
                block.type == kHapProfileBlockId,
                block.type == kHapPropertyBlockId,
                block.type == kHapProofOfRotationBlockId,
                false,
                {},
                {},
                0,
                0,
                {},
                {},
                {},
                {},
                false,
                0,
                0,
                0,
                {"read-failed"}});
            continue;
        }

        SubBlockPayloadInfo info{
            block,
            block.type == kHapSignatureSchemeV1BlockId,
            block.type == kHapProfileBlockId,
            block.type == kHapPropertyBlockId,
            block.type == kHapProofOfRotationBlockId,
            false,
            {},
            {},
            0,
            0,
            {},
            {},
            {},
            {},
            false,
            0,
            0,
            0,
            {}};

        const unsigned char* ptr = bytes->data();
        PKCS7* pkcs7 = d2i_PKCS7(nullptr, &ptr, static_cast<long>(bytes->size()));
        if (pkcs7 == nullptr) {
            if (block.type == kHapPropertyBlockId && bytes->size() >= 12) {
                info.hasCodeSignReference = true;
                info.codeSignBlockType = ByteView(*bytes).readU32(0).value_or(0);
                info.codeSignBlockLength = ByteView(*bytes).readU32(4).value_or(0);
                info.codeSignBlockOffset = ByteView(*bytes).readU32(8).value_or(0);
                if (info.codeSignBlockType == kHapCodeSignBlockId) {
                    std::ostringstream note;
                    note << "code-sign-ref: type=0x30000001"
                         << " length=" << std::dec << info.codeSignBlockLength
                         << " offset=0x" << std::hex << info.codeSignBlockOffset;
                    info.notes.push_back(note.str());
                } else {
                    info.notes.push_back("code-sign-ref-unknown-type");
                }
            } else {
                info.notes.push_back("not-parsed-as-pkcs7");
            }
            results.push_back(std::move(info));
            continue;
        }

        info.parsedAsPkcs7 = true;
        info.pkcs7Type = pkcs7TypeName(pkcs7);
        info.contentType = pkcs7ContentTypeName(pkcs7);
        info.signers = extractSignerInfos(pkcs7);

        STACK_OF(PKCS7_SIGNER_INFO)* signerInfos = PKCS7_get_signer_info(pkcs7);
        if (signerInfos != nullptr) {
            info.signerCount = static_cast<std::size_t>(sk_PKCS7_SIGNER_INFO_num(signerInfos));
            for (const auto& signer : info.signers) {
                info.digestAlgorithms.push_back(signer.digestAlgorithm);
                info.signatureAlgorithms.push_back(signer.signatureAlgorithm);
                if (!signer.signingTime.empty()) {
                    info.signingTimes.push_back(signer.signingTime);
                }
            }
        }

        STACK_OF(X509)* certStack = nullptr;
        if (PKCS7_type_is_signed(pkcs7) && pkcs7->d.sign != nullptr) {
            certStack = pkcs7->d.sign->cert;
        } else if (PKCS7_type_is_signedAndEnveloped(pkcs7) && pkcs7->d.signed_and_enveloped != nullptr) {
            certStack = pkcs7->d.signed_and_enveloped->cert;
        }
        if (certStack != nullptr) {
            info.certificateCount = static_cast<std::size_t>(sk_X509_num(certStack));
        }

        if (info.pkcs7Type.empty()) {
            info.notes.push_back("pkcs7-type-unavailable");
        }
        if (info.contentType.empty()) {
            info.notes.push_back("content-type-unavailable");
        }

        PKCS7_free(pkcs7);
        results.push_back(std::move(info));
    }

    return results;
}

const SubBlockPayloadInfo* findPayloadByType(const Summary& summary, std::uint32_t type)
{
    for (const auto& payload : summary.subBlockPayloads) {
        if (payload.head.type == type) {
            return &payload;
        }
    }
    return nullptr;
}

const SubBlockCertificateInfo* findCertificatesByType(const Summary& summary, std::uint32_t type)
{
    for (const auto& certificates : summary.subBlockCertificates) {
        if (certificates.head.type == type) {
            return &certificates;
        }
    }
    return nullptr;
}

void printBlockRelationships(const Summary& summary)
{
    const bool hasProfileBlock = findPayloadByType(summary, kHapProfileBlockId) != nullptr;
    const bool hasPropertyBlock = findPayloadByType(summary, kHapPropertyBlockId) != nullptr;
    const bool hasProofOfRotation = findPayloadByType(summary, kHapProofOfRotationBlockId) != nullptr;
    const bool propertyDependsOnProfile = hasPropertyBlock && hasProfileBlock;

    bool hasCodeSignRef = false;
    std::uint32_t codeSignLen = 0;
    std::uint32_t codeSignOff = 0;
    const SubBlockPayloadInfo* propertyPayload = findPayloadByType(summary, kHapPropertyBlockId);
    if (propertyPayload != nullptr && propertyPayload->hasCodeSignReference) {
        hasCodeSignRef = true;
        codeSignLen = propertyPayload->codeSignBlockLength;
        codeSignOff = propertyPayload->codeSignBlockOffset;
    }

    const std::string present = "present";
    const std::string absent = "absent";

    auto blockLabel = [&](const std::string& status) -> std::string {
        return "[" + status + "]";
    };

    logMessage(ParserLogLevel::Info, "");
    logMessage(ParserLogLevel::Info, "============================================================================");
    logMessage(ParserLogLevel::Info, "HAP SIGNING BLOCK STRUCTURE");
    logMessage(ParserLogLevel::Info, "============================================================================");
    logMessage(ParserLogLevel::Info, "");
    logMessage(ParserLogLevel::Info, "  These blocks are SIBLINGS inside one HAP signing structure.");
    logMessage(ParserLogLevel::Info, "  They are NOT pieces of a certificate chain.");
    logMessage(ParserLogLevel::Info, "");

    logMessage(ParserLogLevel::Info, "    +--------------------------------------------------+");
    logMessage(ParserLogLevel::Info, "    |              HAP SIGNING BLOCK                  |");
    logMessage(ParserLogLevel::Info, "    +--------------------------------------------------+");
    logMessage(ParserLogLevel::Info, "    |  [0x20000000]  AppSignatureBlock                |");
    logMessage(ParserLogLevel::Info, "    |                (main app signature CMS block)   |");
    logMessage(ParserLogLevel::Info, "    +--------------------------------------------------+");

    logMessage(ParserLogLevel::Info, "    |  [0x20000001]  ProofOfRotationBlock             |");
    logMessage(ParserLogLevel::Info, "    |                (certificate rotation chain)" +
                                   std::string(hasProofOfRotation ? 15 : 16, ' ') +
                                   blockLabel(hasProofOfRotation ? present : absent) +
                                   std::string(2, ' ') + "|");
    logMessage(ParserLogLevel::Info, "    +--------------------------------------------------+");

    logMessage(ParserLogLevel::Info, "    |  [0x20000002]  ProfileBlock                     |");
    logMessage(ParserLogLevel::Info, "    |                (provisioning profile)" +
                                   std::string(22, ' ') +
                                   blockLabel(hasProfileBlock ? present : absent) +
                                   std::string(2, ' ') + "|");
    logMessage(ParserLogLevel::Info, "    +--------------------------------------------------+");

    logMessage(ParserLogLevel::Info, "    |  [0x20000003]  PropertyBlock                    |");
    if (hasPropertyBlock && hasCodeSignRef) {
        logMessage(ParserLogLevel::Info, "    |                (code-sign ref -> 0x30000001)     |");
    } else if (hasPropertyBlock) {
        logMessage(ParserLogLevel::Info, "    |                (" + blockLabel(present) + " property data)                |");
    } else {
        logMessage(ParserLogLevel::Info, "    |                (" + blockLabel(absent) + " property data)                |");
    }
    logMessage(ParserLogLevel::Info, "    +--------------------------------------------------+");
    logMessage(ParserLogLevel::Info, "");

    logMessage(ParserLogLevel::Info, "  EXTERNAL (referenced via PropertyBlock):");
    logMessage(ParserLogLevel::Info, "    [0x30000001]  CodeSignBlock" +
                                   std::string(hasCodeSignRef ? 24 : 25, ' ') +
                                   blockLabel(hasCodeSignRef ? present : absent));
    if (hasCodeSignRef) {
         std::ostringstream refLine;
         refLine << "                  (length=" << std::dec << codeSignLen
                 << " offset=0x" << std::hex << codeSignOff << ")";
         logMessage(ParserLogLevel::Info, refLine.str());
     }
    logMessage(ParserLogLevel::Info, "");

    logMessage(ParserLogLevel::Info, "----------------------------------------------------------------------------");
    logMessage(ParserLogLevel::Info, "BLOCK PURPOSES");
    logMessage(ParserLogLevel::Info, "----------------------------------------------------------------------------");
    logMessage(ParserLogLevel::Info, "  [0x20000000]  AppSignatureBlock       Main app signature (CMS/PKCS7)");
    logMessage(ParserLogLevel::Info, "  [0x20000001]  ProofOfRotationBlock    Certificate rotation chain");
    logMessage(ParserLogLevel::Info, "  [0x20000002]  ProfileBlock            Provisioning profile content");
    logMessage(ParserLogLevel::Info, "  [0x20000003]  PropertyBlock           Code-sign / property metadata");
    logMessage(ParserLogLevel::Info, "  [0x30000001]  CodeSignBlock           Code signature data (external)");
    logMessage(ParserLogLevel::Info, "");

    logMessage(ParserLogLevel::Info, "----------------------------------------------------------------------------");
    logMessage(ParserLogLevel::Info, "BLOCK RELATIONSHIPS");
    logMessage(ParserLogLevel::Info, "----------------------------------------------------------------------------");
    logMessage(ParserLogLevel::Info, "  AppSignatureBlock    <-->  ProfileBlock           : Siblings in same signing block");
    logMessage(ParserLogLevel::Info, "  AppSignatureBlock    <-->  PropertyBlock          : Siblings in same signing block");
    logMessage(ParserLogLevel::Info, "  AppSignatureBlock    <-->  ProofOfRotationBlock   : Siblings in same signing block");
    logMessage(ParserLogLevel::Info, "  ProfileBlock         <-->  PropertyBlock          : PropertyBlock can reference");
    logMessage(ParserLogLevel::Info, "                                                      ProfileBlock during code-sign");
    logMessage(ParserLogLevel::Info, "                                                      verification (stronger relation)");
    logMessage(ParserLogLevel::Info, "  PropertyBlock        --->  CodeSignBlock          : PropertyBlock stores offset/length");
    logMessage(ParserLogLevel::Info, "                                                      pointing to CodeSignBlock data");
    logMessage(ParserLogLevel::Info, "");

    logMessage(ParserLogLevel::Info, "----------------------------------------------------------------------------");
    logMessage(ParserLogLevel::Info, "PROCESS FLOW");
    logMessage(ParserLogLevel::Info, "----------------------------------------------------------------------------");
    logMessage(ParserLogLevel::Info, "  1) AppSignatureBlock signs the entire app package");
    logMessage(ParserLogLevel::Info, "  2) ProofOfRotationBlock carries the certificate rotation chain");
    logMessage(ParserLogLevel::Info, "  3) ProfileBlock carries the provisioning profile with its own certificate chain");
    logMessage(ParserLogLevel::Info, "  4) PropertyBlock carries code-sign reference (offset/length to CodeSignBlock)");
    logMessage(ParserLogLevel::Info, "  5) During code-sign verification, PropertyBlock REQUIRES ProfileBlock content");
    logMessage(ParserLogLevel::Info, "     ProfileBlock provides OwnerID via ParseAppIdentifier(profile)");
    logMessage(ParserLogLevel::Info, "     PropertyBlock provides CodeSignBlock location (offset/length)");
    logMessage(ParserLogLevel::Info, "  6) All optional blocks are covered by the overall HAP signing digest");
    logMessage(ParserLogLevel::Info, "");
    logMessage(ParserLogLevel::Info, "============================================================================");
}

void printKnownBlockView(const Summary& summary)
{
    const std::uint32_t knownTypes[] = {
        kHapSignatureSchemeV1BlockId,
        kHapProofOfRotationBlockId,
        kHapProfileBlockId,
        kHapPropertyBlockId,
    };

    logMessage(ParserLogLevel::Info, "");
    logMessage(ParserLogLevel::Info, "Block details");
    logMessage(ParserLogLevel::Info, "-------------");

    for (const auto type : knownTypes) {
        const SubBlockPayloadInfo* payload = findPayloadByType(summary, type);
        if (payload == nullptr) {
            logMessage(ParserLogLevel::Info, blockTypeName(type) + ": (absent)");
            continue;
        }

        std::ostringstream header;
        header << blockTypeName(type) << "  |  len=" << payload->head.length
               << "  off=0x" << std::hex << payload->head.offset << std::dec;
        logMessage(ParserLogLevel::Info, header.str());

        if (payload->parsedAsPkcs7) {
            std::ostringstream line;
            line << "  PKCS7: " << payload->pkcs7Type;
            if (!payload->contentType.empty()) {
                line << "  content=" << payload->contentType;
            }
            line << "  signers=" << payload->signerCount
                 << "  certs=" << payload->certificateCount;
            logMessage(ParserLogLevel::Info, line.str());

            for (std::size_t i = 0; i < payload->signers.size(); ++i) {
                const auto& s = payload->signers[i];
                std::ostringstream si;
                si << "  signer[" << i << "]: subj=" << s.subject
                   << "  issu=" << s.issuer << "  serial=" << s.serial
                   << "  hash=" << s.digestAlgorithm
                   << "  sign=" << s.signatureAlgorithm;
                logMessage(ParserLogLevel::Info, si.str());
                if (!s.signingTime.empty()) {
                    logMessage(ParserLogLevel::Info, "    signedAt=" + s.signingTime);
                }
                if (!s.signedAttributes.empty()) {
                    std::string attrs;
                    for (std::size_t j = 0; j < s.signedAttributes.size(); ++j) {
                        if (j > 0) attrs += ", ";
                        attrs += s.signedAttributes[j];
                    }
                    logMessage(ParserLogLevel::Info, "    signedAttrs=" + attrs);
                }
            }
        } else {
            std::string note;
            for (const auto& n : payload->notes) {
                if (n.find("code-sign-ref") != std::string::npos) continue;
                if (!note.empty()) note += "; ";
                note += n;
            }
            if (note.empty()) {
                note = "binary-data";
            }
            logMessage(ParserLogLevel::Info, "  PKCS7: no  [" + note + "]");
        }

        const SubBlockCertificateInfo* certs = findCertificatesByType(summary, type);
        if (certs != nullptr) {
            std::string validStr = certs->validation.allCertificatesCurrentlyValid ? "ok" : "issues";
            logMessage(ParserLogLevel::Info, "  cert-chain[" + std::to_string(certs->certificates.size()) +
                                           "]: hashChain=" + std::string(certs->validation.hasThreeLevelChain ? "3" : "") +
                                           std::string(certs->validation.hasTwoLevelChain ? "2" : "") +
                                           "  rootSelfSigned=" + std::string(certs->validation.rootLooksSelfSigned ? "yes" : "no") +
                                           "  linksMatch=" + std::string(certs->validation.issuerSubjectLinksMatch ? "yes" : "no") +
                                           "  sigVerify=" + std::string(certs->validation.signaturesVerify ? "ok" : "FAIL") +
                                           "  valid=" + validStr);

            auto padRight = [](const std::string& s, std::size_t w) -> std::string {
                if (s.size() >= w) return s.substr(0, w);
                return s + std::string(w - s.size(), ' ');
            };

            logMessage(ParserLogLevel::Info, "    " + padRight("Role", 13) + " " + padRight("Serial", 23) + " " +
                                           padRight("NotBefore", 29) + " " + padRight("NotAfter", 29) + " " +
                                           padRight("Key", 23) + " " + padRight("CA", 4) + "  Valid");
            logMessage(ParserLogLevel::Info, "    " + padRight("-------------", 13) + " " + padRight("-----------------------", 23) + " " +
                                           padRight("-----------------------------", 29) + " " + padRight("-----------------------------", 29) + " " +
                                           padRight("-----------------------", 23) + " " + padRight("----", 4) + "  -----");
            for (std::size_t i = 0; i < certs->certificates.size(); ++i) {
                const std::size_t srcIdx = certs->certificates.size() - 1 - i;
                const auto& c = certs->certificates[srcIdx];
                std::string role;
                if (i == 0) role = "Root";
                else if (i + 1 == certs->certificates.size()) role = "Leaf";
                else role = "Intermediate";

                std::string keyInfo;
                if (!c.publicKeyAlgorithm.empty()) {
                    keyInfo = c.publicKeyAlgorithm;
                    if (c.publicKeyBits > 0) {
                        keyInfo += " " + std::to_string(c.publicKeyBits);
                    }
                }

                std::string certValid = c.isCurrentlyValid ? "yes" : "no";

                std::ostringstream cl;
                cl << "    "
                   << padRight(role, 13) << " "
                   << padRight(c.serial, 23) << " "
                   << padRight(c.notBefore, 29) << " "
                   << padRight(c.notAfter, 29) << " "
                   << padRight(keyInfo, 23) << " "
                   << padRight(c.isCA ? "yes" : "no", 4) << "  "
                   << certValid;
                logMessage(ParserLogLevel::Info, cl.str());

                if (!c.keyUsage.empty()) {
                    std::string ku;
                    for (std::size_t j = 0; j < c.keyUsage.size(); ++j) {
                        if (j > 0) ku += ", ";
                        ku += c.keyUsage[j];
                    }
                    logMessage(ParserLogLevel::Info, "      keyUsage=" + ku);
                }
                if (!c.extendedKeyUsage.empty()) {
                    std::string eku;
                    for (std::size_t j = 0; j < c.extendedKeyUsage.size(); ++j) {
                        if (j > 0) eku += ", ";
                        eku += c.extendedKeyUsage[j];
                    }
                    logMessage(ParserLogLevel::Info, "      extKeyUsage=" + eku);
                }
                if (!c.subjectKeyIdentifier.empty()) {
                    logMessage(ParserLogLevel::Info, "      SKI=" + c.subjectKeyIdentifier);
                }
            }
            if (!certs->validation.issues.empty()) {
                for (const auto& issue : certs->validation.issues) {
                    logMessage(ParserLogLevel::Warn, "    issue: " + issue);
                }
            }
        } else if (type == kHapPropertyBlockId && payload->hasCodeSignReference) {
            logMessage(ParserLogLevel::Info, "  cert-chain: none (code-sign locator, 12 bytes)");
        } else if (type != kHapPropertyBlockId) {
            logMessage(ParserLogLevel::Info, "  cert-chain: none");
        }

        if (payload->hasCodeSignReference) {
            logMessage(ParserLogLevel::Info, "  code-sign-ref:");
            {
                std::ostringstream ref;
                 ref << "    target  0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
                     << payload->codeSignBlockType << std::setfill(' ') << std::nouppercase << std::dec
                     << "  (" << blockTypeName(payload->codeSignBlockType) << ")";
                logMessage(ParserLogLevel::Info, ref.str());
            }
            logMessage(ParserLogLevel::Info, "    length  " + std::to_string(payload->codeSignBlockLength) + " bytes");
            {
                std::ostringstream off;
                 off << "    offset  0x" << std::uppercase << std::hex << std::setw(6) << std::setfill('0')
                     << payload->codeSignBlockOffset << std::setfill(' ') << std::nouppercase;
                 logMessage(ParserLogLevel::Info, off.str());
            }
            const bool profileExists = findPayloadByType(summary, kHapProfileBlockId) != nullptr;
            logMessage(ParserLogLevel::Info, "    profile " + std::string(profileExists ? "required (present)" : "REQUIRED (MISSING!)"));
        }

        if (type == kHapProfileBlockId) {
            const bool propertyHasCodeSign = findPayloadByType(summary, kHapPropertyBlockId) != nullptr &&
                findPayloadByType(summary, kHapPropertyBlockId)->hasCodeSignReference;
            if (propertyHasCodeSign) {
                logMessage(ParserLogLevel::Info, "  consumed-by: PropertyBlock code-sign verification");
            }
        }
    }
}

std::string displayedCertificateRole(std::size_t displayedIndex, std::size_t count)
{
    if (count == 0) {
        return {};
    }
    if (displayedIndex == 0) {
        return "Root";
    }
    if (displayedIndex + 1 == count) {
        return "Leaf";
    }
    return "Intermediate";
}

std::string internalCertificateRole(std::size_t internalIndex, std::size_t count)
{
    if (count == 0) {
        return {};
    }
    if (internalIndex == 0) {
        return "Leaf";
    }
    if (internalIndex + 1 == count) {
        return "Root";
    }
    return "Intermediate";
}

std::optional<ByteView> loadFile(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    input.seekg(0, std::ios::end);
    const auto end = input.tellg();
    if (end < 0) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    input.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        if (!input) {
            return std::nullopt;
        }
    }
    return ByteView(std::move(bytes));
}

Summary summarizeHap(const ByteView& view)
{
    Summary summary;
    summary.fileSize = view.size();

    // HAP is ZIP-based, so the summary starts by anchoring on the best EOCD we
    // can justify from the bytes near the end of the file.
    const auto eocd = findBestEocd(view);
    if (!eocd) {
        summary.warnings.push_back("EOCD not found. This file may not be a valid non-ZIP64 HAP/ZIP.");
        return summary;
    }
    summary.eocd = *eocd;

    const std::int64_t eocdEnd = eocd->offset + 22 + eocd->commentLength;
    if (eocdEnd < view.size()) {
        summary.warnings.push_back("Extra trailing bytes exist after EOCD.");
    }

    const auto centralDirOffset = resolveCentralDirectoryOffset(view, *eocd);
    if (!centralDirOffset) {
        summary.warnings.push_back("Could not locate a plausible central directory start.");
        return summary;
    }
    summary.centralDirOffsetResolved = *centralDirOffset;

    if (*centralDirOffset + eocd->centralDirSize != eocd->offset) {
        summary.warnings.push_back("Central directory does not end exactly at EOCD start.");
    }

    const auto footer = parseSignatureFooterAt(view, *centralDirOffset - kHapSignHeadSize);
    if (!footer) {
        summary.warnings.push_back("Could not derive a plausible signature footer from the selected EOCD record.");
        return summary;
    }
    summary.signatureFooter = *footer;

    // At this point the structure we expect is:
    // [ZIP entries ...][HAP signature block][Central Directory][EOCD]
    // so the signing block starts signatureBlockSize bytes before the central directory.
    const std::int64_t signatureStart = *centralDirOffset - footer->signatureBlockSize;
    const std::int64_t signatureEnd = *centralDirOffset - 1;
    if (footer->signatureBlockSize <= 0 || signatureStart < 0) {
        summary.warnings.push_back("Invalid HAP signing block size.");
        return summary;
    }
    if (footer->blockCount < 0 || footer->blockCount > 1024) {
        summary.warnings.push_back("Invalid HAP signing block count.");
        return summary;
    }

    summary.signatureStart = signatureStart;
    summary.signatureEnd = signatureEnd;
    summary.subBlocks = parseSubBlockHeads(view, signatureStart, footer->blockCount);
    summary.subBlockPayloads =
        parseSubBlockPayloads(view, signatureStart, *centralDirOffset, summary.subBlocks);
    summary.subBlockCertificates =
        parseSubBlockCertificates(view, signatureStart, *centralDirOffset, summary.subBlocks);
    if (summary.subBlockCertificates.empty()) {
        summary.warnings.push_back("No PKCS7 certificate chains were decoded from the signature subblocks.");
    }

    const std::int64_t payloadLimit = *centralDirOffset - kHapSignHeadSize;
    for (const auto& block : summary.subBlocks) {
        const std::int64_t dataOffset = signatureStart + block.offset;
        const std::int64_t dataEnd = dataOffset + block.length;
        if (block.length == 0 || dataOffset < signatureStart || dataEnd > payloadLimit) continue;
        auto bytes = view.slice(dataOffset, block.length);
        if (!bytes) continue;

        if (block.type == kHapPropertyBlockId && !summary.propertyBlock) {
            PropertyBlockInfo info;
            info.head = block;
            info.hasCodeSigning = true;
            static const std::vector<std::string> knownLibs = {
                "libbcevchk.so", "libc++_shared.so", "libintegrity.so",
                "libhilog.so", "libace_napi.z.so", "libace_ndk.z.so",
            };
            std::string content(reinterpret_cast<const char*>(bytes->data()),
                               std::min(bytes->size(), size_t(8192)));
            for (const auto& lib : knownLibs) {
                if (content.find(lib) != std::string::npos || bytes->size() > 100000)
                    info.nativeLibs.push_back(lib);
            }
            if (!info.nativeLibs.empty() || bytes->size() >= 100)
                summary.propertyBlock = std::move(info);
        }

        if (block.type == kHapProfileBlockId && !summary.profile) {
            std::string json(reinterpret_cast<const char*>(bytes->data()),
                           std::min(bytes->size(), size_t(65536)));
            auto js = json.find('{');
            if (js != std::string::npos) {
                ProfileInfo pinfo;
                pinfo.head = block;
                pinfo.rawJson = json.substr(js);

                auto getStr = [&](const std::string& key) -> std::string {
                    auto p = pinfo.rawJson.find("\"" + key + "\"");
                    if (p == std::string::npos) return {};
                    p = pinfo.rawJson.find('"', p + key.size() + 3);
                    if (p == std::string::npos) return {};
                    auto e = pinfo.rawJson.find('"', p + 1);
                    if (e == std::string::npos) return {};
                    return pinfo.rawJson.substr(p + 1, e - p - 1);
                };
                auto getInt = [&](const std::string& key) -> std::int32_t {
                    auto p = pinfo.rawJson.find("\"" + key + "\"");
                    if (p == std::string::npos) return 0;
                    p = pinfo.rawJson.find(':', p + key.size() + 2);
                    if (p == std::string::npos) return 0;
                    while (++p < (std::int64_t)pinfo.rawJson.size() && std::isspace(pinfo.rawJson[p]));
                    std::int32_t v = 0;
                    while (p < (std::int64_t)pinfo.rawJson.size() && std::isdigit(pinfo.rawJson[p]))
                        v = v * 10 + (pinfo.rawJson[p++] - '0');
                    return v;
                };

                pinfo.versionName = getStr("version-name");
                pinfo.versionCode = getInt("version-code");
                pinfo.type = getStr("type");
                pinfo.issuer = getStr("issuer");
                pinfo.uuid = getStr("uuid");

                auto bi = pinfo.rawJson.find("\"bundle-info\"");
                if (bi != std::string::npos) {
                    pinfo.bundleName = getStr("bundle-name");
                    pinfo.developerId = getStr("developer-id");
                    pinfo.appIdentifier = getStr("app-identifier");
                    pinfo.apl = getStr("apl");
                    std::string devCert = getStr("distribution-certificate");
                    if (devCert.empty()) devCert = getStr("development-certificate");
                    if (!devCert.empty()) {
                        pinfo.developerCertificate = devCert;
                        std::string unescaped;
                        for (size_t i = 0; i < devCert.size(); ++i) {
                            if (devCert[i] == '\\' && i + 1 < devCert.size()) {
                                switch (devCert[i + 1]) {
                                case 'n': unescaped += '\n'; break;
                                case 't': unescaped += '\t'; break;
                                case 'r': unescaped += '\r'; break;
                                case '\\': unescaped += '\\'; break;
                                case '"': unescaped += '"'; break;
                                default: unescaped += devCert[i + 1]; break;
                                }
                                ++i;
                            } else {
                                unescaped += devCert[i];
                            }
                        }
                        auto b = unescaped.find("-----BEGIN CERTIFICATE-----");
                        auto e = unescaped.find("-----END CERTIFICATE-----");
                        if (b != std::string::npos && e != std::string::npos) {
                            std::string b64 = unescaped.substr(b + 27, e - b - 27);
                            b64.erase(std::remove(b64.begin(), b64.end(), '\n'), b64.end());
                            b64.erase(std::remove(b64.begin(), b64.end(), '\r'), b64.end());
                            b64.erase(std::remove(b64.begin(), b64.end(), ' '), b64.end());
                            BIO* b64Bio = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
                            BIO* b64Filter = BIO_new(BIO_f_base64());
                            BIO_set_flags(b64Filter, BIO_FLAGS_BASE64_NO_NL);
                            BIO* bio = BIO_push(b64Filter, b64Bio);
                            std::vector<unsigned char> der(4096);
                            int derLen = BIO_read(bio, der.data(), 4096);
                            if (derLen > 0) {
                                unsigned char md[EVP_MAX_MD_SIZE];
                                unsigned int mdLen = 0;
                                const unsigned char* derPtr = der.data();
                                X509* cert = d2i_X509(nullptr, &derPtr, derLen);
                                if (cert) {
                                    if (X509_digest(cert, EVP_sha256(), md, &mdLen) == 1 && mdLen > 0) {
                                        std::ostringstream fp;
                                        for (unsigned int i = 0; i < mdLen; ++i) {
                                            if (i > 0) fp << ":";
                                            fp << std::hex << std::uppercase << std::setw(2)
                                               << std::setfill('0') << static_cast<int>(md[i]);
                                        }
                                        pinfo.developerCertFingerprint = fp.str();
                                    }
                                    X509_free(cert);
                                }
                            }
                            BIO_free_all(bio);
                        }
                    }
                }
                summary.profile = std::move(pinfo);
            }
        }
    }

    if (summary.centralDirOffsetResolved) {
        // Collect .so file data offsets/sizes for segment-level hash extraction.
        // Collect .abc file hashes and raw data offsets for runtime verification.
        std::vector<std::string> soFileNames;
        std::vector<std::pair<std::int64_t, std::int64_t>> soOffsetsAndSizes;
        std::vector<std::pair<std::string, std::string>> abcNameAndSha256;

        std::int64_t cdPos = *summary.centralDirOffsetResolved;
        while (view.canRead(cdPos, 46)) {
            auto sigOpt = view.readU32(cdPos);
            if (!sigOpt || *sigOpt != kZipCentralDirSig) break;
            auto csOpt = view.readU32(cdPos + 20);
            auto nlOpt = view.readU16(cdPos + 28);
            auto elOpt = view.readU16(cdPos + 30);
            auto clOpt = view.readU16(cdPos + 32);
            auto lhOpt = view.readU32(cdPos + 42);
            if (!csOpt || !nlOpt || !elOpt || !clOpt || !lhOpt) break;
            std::uint32_t nameLen = *nlOpt, extraLen = *elOpt, commentLen = *clOpt;
            auto nameBytes = view.slice(cdPos + 46, nameLen);
            if (!nameBytes) break;
            std::string filename(reinterpret_cast<const char*>(nameBytes->data()), nameBytes->size());
            std::int64_t dataStart = *lhOpt + 30 + nameLen + extraLen;
            FileHashInfo fh;
            fh.filename = filename;
            fh.size = *csOpt;
            if (*csOpt > 0 && *csOpt < 100*1024*1024 && view.canRead(dataStart, *csOpt)) {
                auto fileData = view.slice(dataStart, *csOpt);
                if (fileData) {
                    unsigned char hash[SHA256_DIGEST_LENGTH];
                    SHA256(fileData->data(), fileData->size(), hash);
                    std::ostringstream hex, fmt;
                    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                        char buf[3];
                        std::snprintf(buf, sizeof(buf), "%02x", hash[i]);
                        hex << buf;
                        if (i > 0) fmt << ":";
                        fmt << buf;
                    }
                    fh.sha256 = hex.str();
                    fh.sha256Formatted = fmt.str();
                }
            }
            // Track .so files for segment-level hash extraction
            if (fh.filename.size() > 3 && fh.filename.substr(fh.filename.size() - 3) == ".so"
                && fh.size > 0 && view.canRead(dataStart, fh.size)) {
                soFileNames.push_back(fh.filename);
                soOffsetsAndSizes.emplace_back(dataStart, fh.size);
            }
            // Track .abc files for runtime memory verification
            if (fh.filename.size() > 4 && fh.filename.substr(fh.filename.size() - 4) == ".abc"
                && !fh.sha256.empty()) {
                abcNameAndSha256.emplace_back(fh.filename, fh.sha256);
            }
            summary.fileHashes.push_back(std::move(fh));
            cdPos += 46 + nameLen + extraLen + commentLen;
        }

        // Compute ELF segment-level reference hashes for .so files
        // and collect .abc reference hashes for runtime verification.
        if (!soFileNames.empty()) {
            summary.soReferenceHashes = extractSoReferenceHashes(
                view.data(), soFileNames, soOffsetsAndSizes);
        }
        if (!abcNameAndSha256.empty()) {
            summary.abcReferenceHashes = extractAbcReferenceHashes(
                abcNameAndSha256);
        }
    }

    if (summary.profile && !summary.profile->developerCertificate.empty()) {
        auto unescape = [](const std::string& s) -> std::string {
            std::string r;
            for (size_t i = 0; i < s.size(); ++i) {
                if (s[i] == '\\' && i+1 < s.size()) {
                    switch (s[i+1]) { case 'n': r+='\n'; break; case 't': r+='\t'; break;
                    case 'r': r+='\r'; break; case '\\': r+='\\'; break;
                    case '"': r+='"'; break; default: r+=s[i+1]; break; } ++i;
                } else r += s[i];
            } return r;
        };
        std::string pem = unescape(summary.profile->developerCertificate);
        auto b = pem.find("-----BEGIN CERTIFICATE-----");
        auto e = pem.find("-----END CERTIFICATE-----");
        if (b != std::string::npos && e != std::string::npos) {
            std::string b64 = pem.substr(b+27, e-b-27);
            b64.erase(std::remove(b64.begin(),b64.end(),'\n'),b64.end());
            b64.erase(std::remove(b64.begin(),b64.end(),'\r'),b64.end());
            b64.erase(std::remove(b64.begin(),b64.end(),' '),b64.end());
            BIO* b64Bio = BIO_new_mem_buf(b64.data(), (int)b64.size());
            BIO* bf = BIO_new(BIO_f_base64());
            BIO_set_flags(bf, BIO_FLAGS_BASE64_NO_NL);
            BIO* bio = BIO_push(bf, b64Bio);
            std::vector<unsigned char> der(8192);
            int dl = BIO_read(bio, der.data(), 8192);
            if (dl > 0) {
                const unsigned char* dp = der.data();
                X509* devCert = d2i_X509(nullptr, &dp, dl);
                if (devCert) {
                    auto info = extractCertificateInfo(devCert);
                    info.sha256Fingerprint = summary.profile->developerCertFingerprint;
                    summary.profile->developerCertInfo = info;
                    summary.identityChain.push_back(info);

                    std::string nextIssuer = info.issuer;
                    while (!nextIssuer.empty() && nextIssuer != info.subject) {
                        bool found = false;
                        for (auto& chain : summary.subBlockCertificates) {
                            for (auto& c : chain.certificates) {
                                if (c.subject == nextIssuer) {
                                    summary.identityChain.push_back(c);
                                    nextIssuer = c.issuer;
                                    if (c.subject == c.issuer) nextIssuer.clear();
                                    found = true;
                                    break;
                                }
                            }
                            if (found) break;
                        }
                        if (!found) {
                            CertificateInfo anchor;
                            anchor.subject = nextIssuer;
                            anchor.isTrustAnchor = true;
                            anchor.isCurrentlyValid = true;
                            summary.identityChain.push_back(anchor);
                            nextIssuer.clear();
                        }
                    }
                    summary.identityChainVerified = summary.identityIssues.empty();
                    X509_free(devCert);
                }
            }
            BIO_free_all(bio);
        }
    }

    return summary;
}

}  // namespace

std::optional<Summary> HapParser::parseFile(const std::string& path) const
{
    const auto view = loadFile(path);
    if (!view) {
        return std::nullopt;
    }
    return summarizeHap(*view);
}

void HapParser::printSummary(const Summary& summary, const DisplayOptions& opts) const
{
    // printSummary intentionally mirrors summarizeHap step-by-step so the output
    // can be read in the same order the parser derived it.
    logMessage(ParserLogLevel::Info, "HAP summary");
    logMessage(ParserLogLevel::Info, "===========");

    auto hexify = [](const std::string& label, std::int64_t value) -> std::string {
        std::ostringstream os;
        os << label << " 0x" << std::hex << std::uppercase << value << std::nouppercase << std::dec
           << " (" << value << ")";
        return os.str();
    };

    logMessage(ParserLogLevel::Info, hexify("FileSize:", summary.fileSize));

    if (!summary.eocd) {
        for (const auto& warning : summary.warnings) {
            logMessage(ParserLogLevel::Warn, "Warning: " + warning);
        }
        return;
    }

    const auto& eocd = *summary.eocd;
    logMessage(ParserLogLevel::Info, hexify("EOCDOffset:", eocd.offset));
    logMessage(ParserLogLevel::Info, hexify("EOCDSize:", 22 + eocd.commentLength));
    logMessage(ParserLogLevel::Info, hexify("CentralDirectoryOffsetRaw:", eocd.centralDirOffsetRaw));
    logMessage(ParserLogLevel::Info, hexify("CentralDirectorySize:", eocd.centralDirSize));
    {
        std::ostringstream os;
        os << "TotalEntries: " << eocd.totalEntries;
        logMessage(ParserLogLevel::Info, os.str());
    }
    logMessage(ParserLogLevel::Info, "CommentLength: " + std::to_string(eocd.commentLength));

    if (summary.centralDirOffsetResolved) {
        logMessage(ParserLogLevel::Info, hexify("CentralDirectoryOffset:", *summary.centralDirOffsetResolved));
        logMessage(ParserLogLevel::Info, hexify("CentralDirectoryEnd:", *summary.centralDirOffsetResolved + eocd.centralDirSize));
    }

    if (summary.signatureFooter && summary.signatureStart && summary.signatureEnd) {
        logMessage(ParserLogLevel::Info, hexify("SignatureBlockCount:", summary.signatureFooter->blockCount));
        logMessage(ParserLogLevel::Info, hexify("SignatureBlockSize:", summary.signatureFooter->signatureBlockSize));
        logMessage(ParserLogLevel::Info, hexify("SignatureStart:", *summary.signatureStart));
        logMessage(ParserLogLevel::Info, hexify("SignatureEnd:", *summary.signatureEnd));
        {
            std::ostringstream os;
            os << "SignatureVersion: " << summary.signatureFooter->version;
            logMessage(ParserLogLevel::Info, os.str());
        }
        if (!summary.signatureFooter->signatureMagic.empty()) {
            const auto& magic = summary.signatureFooter->signatureMagic;
            std::ostringstream ms;
            ms << "SignatureMagicHex: ";
            for (std::size_t i = 0; i < magic.size(); ++i) {
                ms << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                   << (static_cast<int>(magic[i]) & 0xFF) << std::setfill(' ') << std::nouppercase;
                if (i + 1 < magic.size()) ms << " ";
            }
            logMessage(ParserLogLevel::Info, ms.str());
        }
        printBlockRelationships(summary);

        logMessage(ParserLogLevel::Info, "");
        logMessage(ParserLogLevel::Info, "Subblocks overview");
        logMessage(ParserLogLevel::Info, "------------------");
        {
            logMessage(ParserLogLevel::Info, "  #    Block Type             Length     Offset    Name");
            logMessage(ParserLogLevel::Info, "  ---  --------------------  --------  --------  -----------------");
            for (std::size_t i = 0; i < summary.subBlocks.size(); ++i) {
                const auto& block = summary.subBlocks[i];
                std::ostringstream line;
                line << "  " << std::setw(3) << i
                     << "  0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << std::right << block.type
                     << std::setfill(' ') << std::nouppercase << std::dec
                     << "  " << std::setw(8) << block.length
                     << "  0x" << std::hex << std::setw(6) << std::setfill('0') << std::right << block.offset
                     << std::setfill(' ') << std::dec
                     << "  " << block.typeName;
                logMessage(ParserLogLevel::Info, line.str());
            }
        }

        printKnownBlockView(summary);
    }

    for (const auto& warning : summary.warnings) {
        logMessage(ParserLogLevel::Warn, "Warning: " + warning);
    }
}

RuntimeVerifyResult HapParser::verifyRuntime(const Summary& summary)
{
    return verifyRuntimeIntegrity(summary.soReferenceHashes, summary.abcReferenceHashes);
}
