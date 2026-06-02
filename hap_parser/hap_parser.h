#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class HapParser {
public:
    struct EocdInfo {
        std::int64_t offset = -1;
        std::uint16_t diskNumber = 0;
        std::uint16_t centralDirDiskNumber = 0;
        std::uint16_t entriesThisDisk = 0;
        std::uint16_t totalEntries = 0;
        std::uint32_t centralDirSize = 0;
        std::uint32_t centralDirOffsetRaw = 0;
        std::uint16_t commentLength = 0;
    };

    struct SignatureFooterInfo {
        std::int32_t blockCount = 0;
        std::int64_t signatureBlockSize = 0;
        std::string signatureMagic;
        std::int32_t version = 0;
    };

    struct SubBlockHead {
        std::uint32_t type = 0;
        std::uint32_t length = 0;
        std::uint32_t offset = 0;
        std::string typeName;
    };

    struct CertificateInfo {
        std::string subject;
        std::string issuer;
        std::string serial;
        std::string notBefore;
        std::string notAfter;
        std::string publicKeyAlgorithm;
        int publicKeyBits = 0;
        std::string certificateSignatureAlgorithm;
        bool isCA = false;
        std::vector<std::string> keyUsage;
        std::vector<std::string> extendedKeyUsage;
        std::string subjectKeyIdentifier;
        std::string authorityKeyIdentifier;
        bool isCurrentlyValid = false;
        bool isExpired = false;
        bool isNotYetValid = false;
        std::string sha256Fingerprint;
        std::int32_t certVersion = 0;
        std::string signatureAlgorithm;
    };

    struct SignerInfo {
        std::string subject;
        std::string issuer;
        std::string serial;
        std::string digestAlgorithm;
        std::string signatureAlgorithm;
        std::string signingTime;
        std::vector<std::string> signedAttributes;
        std::vector<std::string> unsignedAttributes;
    };

    struct ChainValidationInfo {
        bool hasThreeLevelChain = false;
        bool hasTwoLevelChain = false;
        bool hasFullChain = false;
        bool allCertificatesCurrentlyValid = false;
        bool issuerSubjectLinksMatch = false;
        bool signaturesVerify = false;
        bool rootLooksSelfSigned = false;
        bool rootIncluded = false;
        std::vector<std::string> issues;
        std::int64_t certCount = 0;
        bool hasTwoLevelChainWithSystemRoot = false;
    };

    struct SignatureVerificationInfo {
        bool digestVerified = false;
        bool contentIntegrityOk = false;
        bool signatureVerified = false;
        std::string contentDigestExpected;
        std::string contentDigestActual;
        std::string digestAlgorithm;
        std::string signatureAlgorithm;
        std::vector<std::string> issues;
    };

    struct SubBlockCertificateInfo {
        SubBlockHead head;
        std::vector<CertificateInfo> certificates;
        ChainValidationInfo validation;
        bool isAppSignatureBlock = false;
        bool isProfileBlock = false;
        std::optional<SignatureVerificationInfo> sigVerification;
    };

    struct SubBlockPayloadInfo {
        SubBlockHead head;
        bool isAppSignatureBlock = false;
        bool isProfileBlock = false;
        bool isPropertyBlock = false;
        bool isProofOfRotationBlock = false;
        bool parsedAsPkcs7 = false;
        std::string pkcs7Type;
        std::string contentType;
        std::size_t signerCount = 0;
        std::size_t certificateCount = 0;
        std::vector<SignerInfo> signers;
        std::vector<std::string> digestAlgorithms;
        std::vector<std::string> signatureAlgorithms;
        std::vector<std::string> signingTimes;
        bool hasCodeSignReference = false;
        std::uint32_t codeSignBlockType = 0;
        std::uint32_t codeSignBlockLength = 0;
        std::uint32_t codeSignBlockOffset = 0;
        std::vector<std::string> notes;
    };

    struct ProfileInfo {
        SubBlockHead head;
        std::string versionName;
        std::int32_t versionCode = 0;
        std::string type;
        std::string bundleName;
        std::string developerId;
        std::string appIdentifier;
        std::string apl;
        std::string issuer;
        std::string uuid;
        std::string notBefore;
        std::string notAfter;
        std::vector<std::string> permissions;
        std::vector<std::string> allowedAcls;
        std::vector<std::string> deviceIds;
        std::string rawJson;
        std::string developerCertificate;
        std::string developerCertFingerprint;
    };

    struct PropertyBlockInfo {
        SubBlockHead head;
        bool hasCodeSigning = false;
        std::vector<std::string> nativeLibs;
    };

    struct FileHashInfo {
        std::string filename;
        std::int64_t size = 0;
        std::string sha256;
        std::string sha256Formatted;
    };

    struct Summary {
        std::int64_t fileSize = 0;
        std::optional<EocdInfo> eocd;
        std::optional<std::int64_t> centralDirOffsetResolved;
        std::optional<SignatureFooterInfo> signatureFooter;
        std::optional<std::int64_t> signatureStart;
        std::optional<std::int64_t> signatureEnd;
        std::vector<SubBlockHead> subBlocks;
        std::vector<SubBlockPayloadInfo> subBlockPayloads;
        std::vector<SubBlockCertificateInfo> subBlockCertificates;
        std::optional<ProfileInfo> profile;
        std::optional<PropertyBlockInfo> propertyBlock;
        std::vector<FileHashInfo> fileHashes;
        std::vector<std::string> warnings;
    };

    HapParser() = default;

    struct DisplayOptions {
        bool showAll;
        bool showLayout;
        bool showCerts;
        bool showProfile;
        bool showCodeSign;
        bool showHashes;
        bool showIntegrity;
        std::string expectedManifest;
        DisplayOptions() : showAll(false), showLayout(false), showCerts(false),
                          showProfile(false), showCodeSign(false), showHashes(false),
                          showIntegrity(false) {}
    };

    std::optional<Summary> parseFile(const std::string& path) const;
    void printSummary(const Summary& summary, const DisplayOptions& opts = {}) const;
};
