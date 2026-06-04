#pragma once

#include "HapAnalyzer.h"

#include <map>
#include <string>
#include <vector>

struct CertNode {
    std::string role;
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string keyInfo;
    std::string validity;
    std::string sha256;
    bool        valid = false;
    int         chainIdx = 0;
    int         certIdx  = 0;
};

struct FileEntry {
    std::string protect;
    std::string filename;
    int64_t     size = 0;
    std::string sha256;
    int         integrity   = 0;
    int         manifestCmp = 0;
    std::string expectedHash;
};

struct NestedHap {
    std::string              name;
    HapAnalyzerCtx*          ctx = nullptr;
    std::vector<CertNode>    certNodes;
    std::vector<FileEntry>   fileEntries;
    std::vector<std::string> missingLibs;
};

class AppState {
public:
    int lang = 0;

    HapAnalyzerCtx* ctx         = nullptr;
    std::string     currentFile;
    std::string     statusMsg;
    bool            fileLoaded  = false;
    bool            loadError   = false;

    std::vector<CertNode>               certNodes;
    std::vector<FileEntry>              fileEntries;
    std::vector<std::string>            missingLibs;
    std::map<std::string, std::string>  expectedHashes;
    bool hasManifest    = false;
    bool autoManifest   = false;

    std::vector<NestedHap> nestedHaps;
    std::string            nestedTempDir;

    // ── File loading ────────────────────────────────────────────────────

    void loadFile(const std::string& path);
    void reload();

    // ── Manifest ────────────────────────────────────────────────────────

    void loadManifest(const std::string& path);
    void saveCurrentAsManifest();
    void clearManifest();

private:
    void applyManifestToEntries();
    void collectEntries();
    void parseNestedHaps(const std::string& appPath);
    void collectNestedEntries(HapAnalyzerCtx* ctx, NestedHap& nh);

    static std::string getAndFree(const char* s);
};
