#include <sstream>
#include "AppState.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

std::string AppState::getAndFree(const char* s) {
    std::string r = s ? s : "";
    if (s) free((char*)s);
    return r;
}

static bool isSystemLib(const std::string& path) {
    if (path.size() < 4 || path.substr(path.size() - 3) != ".so") return false;
    return path.find("libs/") != 0;
}

void AppState::applyManifestToEntries() {
    if (!hasManifest) return;
    for (auto& e : fileEntries) {
        if (isSystemLib(e.filename)) continue;
        auto it = expectedHashes.find(e.filename);
        if (it != expectedHashes.end()) {
            e.expectedHash = it->second;
            std::string s = e.sha256;
            s.erase(std::remove(s.begin(), s.end(), ':'), s.end());
            e.manifestCmp = (s == it->second) ? 1 : 2;
        } else {
            e.manifestCmp = 3;
        }
    }
    for (auto& nh : nestedHaps) {
        for (auto& e : nh.fileEntries) {
            if (isSystemLib(e.filename)) continue;
            auto it = expectedHashes.find(e.filename);
            if (it != expectedHashes.end()) {
                e.expectedHash = it->second;
                std::string s = e.sha256;
                s.erase(std::remove(s.begin(), s.end(), ':'), s.end());
                e.manifestCmp = (s == it->second) ? 1 : 2;
            } else {
                e.manifestCmp = 3;
            }
        }
    }
}

void AppState::loadManifest(const std::string& path) {
    expectedHashes.clear();
    hasManifest = false;
    std::ifstream mf(path);
    if (!mf) return;
    std::string content((std::istreambuf_iterator<char>(mf)), {});
    auto fp = content.find("\"files\"");
    if (fp == std::string::npos) return;
    auto objStart = content.find('{', fp);
    auto objEnd = objStart;
    int depth = 0;
    while (objEnd < (int64_t)content.size()) {
        if (content[objEnd] == '{') depth++;
        else if (content[objEnd] == '}' && --depth == 0) break;
        objEnd++;
    }
    if (objEnd <= objStart) return;
    std::string inner = content.substr(objStart + 1, objEnd - objStart - 1);
    std::istringstream iss(inner);
    std::string line;
    while (std::getline(iss, line, ',')) {
        auto cp = line.find(':');
        if (cp == std::string::npos) continue;
        std::string fn = line.substr(0, cp);
        std::string hh = line.substr(cp + 1);
        for (char c : {'"', ' ', '\t', '\n', '\r'}) {
            fn.erase(std::remove(fn.begin(), fn.end(), c), fn.end());
            hh.erase(std::remove(hh.begin(), hh.end(), c), hh.end());
        }
        hh.erase(std::remove(hh.begin(), hh.end(), ':'), hh.end());
        std::transform(hh.begin(), hh.end(), hh.begin(), ::tolower);
        if (!fn.empty() && hh.size() >= 64) expectedHashes[fn] = hh;
    }
    hasManifest = !expectedHashes.empty();
}

void AppState::saveCurrentAsManifest() {
    expectedHashes.clear();
    for (auto& e : fileEntries) {
        if (isSystemLib(e.filename)) continue;
        std::string s = e.sha256;
        s.erase(std::remove(s.begin(), s.end(), ':'), s.end());
        expectedHashes[e.filename] = s;
    }
    hasManifest = true;
    autoManifest = true;
    applyManifestToEntries();
    std::ofstream of(std::string(getenv("HOME")) + "/.hap_analyzer_ref.json");
    of << "{\"files\":{";
    bool first = true;
    for (auto& kv : expectedHashes) {
        if (!first) of << ",";
        of << "\n  \"" << kv.first << "\":\"" << kv.second << "\"";
        first = false;
    }
    of << "\n}}";
}

void AppState::clearManifest() {
    expectedHashes.clear();
    hasManifest = false;
    autoManifest = false;
}

void AppState::collectNestedEntries(HapAnalyzerCtx* ctx, NestedHap& nh) {
    int chainCount = hap_get_cert_chain_count(ctx);
    for (int ci = 0; ci < chainCount; ci++) {
        int cc = hap_get_cert_count(ci, ctx);
        for (int i = 0; i < cc; i++) {
            CertNode n;
            n.chainIdx = ci; n.certIdx = i;
            if (cc == 1) n.role = "single";
            else if (i == 0) n.role = "leaf";
            else if (i == cc - 1) n.role = "root";
            else n.role = "inter";
            n.subject  = getAndFree(hap_get_cert_subject(ci, i, ctx));
            n.issuer   = getAndFree(hap_get_cert_issuer(ci, i, ctx));
            n.sha256   = getAndFree(hap_get_cert_sha256(ci, i, ctx));
            n.keyInfo  = getAndFree(hap_get_cert_key_info(ci, i, ctx));
            n.validity = getAndFree(hap_get_cert_validity(ci, i, ctx));
            n.valid    = hap_get_cert_is_valid(ci, i, ctx) != 0;
            nh.certNodes.push_back(n);
        }
    }
    bool hasCS = hap_has_code_sign(ctx) != 0;
    std::set<std::string> signedLibBases;
    int libCount = hap_get_code_sign_lib_count(ctx);
    for (int i = 0; i < libCount; i++) {
        const char* lib = hap_get_code_sign_lib(i, ctx);
        std::string name(lib);
        free((char*)lib);
        if (name.find("binary code-signing") != std::string::npos) continue;
        auto slash = name.rfind('/');
        signedLibBases.insert(slash != std::string::npos ? name.substr(slash + 1) : name);
    }
    std::set<std::string> zipSoPaths, archDirs;
    int64_t fc = hap_get_file_count(ctx);
    for (int64_t i = 0; i < fc; i++) {
        FileEntry e;
        e.filename  = getAndFree(hap_get_filename(i, ctx));
        e.size      = hap_get_file_size_at(i, ctx);
        e.sha256    = getAndFree(hap_get_file_sha256(i, ctx));
        bool isSo = e.filename.size() > 3 && e.filename.substr(e.filename.size()-3) == ".so";
        e.protect = (isSo && hasCS) ? "CodeSign" : "PKCS7";
        if (isSo) {
            zipSoPaths.insert(e.filename);
            auto fn = e.filename.rfind('/');
            if (fn != std::string::npos) archDirs.insert(e.filename.substr(0, fn));
        }
        if (isSo && !isSystemLib(e.filename)) {
            auto fn = e.filename.rfind('/');
            std::string base = fn != std::string::npos ? e.filename.substr(fn+1) : e.filename;
            if (hasCS && !signedLibBases.count(base)) e.integrity = -1;
            else if (hasCS) e.integrity = 1;
        }
        nh.fileEntries.push_back(e);
    }
    for (const auto& base : signedLibBases) {
        bool foundAny = false, foundUnderArch = false;
        for (const auto& path : zipSoPaths) {
            auto fn = path.rfind('/');
            if (fn != std::string::npos && path.substr(fn+1) == base)
                foundAny = foundUnderArch = true;
            if (path == base) foundAny = true;
        }
        if (!foundUnderArch) continue;
        if (!foundAny) { nh.missingLibs.push_back(base); continue; }
        for (const auto& arch : archDirs) {
            std::string expected = arch + "/" + base;
            if (zipSoPaths.find(expected) == zipSoPaths.end())
                nh.missingLibs.push_back(expected);
        }
    }
}

void AppState::parseNestedHaps(const std::string& appPath) {
    for (auto& nh : nestedHaps) { if (nh.ctx) hap_analyzer_destroy(nh.ctx); }
    nestedHaps.clear();
    if (!nestedTempDir.empty()) {
        system(("rm -rf " + nestedTempDir).c_str());
    }
    nestedTempDir = "/tmp/hap_nested_" + std::to_string(getpid());
    mkdir(nestedTempDir.c_str(), 0755);
    char buf[4096];
    std::string cmd = "python3 -c \"import zipfile; [print(n) for n in zipfile.ZipFile('"
                    + appPath + "').namelist() if n.endswith('.hap') or n.endswith('.hsp')]\" 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return;
    while (fgets(buf, sizeof(buf), fp)) {
        std::string name(buf);
        name.erase(name.find_last_not_of("\n\r") + 1);
        if (name.empty()) continue;
        std::string outPath = nestedTempDir + "/" + name;
        std::string outDir = outPath.substr(0, outPath.rfind('/'));
        mkdir(outDir.c_str(), 0755);
        system(("python3 -c \"import zipfile,sys; z=zipfile.ZipFile('"
                + appPath + "'); sys.stdout.buffer.write(z.read('" + name + "'))\" > \""
                + outPath + "\" 2>/dev/null").c_str());
        HapAnalyzerCtx* ctx = hap_analyzer_create();
        if (hap_analyzer_load(ctx, outPath.c_str())) {
            NestedHap nh;
            nh.name = name;
            nh.ctx  = ctx;
            collectNestedEntries(ctx, nh);
            nestedHaps.push_back(std::move(nh));
        } else {
            hap_analyzer_destroy(ctx);
        }
    }
    pclose(fp);
}

void AppState::collectEntries() {
    fileEntries.clear();
    missingLibs.clear();
    bool hasCodeSign = hap_has_code_sign(ctx) != 0;

    std::set<std::string> signedLibBases;
    int libCount = hap_get_code_sign_lib_count(ctx);
    for (int i = 0; i < libCount; i++) {
        const char* lib = hap_get_code_sign_lib(i, ctx);
        std::string name(lib);
        free((char*)lib);
        if (name.find("binary code-signing") != std::string::npos) continue;
        auto slash = name.rfind('/');
        signedLibBases.insert(slash != std::string::npos ? name.substr(slash + 1) : name);
    }

    int64_t fileCount = hap_get_file_count(ctx);
    fileEntries.reserve(static_cast<size_t>(fileCount));
    std::set<std::string> zipSoPaths, archDirs;
    for (int64_t i = 0; i < fileCount; i++) {
        FileEntry e;
        e.filename  = getAndFree(hap_get_filename(i, ctx));
        e.size      = hap_get_file_size_at(i, ctx);
        e.sha256    = getAndFree(hap_get_file_sha256(i, ctx));
        bool isSo = e.filename.size() > 3 && e.filename.substr(e.filename.size() - 3) == ".so";
        e.protect = (isSo && hasCodeSign) ? "CodeSign" : "PKCS7";
        if (isSo) {
            zipSoPaths.insert(e.filename);
            auto fn = e.filename.rfind('/');
            if (fn != std::string::npos) archDirs.insert(e.filename.substr(0, fn));
        }
        if (isSo && !isSystemLib(e.filename)) {
            auto fn = e.filename.rfind('/');
            std::string base = fn != std::string::npos ? e.filename.substr(fn+1) : e.filename;
            if (hasCodeSign && !signedLibBases.count(base)) e.integrity = -1;
            else if (hasCodeSign) e.integrity = 1;
        }
        fileEntries.push_back(e);
    }
    for (const auto& base : signedLibBases) {
        bool foundAny = false, foundUnderArch = false;
        for (const auto& path : zipSoPaths) {
            auto fn = path.rfind('/');
            if (fn != std::string::npos && path.substr(fn+1) == base)
                foundAny = foundUnderArch = true;
            if (path == base) foundAny = true;
        }
        if (!foundUnderArch) continue;
        if (!foundAny) { missingLibs.push_back(base); continue; }
        for (const auto& arch : archDirs) {
            std::string expected = arch + "/" + base;
            if (zipSoPaths.find(expected) == zipSoPaths.end())
                missingLibs.push_back(expected);
        }
    }
}

void AppState::loadFile(const std::string& path) {
    if (ctx) hap_analyzer_destroy(ctx);
    ctx       = hap_analyzer_create();
    loadError = false;
    currentFile.clear();

    if (!hap_analyzer_load(ctx, path.c_str())) {
        statusMsg  = std::string(lang ? "解析失败: " : "Failed to parse: ") + path;
        fileLoaded = false;
        loadError  = true;
        certNodes.clear();
        fileEntries.clear();
        return;
    }
    currentFile = path;
    statusMsg   = std::string(lang ? "已加载: " : "Loaded: ") + path;
    fileLoaded  = true;
    loadError   = false;

    certNodes.clear();
    int chainCount = hap_get_cert_chain_count(ctx);
    for (int ci = 0; ci < chainCount; ci++) {
        int certCount = hap_get_cert_count(ci, ctx);
        for (int i = 0; i < certCount; i++) {
            CertNode n;
            n.chainIdx = ci; n.certIdx = i;
            if (certCount == 1) n.role = "single";
            else if (i == 0) n.role = "leaf";
            else if (i == certCount - 1) n.role = "root";
            else n.role = "inter";
            n.subject  = getAndFree(hap_get_cert_subject(ci, i, ctx));
            n.issuer   = getAndFree(hap_get_cert_issuer(ci, i, ctx));
            n.sha256   = getAndFree(hap_get_cert_sha256(ci, i, ctx));
            n.keyInfo  = getAndFree(hap_get_cert_key_info(ci, i, ctx));
            n.validity = getAndFree(hap_get_cert_validity(ci, i, ctx));
            n.valid    = hap_get_cert_is_valid(ci, i, ctx) != 0;
            certNodes.push_back(n);
        }
    }

    bool isApp = path.size() > 4 && path.substr(path.size() - 4) == ".app";
    if (isApp) parseNestedHaps(path);
    else nestedHaps.clear();

    collectEntries();
    applyManifestToEntries();
    if (!hasManifest && !isApp) saveCurrentAsManifest();
}

void AppState::reload() {
    if (!currentFile.empty()) loadFile(currentFile);
}
