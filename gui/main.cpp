#include "HapAnalyzer.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <unistd.h>
extern "C" void macos_register_open_handler(void (*callback)(const char*));
extern "C" const char* macos_open_file_dialog(void);
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#ifdef __APPLE__
static std::string resolveFont(const char* name) {
    char path[PATH_MAX];
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) != 0) return name;
    std::string dir = path;
    dir = dir.substr(0, dir.rfind('/'));
    std::string tries[] = {
        dir + "/../Resources/" + name,
        dir + "/" + name,
    };
    for (auto& p : tries) {
        if (access(p.c_str(), R_OK) == 0) return p;
    }
    return name;
}
#endif

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <unordered_map>

static int g_lang = 0;

static const char* _(const char* en, const char* zh) { return g_lang == 1 ? zh : en; }

// ── Global state ────────────────────────────────────────────────────────────

static HapAnalyzerCtx* g_ctx         = nullptr;
static std::string     g_currentFile;
static std::string     g_statusMsg;
static bool            g_fileLoaded  = false;
static bool            g_loadError   = false;

// ── Helpers ─────────────────────────────────────────────────────────────────

static std::string getAndFree(const char* s) {
    std::string r = s ? s : "";
    if (s) free((char*)s);
    return r;
}

static std::string formatSize(int64_t bytes) {
    if (bytes >= 1024 * 1024) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1f MB", bytes / (1024.0 * 1024.0));
        return buf;
    }
    if (bytes >= 1024) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1024.0);
        return buf;
    }
    return std::to_string(bytes) + " B";
}

static std::string extractCN(const std::string& subject) {
    auto pos = subject.find("commonName=");
    if (pos == std::string::npos) return subject;
    std::string cn = subject.substr(pos + 11);
    auto end = cn.find(',');
    if (end != std::string::npos) cn = cn.substr(0, end);
    return cn;
}

struct CertNode {
    std::string  role;
    std::string  subject;
    std::string  issuer;
    std::string  serial;
    std::string  keyInfo;
    std::string  validity;
    std::string  sha256;
    bool         valid;
    int          chainIdx;
    int          certIdx;
};

struct FileEntry {
    std::string protect;
    std::string filename;
    int64_t     size;
    std::string sha256;
    int         integrity;   // -1=injected, 0=normal, 1=signed
    int         manifestCmp; // -1=missing, 0=no-manifest, 1=match, 2=mismatch, 3=added
    std::string expectedHash;
};

static std::vector<CertNode>  g_certNodes;
static std::vector<FileEntry> g_fileEntries;
static std::vector<std::string> g_missingLibs;
static std::map<std::string, std::string> g_expectedHashes;
static bool g_hasManifest = false;
static bool g_autoManifest = false;

static bool isSystemLib(const std::string& path) {
    if (path.size() < 4 || path.substr(path.size() - 3) != ".so") return false;
    return path.find("libs/") != 0;
}

struct NestedHap {
    std::string        name;
    HapAnalyzerCtx*    ctx = nullptr;
    std::vector<CertNode>  certNodes;
    std::vector<FileEntry> fileEntries;
    std::vector<std::string> missingLibs;
};
static std::vector<NestedHap> g_nestedHaps;
static std::string g_nestedTempDir;

static void loadManifest(const std::string& path) {
    g_expectedHashes.clear();
    g_hasManifest = false;
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
        if (!fn.empty() && hh.size() >= 64) g_expectedHashes[fn] = hh;
    }
    g_hasManifest = !g_expectedHashes.empty();
}

static void applyManifestToEntries() {
    if (!g_hasManifest) return;
    for (auto& e : g_fileEntries) {
        if (isSystemLib(e.filename)) continue;
        auto it = g_expectedHashes.find(e.filename);
        if (it != g_expectedHashes.end()) {
            e.expectedHash = it->second;
            std::string stripped = e.sha256;
            stripped.erase(std::remove(stripped.begin(), stripped.end(), ':'), stripped.end());
            e.manifestCmp = (stripped == it->second) ? 1 : 2;
        } else {
            e.manifestCmp = 3;
        }
    }
    for (auto& nh : g_nestedHaps) {
        for (auto& e : nh.fileEntries) {
            if (isSystemLib(e.filename)) continue;
            auto it = g_expectedHashes.find(e.filename);
            if (it != g_expectedHashes.end()) {
                e.expectedHash = it->second;
                std::string stripped = e.sha256;
                stripped.erase(std::remove(stripped.begin(), stripped.end(), ':'), stripped.end());
                e.manifestCmp = (stripped == it->second) ? 1 : 2;
            } else {
                e.manifestCmp = 3;
            }
        }
    }
}

static void saveCurrentAsManifest() {
    g_expectedHashes.clear();
    for (auto& e : g_fileEntries) {
        if (isSystemLib(e.filename)) continue;
        std::string stripped = e.sha256;
        stripped.erase(std::remove(stripped.begin(), stripped.end(), ':'), stripped.end());
        g_expectedHashes[e.filename] = stripped;
    }
    g_hasManifest = true;
    g_autoManifest = true;
    applyManifestToEntries();
    std::ofstream of(std::string(getenv("HOME")) + "/.hap_analyzer_ref.json");
    of << "{\"files\":{";
    bool first = true;
    for (auto& kv : g_expectedHashes) {
        if (!first) of << ",";
        of << "\n  \"" << kv.first << "\":\"" << kv.second << "\"";
        first = false;
    }
    of << "\n}}";
}

static void collectNestedEntries(HapAnalyzerCtx* ctx, NestedHap& nh) {
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
        if (slash != std::string::npos)
            signedLibBases.insert(name.substr(slash + 1));
        else
            signedLibBases.insert(name);
    }

    std::set<std::string> zipSoPaths;
    std::set<std::string> archDirs;
    int64_t fc = hap_get_file_count(ctx);
    for (int64_t i = 0; i < fc; i++) {
        FileEntry e;
        e.filename  = getAndFree(hap_get_filename(i, ctx));
        e.size      = hap_get_file_size_at(i, ctx);
        e.sha256    = getAndFree(hap_get_file_sha256(i, ctx));
        bool isSo   = e.filename.size() > 3 && e.filename.substr(e.filename.size()-3) == ".so";
        e.protect   = (isSo && hasCS) ? "CodeSign" : "PKCS7";
        e.integrity = 0;
        if (isSo) {
            zipSoPaths.insert(e.filename);
            auto fn = e.filename.rfind('/');
            if (fn != std::string::npos) archDirs.insert(e.filename.substr(0, fn));
        }
        if (isSo && !isSystemLib(e.filename)) {
            auto fn = e.filename.rfind('/');
            std::string base = (fn != std::string::npos) ? e.filename.substr(fn+1) : e.filename;
            bool inList = hasCS && signedLibBases.count(base);
            if (hasCS && !inList) e.integrity = -1;
            else if (inList) e.integrity = 1;
        }
        nh.fileEntries.push_back(e);
    }
    for (const auto& base : signedLibBases) {
        bool foundAny = false;
        bool foundUnderArch = false;
        for (const auto& path : zipSoPaths) {
            auto fn = path.rfind('/');
            if (fn != std::string::npos && path.substr(fn+1) == base) {
                foundAny = true;
                foundUnderArch = true;
            }
            if (path == base) foundAny = true;
        }
        if (!foundUnderArch) continue;
        if (!foundAny) {
            nh.missingLibs.push_back(base);
            continue;
        }
        for (const auto& arch : archDirs) {
            std::string expected = arch + "/" + base;
            if (zipSoPaths.find(expected) == zipSoPaths.end()) {
                nh.missingLibs.push_back(expected);
            }
        }
    }
}

static void parseNestedHaps(const std::string& appPath) {
    for (auto& nh : g_nestedHaps) { if (nh.ctx) hap_analyzer_destroy(nh.ctx); }
    g_nestedHaps.clear();
    if (!g_nestedTempDir.empty()) {
        std::string cmd = "rm -rf " + g_nestedTempDir;
        system(cmd.c_str());
    }
    g_nestedTempDir = "/tmp/hap_nested_" + std::to_string(getpid());
    mkdir(g_nestedTempDir.c_str(), 0755);

    char buf[4096];
    std::string cmd = "python3 -c \"import zipfile; [print(n) for n in zipfile.ZipFile('"
                    + appPath + "').namelist() if n.endswith('.hap') or n.endswith('.hsp')]\" 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return;
    while (fgets(buf, sizeof(buf), fp)) {
        std::string name(buf);
        name.erase(name.find_last_not_of("\n\r") + 1);
        if (name.empty()) continue;

        std::string outPath = g_nestedTempDir + "/" + name;
        std::string outDir = outPath.substr(0, outPath.rfind('/'));
        mkdir(outDir.c_str(), 0755);
        std::string extCmd = "python3 -c \"import zipfile,sys; z=zipfile.ZipFile('"
                           + appPath + "'); sys.stdout.buffer.write(z.read('" + name + "'))\" > \""
                           + outPath + "\" 2>/dev/null";
        system(extCmd.c_str());

        HapAnalyzerCtx* ctx = hap_analyzer_create();
        if (hap_analyzer_load(ctx, outPath.c_str())) {
            NestedHap nh;
            nh.name = name;
            nh.ctx  = ctx;
            collectNestedEntries(ctx, nh);
            g_nestedHaps.push_back(std::move(nh));
        } else {
            hap_analyzer_destroy(ctx);
        }
    }
    pclose(fp);
}

// ── Load file ───────────────────────────────────────────────────────────────

static void loadFile(const std::string& path) {
    if (g_ctx) hap_analyzer_destroy(g_ctx);
    g_ctx        = hap_analyzer_create();
    g_loadError  = false;
    g_currentFile.clear();

    if (!hap_analyzer_load(g_ctx, path.c_str())) {
        g_statusMsg  = std::string(_("Failed to parse: ", "解析失败: ")) + path;
        g_fileLoaded = false;
        g_loadError  = true;
        g_certNodes.clear();
        g_fileEntries.clear();
        return;
    }

    g_currentFile = path;
    g_statusMsg   = std::string(_("Loaded: ", "已加载: ")) + path;
    g_fileLoaded  = true;
    g_loadError   = false;

    g_certNodes.clear();
    int chainCount = hap_get_cert_chain_count(g_ctx);
    for (int ci = 0; ci < chainCount; ci++) {
        int certCount = hap_get_cert_count(ci, g_ctx);
        for (int i = 0; i < certCount; i++) {
            CertNode n;
            n.chainIdx = ci; n.certIdx = i;
            if (certCount == 1) n.role = "single";
            else if (i == 0) n.role = "leaf";
            else if (i == certCount - 1) n.role = "root";
            else n.role = "inter";
            n.subject  = getAndFree(hap_get_cert_subject(ci, i, g_ctx));
            n.issuer   = getAndFree(hap_get_cert_issuer(ci, i, g_ctx));
            n.sha256   = getAndFree(hap_get_cert_sha256(ci, i, g_ctx));
            n.keyInfo  = getAndFree(hap_get_cert_key_info(ci, i, g_ctx));
            n.validity = getAndFree(hap_get_cert_validity(ci, i, g_ctx));
            n.valid    = hap_get_cert_is_valid(ci, i, g_ctx) != 0;
            g_certNodes.push_back(n);
        }
    }

    bool isApp = path.size() > 4 && path.substr(path.size() - 4) == ".app";
    if (isApp) parseNestedHaps(path);
    else g_nestedHaps.clear();

    // ── Collect file entries ───────────────────────────────────────────
    g_fileEntries.clear();
    g_missingLibs.clear();
    bool hasCodeSign = hap_has_code_sign(g_ctx) != 0;

    std::set<std::string> signedLibBases;
    int libCount = hap_get_code_sign_lib_count(g_ctx);
    for (int i = 0; i < libCount; i++) {
        const char* lib = hap_get_code_sign_lib(i, g_ctx);
        std::string name(lib);
        free((char*)lib);
        if (name.find("binary code-signing") != std::string::npos) continue;
        auto slash = name.rfind('/');
        if (slash != std::string::npos)
            signedLibBases.insert(name.substr(slash + 1));
        else
            signedLibBases.insert(name);
    }

    int64_t fileCount = hap_get_file_count(g_ctx);
    g_fileEntries.reserve(static_cast<size_t>(fileCount));
    std::set<std::string> zipSoPaths;
    std::set<std::string> archDirs;
    for (int64_t i = 0; i < fileCount; i++) {
        FileEntry e;
        e.filename  = getAndFree(hap_get_filename(i, g_ctx));
        e.size      = hap_get_file_size_at(i, g_ctx);
        e.sha256    = getAndFree(hap_get_file_sha256(i, g_ctx));
        bool isSo   = e.filename.size() > 3 && e.filename.substr(e.filename.size() - 3) == ".so";
        e.protect   = (isSo && hasCodeSign) ? "CodeSign" : "PKCS7";
        e.integrity = 0;
        if (isSo) {
            zipSoPaths.insert(e.filename);
            auto fn = e.filename.rfind('/');
            if (fn != std::string::npos) archDirs.insert(e.filename.substr(0, fn));
        }
        if (isSo && !isSystemLib(e.filename)) {
            auto fn = e.filename.rfind('/');
            std::string base = (fn != std::string::npos) ? e.filename.substr(fn+1) : e.filename;
            bool inList = hasCodeSign && signedLibBases.count(base);
            if (hasCodeSign && !inList) e.integrity = -1;
            else if (inList) e.integrity = 1;
        }
        g_fileEntries.push_back(e);
    }

    for (const auto& base : signedLibBases) {
        bool foundAny = false;
        bool foundUnderArch = false;
        std::string foundPath;
        for (const auto& path : zipSoPaths) {
            auto fn = path.rfind('/');
            if (fn != std::string::npos && path.substr(fn+1) == base) {
                foundAny = true;
                foundUnderArch = true;
                if (foundPath.empty()) foundPath = path;
            }
            if (path == base) foundAny = true;
        }
        if (!foundUnderArch) continue;
        if (!foundAny) {
            g_missingLibs.push_back(base);
            continue;
        }
        for (const auto& arch : archDirs) {
            std::string expected = arch + "/" + base;
            if (zipSoPaths.find(expected) == zipSoPaths.end())
                g_missingLibs.push_back(expected);
        }
    }

    applyManifestToEntries();
    if (!g_hasManifest && !isApp) saveCurrentAsManifest();
}

// ── Drop zone ───────────────────────────────────────────────────────────────

static void renderDropZone() {
    ImVec2 winSize = ImGui::GetContentRegionAvail();
    float  zoneH   = 64.0f;

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.94f, 0.95f, 0.97f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border,  ImVec4(0.60f, 0.70f, 0.90f, 1.0f));

    ImGui::BeginChild("DropZone", ImVec2(winSize.x, zoneH), true,
                      ImGuiWindowFlags_NoScrollbar);

    float textY = (zoneH - ImGui::GetTextLineHeight()) * 0.5f;

    ImGui::SetCursorPos(ImVec2(12, textY - 4));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.85f, 0.85f, 0.87f, 1.0f));
    if (ImGui::Button(_("EN", "中文"), ImVec2(56, 28))) {
        g_lang = g_lang ? 0 : 1;
    }
    ImGui::PopStyleColor();

    const char* label = g_fileLoaded
        ? g_currentFile.c_str()
        : _("Drop .hap / .app file here", "拖放 .hap / .app 文件至此");

    ImVec2 textSize = ImGui::CalcTextSize(label);
    float  textX    = (winSize.x - textSize.x) * 0.5f;
    ImGui::SetCursorPos(ImVec2(textX, textY));
    ImGui::TextUnformatted(label);

    ImGui::EndChild();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();

    ImGui::Spacing();
}

// ── Summary tab ─────────────────────────────────────────────────────────────

static void renderSummaryTab() {
    if (!g_fileLoaded) {
        ImGui::TextDisabled("%s", _("No file loaded. Drop a .hap file or use File > Open.",
                                     "未加载文件。拖放 .hap 文件或使用 文件 > 打开。"));
        return;
    }

    // ── Verdict banner ──────────────────────────────────────────────────
    const char* verdict = hap_get_verdict(g_ctx);
    const char* summary = hap_get_verdict_summary(g_ctx);

    ImVec4 color;
    if (std::strcmp(verdict, "PASS") == 0)
        color = ImVec4(0.20f, 0.78f, 0.35f, 1.0f);
    else if (std::strstr(verdict, "warning") || std::strstr(verdict, "PASS with"))
        color = ImVec4(1.00f, 0.58f, 0.00f, 1.0f);
    else
        color = ImVec4(1.00f, 0.23f, 0.19f, 1.0f);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(color.x * 0.15f, color.y * 0.15f, color.z * 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border,  color);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);

    ImGui::BeginChild("VerdictBanner", ImVec2(0, 80), true,
                      ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPosY(12.0f);
    ImGui::SetCursorPosX(16.0f);

    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::SetWindowFontScale(1.8f);
    ImGui::Text("%s: %s", _("VERDICT", "判定"), verdict);
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();

    ImGui::SetCursorPosX(16.0f);
    ImGui::TextUnformatted(summary);
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);
    ImGui::Spacing();

    free((char*)verdict);
    free((char*)summary);

    // ── File info ───────────────────────────────────────────────────────
    if (ImGui::CollapsingHeader(_("File Info", "文件信息"), ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent(12.0f);
        ImGui::Text("%s %s", _("File Size:", "文件大小:"), formatSize(hap_get_file_size(g_ctx)).c_str());
        ImGui::Text("%s %d %s (version %d)",
                    _("Sign Blocks:", "签名块:"), hap_get_subblock_count(g_ctx),
                    _("blocks", "个"), hap_get_chain_version(g_ctx));
        ImGui::Text("%s %lld %s", _("ZIP Entries:", "ZIP条目:"), hap_get_file_count(g_ctx),
                    _("files", "个文件"));
        ImGui::Unindent(12.0f);
    }

    // ── Profile ─────────────────────────────────────────────────────────
    const char* bundle  = hap_get_profile_field("bundle", g_ctx);
    const char* devId   = hap_get_profile_field("devid", g_ctx);
    const char* appId   = hap_get_profile_field("appid", g_ctx);
    const char* type    = hap_get_profile_field("type", g_ctx);
    const char* apl     = hap_get_profile_field("apl", g_ctx);
    const char* issuer  = hap_get_profile_field("issuer", g_ctx);
    const char* certFp  = hap_get_profile_field("certfp", g_ctx);
    const char* valid   = hap_get_profile_field("validity", g_ctx);

    bool hasProfile = std::strlen(bundle) > 0 || std::strlen(type) > 0;
    if (hasProfile && ImGui::CollapsingHeader(_("Provision Profile", "配置描述文件"), ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent(12.0f);
        if (std::strlen(bundle))  ImGui::Text("Bundle:      %s", bundle);
        if (std::strlen(devId))   ImGui::Text("Developer:   %s", devId);
        if (std::strlen(appId))   ImGui::Text("App ID:      %s", appId);
        if (std::strlen(type))    ImGui::Text("Type:        %s", type);
        if (std::strlen(apl))     ImGui::Text("APL:         %s", apl);
        if (std::strlen(issuer))  ImGui::Text("Issuer:      %s", issuer);
        if (std::strlen(valid))   ImGui::Text("Validity:    %s", valid);
        if (std::strlen(certFp))  ImGui::Text("Dev Cert FP: %s", certFp);
        ImGui::Unindent(12.0f);
    }
    free((char*)bundle); free((char*)devId);  free((char*)appId);
    free((char*)type);   free((char*)apl);    free((char*)issuer);
    free((char*)certFp); free((char*)valid);

    // ── Code signing ────────────────────────────────────────────────────
    if (ImGui::CollapsingHeader(_("Code Signing", "代码签名"))) {
        ImGui::Indent(12.0f);
        ImGui::Text("%s %s", _("Code Signing:", "代码签名:"),
                    hap_has_code_sign(g_ctx) ? _("Present", "已启用") : _("Not detected", "未检测到"));
        int libCount = hap_get_code_sign_lib_count(g_ctx);
        for (int i = 0; i < libCount; i++) {
            const char* lib = hap_get_code_sign_lib(i, g_ctx);
            ImGui::Text("  - %s", lib);
            free((char*)lib);
        }
        ImGui::Unindent(12.0f);
    }

    // ── Certificate chains summary ──────────────────────────────────────
    int chainCount = hap_get_cert_chain_count(g_ctx);
    if (chainCount > 0 && ImGui::CollapsingHeader(_("Certificate Chains", "证书链"), ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent(12.0f);
        for (int ci = 0; ci < chainCount; ci++) {
            int certCount = hap_get_cert_count(ci, g_ctx);
            int contentOk = hap_get_chain_content_ok(ci, g_ctx);
            ImGui::Text(_("Chain %d: %d certificates", "链 %d: %d 个证书"), ci + 1, certCount);
            if (contentOk >= 0) {
                ImGui::SameLine();
                if (contentOk == 1)
                    ImGui::TextColored(ImVec4(0.20f, 0.78f, 0.35f, 1.0f), "  %s",
                                       _("content OK", "内容完整"));
                else
                    ImGui::TextColored(ImVec4(1.00f, 0.23f, 0.19f, 1.0f), "  %s",
                                       _("content TAMPERED", "内容被篡改"));
            }
            int validCerts = 0;
            for (int i = 0; i < certCount; i++) {
                if (hap_get_cert_is_valid(ci, i, g_ctx)) validCerts++;
            }
            ImGui::SameLine();
            if (validCerts == certCount)
                ImGui::TextColored(ImVec4(0.20f, 0.78f, 0.35f, 1.0f), "  (%s)",
                                   _("all valid", "全部有效"));
            else
                ImGui::TextColored(ImVec4(1.00f, 0.58f, 0.00f, 1.0f), "  (%d/%d %s)", validCerts, certCount,
                                   _("valid", "有效"));
        }
        ImGui::Unindent(12.0f);
    }

    if (!g_nestedHaps.empty() && ImGui::CollapsingHeader(
            _("Inner HAP Packages", "内部 HAP 包"), ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Indent(12.0f);
        for (size_t ni = 0; ni < g_nestedHaps.size(); ni++) {
            auto& nh = g_nestedHaps[ni];
            ImGui::Text("%s", nh.name.c_str());
            ImGui::SameLine();
            const char* nhv = hap_get_verdict(nh.ctx);
            const char* nhs = hap_get_verdict_summary(nh.ctx);
            ImVec4 c = ImVec4(1,1,1,1);
            if (strstr(nhv, "FAIL")) c = ImVec4(1.0f, 0.23f, 0.19f, 1.0f);
            else if (strstr(nhv, "warning")) c = ImVec4(1.0f, 0.58f, 0.0f, 1.0f);
            else c = ImVec4(0.20f, 0.78f, 0.35f, 1.0f);
            ImGui::TextColored(c, "  %s", nhv);
            ImGui::Text("  %zu files, %zu cert chains", nh.fileEntries.size(), nh.certNodes.size());
            free((char*)nhv); free((char*)nhs);
        }
        ImGui::Unindent(12.0f);
    }
}

// ── Certificates tab ────────────────────────────────────────────────────────

static void renderCertificatesTab() {
    if (!g_fileLoaded) {
        ImGui::TextDisabled("%s", _("No file loaded.", "未加载文件。"));
        return;
    }

    if (g_certNodes.empty()) {
        ImGui::TextDisabled("%s", _("No certificates found in this file.", "此文件中未找到证书。"));
        return;
    }

    // Group nodes by chain
    int prevChain = -1;
    for (size_t i = 0; i < g_certNodes.size(); i++) {
        const auto& n = g_certNodes[i];

        // Chain header
        if (n.chainIdx != prevChain) {
            if (prevChain >= 0) ImGui::TreePop();
            prevChain = n.chainIdx;

            int chainCertCount = hap_get_cert_count(n.chainIdx, g_ctx);
            int contentOk = hap_get_chain_content_ok(n.chainIdx, g_ctx);
            char label[128];
            const char* contentStatus = "";
            if (contentOk == 1)       contentStatus = _("  [content OK]", "  [内容完整]");
            else if (contentOk == 0)  contentStatus = _("  [TAMPERED]", "  [已篡改]");
            std::snprintf(label, sizeof(label), _("Chain %d  (%d certs)%s", "链 %d  (%d 证书)%s"),
                          n.chainIdx + 1, chainCertCount, contentStatus);
            ImGui::SetNextItemOpen(true, ImGuiCond_Once);
            if (!ImGui::TreeNode(label)) {
                // Skip all certs in this chain
                while (i + 1 < g_certNodes.size() && g_certNodes[i + 1].chainIdx == n.chainIdx)
                    i++;
                prevChain = -1;  // reset for next chain
                continue;
            }
        }

        // Cert node
        ImGui::BulletText("%s", extractCN(n.subject).c_str());
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 60.0f);
        ImGui::TextColored(n.valid ? ImVec4(0.20f,0.78f,0.35f,1.0f)
                                   : ImVec4(1.00f,0.23f,0.19f,1.0f),
                           " %s", n.valid ? _("valid", "有效") : _("invalid", "无效"));
        ImGui::Indent(20.0f);
        ImGui::TextDisabled("%s  |  %s", n.keyInfo.c_str(), n.validity.c_str());
        ImGui::TextDisabled("SHA256:  %s", n.sha256.c_str());
        ImGui::TextDisabled("Issuer:  %s", n.issuer.c_str());
        ImGui::TextDisabled("Subject: %s", n.subject.c_str());
        ImGui::Unindent(20.0f);
    }
    if (prevChain >= 0) ImGui::TreePop();

    for (size_t ni = 0; ni < g_nestedHaps.size(); ni++) {
        auto& nh = g_nestedHaps[ni];
        if (nh.certNodes.empty()) continue;
        ImGui::Spacing();
        if (ImGui::TreeNode(nh.name.c_str())) {
            int prev = -1;
            for (size_t i = 0; i < nh.certNodes.size(); i++) {
                const auto& n = nh.certNodes[i];
                if (n.chainIdx != prev) {
                    if (prev >= 0) ImGui::TreePop();
                    prev = n.chainIdx;
                    char label[128];
                    std::snprintf(label, sizeof(label), "Chain %d (%zu certs)", n.chainIdx + 1,
                                  std::count_if(nh.certNodes.begin(), nh.certNodes.end(),
                                                [&](auto& x){ return x.chainIdx == n.chainIdx; }));
                    ImGui::SetNextItemOpen(true, ImGuiCond_Once);
                    if (!ImGui::TreeNode(label)) {
                        while (i+1 < nh.certNodes.size() && nh.certNodes[i+1].chainIdx == n.chainIdx) i++;
                        prev = -1; continue;
                    }
                }
                ImGuiTreeNodeFlags f = ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
                ImGui::BulletText("%s", extractCN(n.subject).c_str());
                ImGui::SameLine(ImGui::GetContentRegionAvail().x - 60.0f);
                ImGui::TextColored(n.valid ? ImVec4(0.20f,0.78f,0.35f,1.0f)
                                           : ImVec4(1.00f,0.23f,0.19f,1.0f),
                                   " %s", n.valid ? _("valid", "有效") : _("invalid", "无效"));
                ImGui::Indent(20.0f);
                ImGui::TextDisabled("%s  |  %s", n.keyInfo.c_str(), n.validity.c_str());
                ImGui::TextDisabled("SHA256:  %s", n.sha256.c_str());
                ImGui::TextDisabled("Issuer:  %s", n.issuer.c_str());
                ImGui::TextDisabled("Subject: %s", n.subject.c_str());
                ImGui::Unindent(20.0f);
            }
            if (prev >= 0) ImGui::TreePop();
            ImGui::TreePop();
        }
    }
}

// ── Structure tab ───────────────────────────────────────────────────────────

static void renderFileTable(const char* id, const std::vector<FileEntry>& entries,
                             const std::vector<int>& indices, float height) {
    int ncols = g_hasManifest ? 6 : 5;
    if (!ImGui::BeginTable(id, ncols, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                           ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable,
                           ImVec2(0, height))) return;
    ImGui::TableSetupColumn(_("Status", "状态"), ImGuiTableColumnFlags_WidthFixed, 60.0f);
    if (g_hasManifest)
        ImGui::TableSetupColumn(_("Match", "匹配"), ImGuiTableColumnFlags_WidthFixed, 50.0f);
    ImGui::TableSetupColumn(_("Protect", "保护"), ImGuiTableColumnFlags_WidthFixed, 70.0f);
    ImGui::TableSetupColumn(_("File", "文件"), ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn(_("Size", "大小"), ImGuiTableColumnFlags_WidthFixed, 80.0f);
    ImGui::TableSetupColumn("SHA256", ImGuiTableColumnFlags_WidthFixed, 470.0f);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(indices.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
            const auto& e = entries[indices[row]];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (e.integrity == -1)
                ImGui::TextColored(ImVec4(1.0f,0.23f,0.19f,1.0f), "INJECT");
            else if (e.integrity == 1)
                ImGui::TextColored(ImVec4(0.2f,0.78f,0.35f,1.0f), "Signed");
            else ImGui::TextUnformatted("-");

            int col = 1;
            if (g_hasManifest) {
                ImGui::TableSetColumnIndex(col++);
                switch (e.manifestCmp) {
                case 1: break;
                case 2:
                    ImGui::TextColored(ImVec4(1.0f,0.23f,0.19f,1.0f), "MISMATCH");
                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip(); ImGui::Text("Exp: %s", e.expectedHash.c_str()); ImGui::EndTooltip();
                    }
                    break;
                case 3: ImGui::TextColored(ImVec4(1.0f,0.58f,0.0f,1.0f), "ADDED"); break;
                default: break;
                }
            }
            ImGui::TableSetColumnIndex(col++);
            if (e.protect == "CodeSign")
                ImGui::TextColored(ImVec4(0.0f,0.48f,1.0f,1.0f), "%s", e.protect.c_str());
            else ImGui::TextUnformatted(e.protect.c_str());
            ImGui::TableSetColumnIndex(col++);
            ImGui::TextUnformatted(e.filename.c_str());
            ImGui::TableSetColumnIndex(col++);
            ImGui::TextUnformatted(formatSize(e.size).c_str());
            ImGui::TableSetColumnIndex(col++);
            ImGui::TextUnformatted(e.sha256.c_str());
        }
    }
    ImGui::EndTable();
}

static void renderStructureSection(const std::vector<FileEntry>& entries,
                                    const std::vector<std::string>* missingLibs,
                                    const char* prefix) {
    if (entries.empty()) return;

    std::vector<int> mismatched, injected, added, missing, ok;
    for (size_t i = 0; i < entries.size(); i++) {
        int c = entries[i].manifestCmp;
        if (c == 2) mismatched.push_back(static_cast<int>(i));
        else if (entries[i].integrity == -1) injected.push_back(static_cast<int>(i));
        else if (c == 3) added.push_back(static_cast<int>(i));
        else ok.push_back(static_cast<int>(i));
    }
    for (auto& lib : (missingLibs ? *missingLibs : std::vector<std::string>()))
        missing.push_back(-1);

    if (missingLibs && !missingLibs->empty()) {
        ImGui::TextColored(ImVec4(1.0f,0.58f,0.0f,1.0f),
                          _("Missing from code-sign: %zu lib(s)", "代码签名缺失: %zu 个库"),
                          missingLibs->size());
        for (auto& lib : *missingLibs) ImGui::BulletText("%s", lib.c_str());
    }

    ImGui::Text("%zu %s", entries.size(), _("files", "个文件"));
    if (g_hasManifest) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.0f,0.48f,1.0f,1.0f),
            g_autoManifest ? "  [auto-ref]" : "  [manifest]");
    }
    ImGui::SameLine();
    if (!mismatched.empty())
        ImGui::TextColored(ImVec4(1.0f,0.23f,0.19f,1.0f), "  %zu mismatch", mismatched.size());
    if (!injected.empty())
        ImGui::TextColored(ImVec4(1.0f,0.23f,0.19f,1.0f), "  %zu injected", injected.size());
    if (!added.empty())
        ImGui::TextColored(ImVec4(1.0f,0.58f,0.0f,1.0f), "  %zu added", added.size());
    if (missingLibs && !missingLibs->empty())
        ImGui::TextColored(ImVec4(1.0f,0.23f,0.19f,1.0f), "  %zu missing", missingLibs->size());
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.2f,0.78f,0.35f,1.0f), "  %zu ok", ok.size());

    auto showGroup = [&](const char* labelEn, const char* labelZh,
                          const std::vector<int>& indices,
                          ImVec4 hdrColor, bool defaultOpen) {
        if (indices.empty()) return;
        char hdr[128];
        std::snprintf(hdr, sizeof(hdr), "%s (%zu)", _(labelEn, labelZh), indices.size());
        ImGui::PushStyleColor(ImGuiCol_Header, hdrColor);
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered,
            ImVec4(hdrColor.x, hdrColor.y, hdrColor.z, hdrColor.w + 0.2f));
        if (ImGui::CollapsingHeader(hdr, defaultOpen ? ImGuiTreeNodeFlags_DefaultOpen : 0)) {
            char tid[64]; std::snprintf(tid, sizeof(tid), "##%s_%s", prefix, labelEn);
            renderFileTable(tid, entries, indices, ImGui::GetTextLineHeight() * 10);
        }
        ImGui::PopStyleColor(2);
    };

    showGroup("Mismatched", "哈希不匹配", mismatched,
              ImVec4(1.0f,0.15f,0.15f,0.3f), true);
    showGroup("Injected", "注入文件", injected,
              ImVec4(1.0f,0.15f,0.15f,0.3f), true);
    showGroup("Added", "新增文件", added,
              ImVec4(1.0f,0.55f,0.0f,0.3f), true);
    showGroup("OK", "匹配", ok,
              ImVec4(0.15f,0.7f,0.15f,0.2f), false);

    if (missingLibs && !missingLibs->empty()) {
        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(1.0f,0.15f,0.15f,0.3f));
        if (ImGui::CollapsingHeader(_("Missing from ZIP", "ZIP中缺失"),
                                     ImGuiTreeNodeFlags_DefaultOpen)) {
            for (auto& lib : *missingLibs)
                ImGui::BulletText("%s", lib.c_str());
        }
        ImGui::PopStyleColor();
    }
}

static void renderStructureTab() {
    if (!g_fileLoaded) {
        ImGui::TextDisabled("%s", _("No file loaded.", "未加载文件。"));
        return;
    }
    if (g_fileEntries.empty()) {
        ImGui::TextDisabled("%s", _("No files found in ZIP.", "ZIP 中未找到文件。"));
        return;
    }

    ImGui::Separator();
    renderStructureSection(g_fileEntries, &g_missingLibs, "main");

    for (size_t ni = 0; ni < g_nestedHaps.size(); ni++) {
        auto& nh = g_nestedHaps[ni];
        if (nh.fileEntries.empty()) continue;
        ImGui::Spacing();
        char label[256];
        std::snprintf(label, sizeof(label), "%s  (%zu files)  ###nest%d",
                      nh.name.c_str(), nh.fileEntries.size(), (int)ni);
        if (ImGui::CollapsingHeader(label, ImGuiTreeNodeFlags_DefaultOpen)) {
            char pfx[32]; std::snprintf(pfx, sizeof(pfx), "nest%d", (int)ni);
            renderStructureSection(nh.fileEntries, &nh.missingLibs, pfx);
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

static void applyMacOSStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]                  = ImVec4(0.07f, 0.07f, 0.08f, 1.00f);
    c[ImGuiCol_TextDisabled]          = ImVec4(0.55f, 0.55f, 0.57f, 1.00f);
    c[ImGuiCol_WindowBg]              = ImVec4(0.95f, 0.95f, 0.96f, 1.00f);
    c[ImGuiCol_ChildBg]               = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    c[ImGuiCol_PopupBg]               = ImVec4(1.00f, 1.00f, 1.00f, 0.98f);
    c[ImGuiCol_Border]                = ImVec4(0.80f, 0.80f, 0.82f, 1.00f);
    c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    c[ImGuiCol_FrameBg]               = ImVec4(0.93f, 0.93f, 0.94f, 1.00f);
    c[ImGuiCol_FrameBgHovered]        = ImVec4(0.88f, 0.88f, 0.89f, 1.00f);
    c[ImGuiCol_FrameBgActive]         = ImVec4(0.84f, 0.84f, 0.86f, 1.00f);
    c[ImGuiCol_TitleBg]               = ImVec4(0.91f, 0.91f, 0.92f, 1.00f);
    c[ImGuiCol_TitleBgActive]         = ImVec4(0.87f, 0.87f, 0.88f, 1.00f);
    c[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.91f, 0.91f, 0.92f, 1.00f);
    c[ImGuiCol_MenuBarBg]             = ImVec4(0.91f, 0.91f, 0.92f, 1.00f);
    c[ImGuiCol_ScrollbarBg]           = ImVec4(0.97f, 0.97f, 0.97f, 1.00f);
    c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.78f, 0.78f, 0.80f, 1.00f);
    c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.65f, 0.65f, 0.67f, 1.00f);
    c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.55f, 0.55f, 0.57f, 1.00f);
    c[ImGuiCol_CheckMark]             = ImVec4(0.00f, 0.48f, 1.00f, 1.00f);
    c[ImGuiCol_SliderGrab]            = ImVec4(0.00f, 0.48f, 1.00f, 1.00f);
    c[ImGuiCol_SliderGrabActive]      = ImVec4(0.00f, 0.38f, 0.80f, 1.00f);
    c[ImGuiCol_Button]                = ImVec4(0.00f, 0.48f, 1.00f, 1.00f);
    c[ImGuiCol_ButtonHovered]         = ImVec4(0.00f, 0.40f, 0.85f, 1.00f);
    c[ImGuiCol_ButtonActive]          = ImVec4(0.00f, 0.33f, 0.70f, 1.00f);
    c[ImGuiCol_Header]                = ImVec4(0.00f, 0.48f, 1.00f, 0.31f);
    c[ImGuiCol_HeaderHovered]         = ImVec4(0.00f, 0.48f, 1.00f, 0.20f);
    c[ImGuiCol_HeaderActive]          = ImVec4(0.00f, 0.48f, 1.00f, 0.40f);
    c[ImGuiCol_Separator]             = ImVec4(0.80f, 0.80f, 0.82f, 1.00f);
    c[ImGuiCol_SeparatorHovered]      = ImVec4(0.00f, 0.48f, 1.00f, 0.60f);
    c[ImGuiCol_SeparatorActive]       = ImVec4(0.00f, 0.48f, 1.00f, 0.80f);
    c[ImGuiCol_ResizeGrip]            = ImVec4(0.80f, 0.80f, 0.82f, 1.00f);
    c[ImGuiCol_ResizeGripHovered]     = ImVec4(0.65f, 0.65f, 0.67f, 1.00f);
    c[ImGuiCol_ResizeGripActive]      = ImVec4(0.00f, 0.48f, 1.00f, 0.80f);
    c[ImGuiCol_Tab]                   = ImVec4(0.89f, 0.89f, 0.90f, 1.00f);
    c[ImGuiCol_TabHovered]            = ImVec4(0.82f, 0.82f, 0.84f, 1.00f);
    c[ImGuiCol_TabActive]             = ImVec4(0.00f, 0.48f, 1.00f, 1.00f);
    c[ImGuiCol_TabUnfocused]          = ImVec4(0.89f, 0.89f, 0.90f, 1.00f);
    c[ImGuiCol_TabUnfocusedActive]    = ImVec4(0.82f, 0.82f, 0.84f, 1.00f);
    c[ImGuiCol_TableHeaderBg]         = ImVec4(0.93f, 0.93f, 0.94f, 1.00f);
    c[ImGuiCol_TableBorderStrong]     = ImVec4(0.73f, 0.73f, 0.75f, 1.00f);
    c[ImGuiCol_TableBorderLight]      = ImVec4(0.87f, 0.87f, 0.89f, 1.00f);
    c[ImGuiCol_TableRowBg]            = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    c[ImGuiCol_TableRowBgAlt]         = ImVec4(0.96f, 0.96f, 0.97f, 1.00f);
    c[ImGuiCol_TextSelectedBg]        = ImVec4(0.00f, 0.48f, 1.00f, 0.35f);
    c[ImGuiCol_NavHighlight]          = ImVec4(0.00f, 0.48f, 1.00f, 0.30f);
    s.WindowRounding    = 8.0f;
    s.FrameRounding     = 6.0f;
    s.GrabRounding      = 4.0f;
    s.TabRounding       = 6.0f;
    s.ScrollbarRounding = 6.0f;
    s.WindowPadding     = ImVec2(12, 12);
    s.FramePadding      = ImVec2(8, 5);
    s.ItemSpacing       = ImVec2(10, 6);
    s.ItemInnerSpacing  = ImVec2(8, 4);
    s.IndentSpacing     = 20.0f;
    s.ScrollbarSize     = 8.0f;
    s.GrabMinSize       = 10.0f;
}

int main(int argc, char** argv) {
    std::string cliFile;
    if (argc >= 2) cliFile = argv[1];

    if (!glfwInit()) return 1;

#ifdef __APPLE__
    macos_register_open_handler([](const char* path) { loadFile(path); });
#endif

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
    glfwWindowHint(GLFW_COCOA_RETINA_FRAMEBUFFER, GLFW_TRUE);

    GLFWwindow* window = glfwCreateWindow(1100, 750,
        _("HAP Security Analyzer", "HAP 安全分析器"), nullptr, nullptr);
    if (!window) { glfwTerminate(); return 1; }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // ── File drop callback ─────────────────────────────────────────────
    glfwSetDropCallback(window, [](GLFWwindow*, int count, const char** paths) {
        if (count > 0) loadFile(paths[0]);
    });

    // ── Init ImGui ──────────────────────────────────────────────────────
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.IniFilename  = nullptr;

    io.FontDefault = io.Fonts->AddFontFromFileTTF(
        resolveFont("Hiragino.ttc").c_str(), 15.0f, nullptr,
        io.Fonts->GetGlyphRangesChineseFull());

    applyMacOSStyle();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    std::string refPath = std::string(getenv("HOME")) + "/.hap_analyzer_ref.json";
    loadManifest(refPath);
    g_autoManifest = g_hasManifest;

    if (!cliFile.empty()) loadFile(cliFile);

    // ── Main loop ────────────────────────────────────────────────────────
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplGlfw_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui::NewFrame();

        // Full-window dockspace
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

        ImGuiWindowFlags winFlags = ImGuiWindowFlags_NoTitleBar |
                                     ImGuiWindowFlags_NoCollapse |
                                     ImGuiWindowFlags_NoResize |
                                     ImGuiWindowFlags_NoMove |
                                     ImGuiWindowFlags_NoBringToFrontOnFocus |
                                     ImGuiWindowFlags_NoNavFocus |
                                     ImGuiWindowFlags_MenuBar |
                                     ImGuiWindowFlags_NoDocking;

        ImGui::Begin("MainWindow", nullptr, winFlags);
        ImGui::PopStyleVar(2);

        // ── Menu bar ────────────────────────────────────────────────────
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu(_("File", "文件"))) {
                if (ImGui::MenuItem(_("Open...", "打开..."))) { }
                if (ImGui::MenuItem(_("Load Manifest...", "加载清单..."))) {
#ifdef __APPLE__
                    const char* mp = macos_open_file_dialog();
                    if (mp) { loadManifest(mp); applyManifestToEntries(); free((void*)mp); }
#endif
                }
                if (g_fileLoaded && ImGui::MenuItem(_("Set as Reference", "设为基准"))) {
                    saveCurrentAsManifest();
                }
                if (g_hasManifest && ImGui::MenuItem(_("Clear Reference", "清除基准"))) {
                    g_expectedHashes.clear();
                    g_hasManifest = false;
                    g_autoManifest = false;
                }
                ImGui::Separator();
                if (ImGui::MenuItem(_("Language / 语言", "语言 / Language"))) {
                    g_lang = g_lang ? 0 : 1;
                }
                ImGui::Separator();
                if (ImGui::MenuItem(_("Quit", "退出"), "Cmd+Q")) {
                    glfwSetWindowShouldClose(window, GLFW_TRUE);
                }
                ImGui::EndMenu();
            }
            if (g_fileLoaded && ImGui::BeginMenu(_("View", "查看"))) {
                if (ImGui::MenuItem(_("Reload", "重新加载"), "Cmd+R")) {
                    loadFile(g_currentFile);
                }
                ImGui::EndMenu();
            }
            ImGui::EndMenuBar();
        }

        // ── Render drop zone ────────────────────────────────────────────
        renderDropZone();

        // ── Status bar ──────────────────────────────────────────────────
        if (!g_statusMsg.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text,
                g_loadError ? ImVec4(1.00f, 0.23f, 0.19f, 1.0f)
                            : ImVec4(0.20f, 0.78f, 0.35f, 1.0f));
            ImGui::TextWrapped("%s", g_statusMsg.c_str());
            ImGui::PopStyleColor();
            ImGui::Separator();
        }

        // ── Tabs ────────────────────────────────────────────────────────
        if (ImGui::BeginTabBar("MainTabs")) {
            if (ImGui::BeginTabItem(_("Summary", "摘要"))) {
                renderSummaryTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("Certificates", "证书"))) {
                renderCertificatesTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem(_("Structure", "文件结构"))) {
                renderStructureTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::End();

        // ── Render ──────────────────────────────────────────────────────
        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.95f, 0.95f, 0.96f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // ── Cleanup ──────────────────────────────────────────────────────────
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    if (g_ctx) hap_analyzer_destroy(g_ctx);

    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
