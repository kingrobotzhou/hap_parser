#include "hap_parser.h"

#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file.hap|file.app> [options]\n";
        std::cerr << "\nOptions:\n";
        std::cerr << "  -a, --all        Show all sections\n";
        std::cerr << "  -l, --layout     Show file layout diagram\n";
        std::cerr << "  -p, --profile    Show provision profile details\n";
        std::cerr << "  -c, --codesign   Show code signing info\n";
        std::cerr << "  -H, --hashes     Show file SHA256 hashes\n";
        std::cerr << "  -i, --integrity  Show integrity verification table\n";
        std::cerr << "  --expect <file>  Compare hashes against JSON manifest\n";
        std::cerr << "\nDefault: certificate verification graph only\n";
        return 1;
    }

    HapParser parser;
    HapParser::DisplayOptions opts;
    std::string filePath;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-a" || arg == "--all") {
            opts.showAll = true;
        } else if (arg == "-l" || arg == "--layout") {
            opts.showLayout = true;
        } else if (arg == "-p" || arg == "--profile") {
            opts.showProfile = true;
        } else if (arg == "-c" || arg == "--codesign") {
            opts.showCodeSign = true;
        } else if (arg == "-H" || arg == "--hashes") {
            opts.showHashes = true;
        } else if (arg == "-i" || arg == "--integrity") {
            opts.showIntegrity = true;
        } else if (arg == "--expect" && i + 1 < argc) {
            opts.expectedManifest = argv[++i];
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        } else {
            filePath = arg;
        }
    }

    if (filePath.empty()) {
        std::cerr << "No input file specified.\n";
        return 1;
    }

    const auto summary = parser.parseFile(filePath);
    if (!summary) {
        std::cerr << "Failed to read file: " << filePath << "\n";
        return 1;
    }

    parser.printSummary(*summary, opts);
    return 0;
}
