// ============================================================================
//  main.cpp —— 3DES 文件加解密小软件的命令行界面
//  ---------------------------------------------------------------------------
//  子命令：
//    selftest  内置自检（标准向量 / 往返 / 模式性质）
//    genkey    生成随机密钥（可用 --out 直接导出为密钥文件）
//    keyexport 把已有密钥导出为密钥文件
//    keyinfo   查看密钥文件内容（算法 / 长度 / 密钥HEX）
//    subkeys   打印指定密钥的 16 轮子密钥（教学观察用）
//    block     对单个 64 位分组加解密（与标准向量对照用）
//    enc/dec   文件加密 / 解密
//  密钥既可以写十六进制（-k <HEX>），也可以放在文件里导入（-kf <文件> 或 -k @<文件>）；
//  加密 / 解密对话框与命令行共用同一套密钥文件格式（见 tdes::makeKeyText）。
//  Windows 下通过 CommandLineToArgvW 取得 UTF-16 命令行并转为 UTF-8，
//  再配合 std::filesystem 的 u8path，保证中文文件名也能正确处理。
// ============================================================================
#include "des.h"
#include "tdes.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>   // 注意：windows.h 必须在 shellapi.h 之前
#include <shellapi.h>
#endif

namespace {

namespace fs = std::filesystem;

std::string toLower(const std::string& s) {
    std::string r = s;
    for (char& c : r) {
        if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    }
    return r;
}

#ifdef _WIN32
// 取得 UTF-8 编码的命令行参数
std::vector<std::string> getArgs() {
    std::vector<std::string> out;
    int argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!wargv) return out;
    for (int i = 0; i < argc; ++i) {
        const std::wstring w(wargv[i]);
        if (w.empty()) {
            out.push_back(std::string());
            continue;
        }
        const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string u((std::size_t)n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &u[0], n, nullptr, nullptr);
        out.push_back(u);
    }
    LocalFree(wargv);
    return out;
}
#else
std::vector<std::string> getArgs(int argc, char** argv) { return std::vector<std::string>(argv, argv + argc); }
#endif

void printUsage() {
    std::printf(
        "三重 DES 文件加解密工具  (DES / 3DES-EDE，ECB/CBC + PKCS#7)\n"
        "\n"
        "用法:\n"
        "  tdes selftest                                    运行内置自检（标准向量 KAT）\n"
        "  tdes genkey [--alg des|3des2|3des3] [--out <密钥文件>]\n"
        "                                                   生成随机密钥（--out 同时导出到文件）\n"
        "  tdes keyexport <密钥文件> -k <HEX>               把已有密钥导出为密钥文件\n"
        "  tdes keyinfo <密钥文件>                          查看密钥文件（算法 / 长度 / 密钥HEX）\n"
        "  tdes subkeys -k <HEX|@密钥文件> [--alg ...]      打印 16 轮子密钥\n"
        "  tdes block [-e|-d] -k <HEX|@密钥文件> -p <16位HEX> [--alg ...]\n"
        "                                                   对单个 64 位分组加/解密\n"
        "  tdes enc <明文文件> <密文文件> (-k <HEX>|-kf <密钥文件>) [选项]\n"
        "  tdes dec <密文文件> <明文文件> (-k <HEX>|-kf <密钥文件>) [选项]\n"
        "\n"
        "选项:\n"
        "  -k <HEX>     密钥(十六进制)：DES=8 字节 / 3DES-2Key=16 字节 / 3DES-3Key=24 字节\n"
        "  -k @<文件>   等价于 -kf <文件>（从密钥文件导入密钥）\n"
        "  -kf <文件>   从密钥文件导入密钥（文件里若有 alg= 则以它为准）\n"
        "  --keyfile <文件>   -kf 的长写法\n"
        "  -o <文件>    导出密钥文件（用于 genkey）\n"
        "  --out <文件>  -o 的长写法\n"
        "  --alg <N>    算法: des | 3des2 | 3des3     (默认 3des3；用密钥文件时可省略)\n"
        "  -m <MODE>    工作模式: cbc | ecb           (默认 cbc；解密时自动读密文文件头)\n"
        "  -iv <HEX>    显式指定 8 字节 IV             (默认: 非 raw 模式随机生成并写入文件头；\n"
        "                                              --raw 模式必须自行约定，缺省全 0)\n"
        "  --raw        不写/不读 22 字节自描述文件头 (便于与其它实现互操作)\n"
        "  -f           允许覆盖已存在的输出文件\n"
        "  -q           安静模式，只输出错误\n"
        "  -h           显示本帮助\n"
        "\n"
        "示例:\n"
        "  tdes genkey --alg 3des3 --out 我的密钥.key      生成并导出密钥文件\n"
        "  tdes enc 实验报告.docx 实验报告.docx.3des -kf 我的密钥.key\n"
        "  tdes dec 实验报告.docx.3des 还原.docx     -k @我的密钥.key\n"
        "  tdes keyinfo 我的密钥.key                       查看密钥文件\n"
        "  tdes block -k 133457799BBCDFF1 -p 0123456789ABCDEF --alg des\n");
}

struct Options {
    std::string cmd;
    std::vector<std::string> pos;
    std::string keyHex;
    std::string keyFile;   // 密钥文件路径（-kf / --keyfile / -k @文件）
    std::string outFile;   // 导出密钥文件的路径（-o / --out）
    std::string ivHex;
    std::string blockHex;
    tdes::Alg alg = tdes::Alg::TDES3;
    tdes::Mode mode = tdes::Mode::CBC;
    bool algGiven = false;
    bool modeGiven = false;
    bool raw = false;
    bool force = false;
    bool decrypt = false;
    bool quiet = false;
};

bool parseAlg(const std::string& s, tdes::Alg& a) {
    const std::string t = toLower(s);
    if (t == "des") { a = tdes::Alg::DES; return true; }
    if (t == "3des2" || t == "tdes2" || t == "2key") { a = tdes::Alg::TDES2; return true; }
    if (t == "3des" || t == "3des3" || t == "tdes" || t == "3key") { a = tdes::Alg::TDES3; return true; }
    return false;
}

bool parseOptions(const std::vector<std::string>& a, Options& o, std::string& err) {
    for (std::size_t i = 1; i < a.size(); ++i) {
        const std::string& s = a[i];
        auto valueOf = [&](const char* name) -> const std::string* {
            if (i + 1 >= a.size()) {
                err = std::string("选项 ") + name + " 缺少参数";
                return nullptr;
            }
            return &a[++i];
        };
        if (s == "-h" || s == "--help") {
            o.cmd = "help";
        } else if (s == "-k") {
            const std::string* v = valueOf("-k");
            if (!v) return false;
            // -k @密钥文件 等价于 -kf 密钥文件
            if (!v->empty() && (*v)[0] == '@') o.keyFile = v->substr(1);
            else o.keyHex = *v;
        } else if (s == "-kf" || s == "--keyfile") {
            const std::string* v = valueOf("--keyfile");
            if (!v) return false;
            o.keyFile = *v;
        } else if (s == "-o" || s == "--out") {
            const std::string* v = valueOf("--out");
            if (!v) return false;
            o.outFile = *v;
        } else if (s == "-iv") {
            const std::string* v = valueOf("-iv");
            if (!v) return false;
            o.ivHex = *v;
        } else if (s == "-p") {
            const std::string* v = valueOf("-p");
            if (!v) return false;
            o.blockHex = *v;
        } else if (s == "-m" || s == "--mode") {
            const std::string* v = valueOf("-m");
            if (!v) return false;
            const std::string t = toLower(*v);
            if (t == "cbc") o.mode = tdes::Mode::CBC;
            else if (t == "ecb") o.mode = tdes::Mode::ECB;
            else { err = "未知工作模式: " + *v; return false; }
            o.modeGiven = true;
        } else if (s == "-a" || s == "--alg") {
            const std::string* v = valueOf("--alg");
            if (!v) return false;
            if (!parseAlg(*v, o.alg)) { err = "未知算法: " + *v; return false; }
            o.algGiven = true;
        } else if (s == "--raw") {
            o.raw = true;
        } else if (s == "-f" || s == "--force") {
            o.force = true;
        } else if (s == "-e" || s == "--encrypt") {
            o.decrypt = false;
        } else if (s == "-d" || s == "--decrypt") {
            o.decrypt = true;
        } else if (s == "-q" || s == "--quiet") {
            o.quiet = true;
        } else if (!s.empty() && s[0] == '-') {
            err = "未知选项: " + s;
            return false;
        } else if (o.cmd.empty()) {
            o.cmd = toLower(s);
        } else {
            o.pos.push_back(s);
        }
    }
    return true;
}

// 统一解析密钥来源：-k <HEX> / -k @<文件> / -kf <文件>
//   key —— 输出密钥字节；hex —— 输出密钥的十六进制形式（用于显示）
//   alg —— 入口为期望算法；使用密钥文件时以文件中的声明为准，与 --alg 冲突则报错
//   byLen —— true 时允许按十六进制长度推断算法（未显式给出 --alg 或解密时使用）
bool resolveKey(const Options& o, bool byLen, tdes::Alg& alg, std::vector<std::uint8_t>& key,
                std::string& hex, std::string& err) {
    if (!o.keyFile.empty()) {
        tdes::Alg fileAlg = tdes::Alg::TDES3;
        if (!tdes::readKeyFile(o.keyFile, key, fileAlg, err)) return false;
        if (o.algGiven && o.alg != fileAlg) {
            err = std::string("命令行 --alg ") + tdes::algName(o.alg) + " 与密钥文件中声明的 " +
                  tdes::algName(fileAlg) + " 不一致";
            return false;
        }
        alg = fileAlg;
        hex = tdes::toHex(key);
        return true;
    }
    if (o.keyHex.empty()) {
        err = "缺少密钥：请用 -k <密钥HEX>，或用 -kf <密钥文件> / -k @<密钥文件> 导入";
        return false;
    }
    if (byLen) {
        if (o.keyHex.size() == 16) alg = tdes::Alg::DES;
        else if (o.keyHex.size() == 32) alg = tdes::Alg::TDES2;
        else if (o.keyHex.size() == 48) alg = tdes::Alg::TDES3;
    }
    if (!tdes::parseKeyHex(o.keyHex, alg, key, err)) return false;
    hex = tdes::toHex(key);
    return true;
}

void printStats(bool encrypt, const tdes::Params& p, const tdes::FileResult& r,
                const std::string& inPath, const std::string& outPath, long long ms) {    const double mb = (double)r.inBytes / 1048576.0;
    const double speed = ms > 0 ? mb / ((double)ms / 1000.0) : 0.0;
    std::printf("操作      : %s\n", encrypt ? "加密" : "解密");
    std::printf("算法      : %s\n", tdes::algName(p.alg));
    std::printf("工作模式  : %s%s\n", tdes::modeName(p.mode), p.raw ? " (裸密文，无文件头)" : "");
    std::printf("IV        : %s\n", tdes::toHex(p.iv, 8).c_str());
    std::printf("输入文件  : %s\n", inPath.c_str());
    std::printf("输出文件  : %s\n", outPath.c_str());
    std::printf("输入大小  : %llu 字节\n", (unsigned long long)r.inBytes);
    std::printf("输出大小  : %llu 字节\n", (unsigned long long)r.outBytes);
    std::printf("分组数    : %llu\n", (unsigned long long)r.blocks);
    std::printf("耗时      : %lld ms   吞吐 %.2f MB/s\n", ms, speed);
}

int doSubkeys(const Options& o) {
    std::string err, hex;
    std::vector<std::uint8_t> key;
    tdes::Alg alg = o.alg;
    if (!resolveKey(o, !o.algGiven, alg, key, hex, err)) {
        std::fprintf(stderr, "错误: %s\n", err.c_str());
        return 2;
    }
    des::SubKeys sk;
    des::keySchedule(key.data(), sk);
    std::printf("算法: %s   密钥: %s\n", tdes::algName(alg), hex.c_str());
    std::printf("注：3DES 只展示 K1 的 16 个子密钥，K2/K3 同理。\n");
    for (int i = 0; i < 16; ++i) {
        std::printf("K%-2d = %012llX\n", i + 1, (unsigned long long)sk.k[i]);
    }
    return 0;
}

int doBlock(const Options& o) {
    std::string err, hex;
    std::vector<std::uint8_t> key;
    tdes::Alg alg = o.alg;
    if (!resolveKey(o, !o.algGiven, alg, key, hex, err)) {
        std::fprintf(stderr, "错误: %s\n", err.c_str());
        return 2;
    }
    const std::string inHex = !o.blockHex.empty() ? o.blockHex : (o.pos.empty() ? std::string() : o.pos[0]);
    std::uint8_t in[8], out[8];
    if (!tdes::parseHexBytes(inHex, in, 8)) {
        std::fprintf(stderr, "错误: 分组数据必须是 16 个十六进制字符\n");
        return 2;
    }
    const std::vector<des::SubKeys> ks = tdes::buildSubKeys(key, alg);
    if (o.decrypt) {
        tdes::decryptBlock(in, out, ks, alg);
    } else {
        tdes::encryptBlock(in, out, ks, alg);
    }
    if (o.quiet) {  // 机器可读输出：只打印结果十六进制，便于脚本比对
        std::printf("%s\n", tdes::toHex(out, 8).c_str());
        return 0;
    }
    std::printf("算法     : %s\n", tdes::algName(alg));
    std::printf("密钥     : %s\n", hex.c_str());
    std::printf("%s   : %s\n", o.decrypt ? "密文分组" : "明文分组", inHex.c_str());
    std::printf("%s   : %s\n", o.decrypt ? "还原明文" : "输出密文", tdes::toHex(out, 8).c_str());
    return 0;
}

// 把已有密钥导出为密钥文件
int doKeyExport(const Options& o) {
    std::string err, hex;
    std::vector<std::uint8_t> key;
    tdes::Alg alg = o.alg;
    if (!resolveKey(o, !o.algGiven, alg, key, hex, err)) {
        std::fprintf(stderr, "错误: %s\n", err.c_str());
        return 2;
    }
    if (!tdes::writeKeyFile(o.pos[0], alg, key, err)) {
        std::fprintf(stderr, "错误: %s\n", err.c_str());
        return 4;
    }
    std::printf("算法      : %s\n", tdes::algName(alg));
    std::printf("密钥HEX   : %s\n", hex.c_str());
    std::printf("密钥文件  : %s\n", o.pos[0].c_str());
    return 0;
}

// 查看 / 校验密钥文件
int doKeyInfo(const Options& o) {
    std::vector<std::uint8_t> key;
    tdes::Alg alg = tdes::Alg::TDES3;
    std::string err;
    if (!tdes::readKeyFile(o.pos[0], key, alg, err)) {
        std::fprintf(stderr, "错误: %s\n", err.c_str());
        return 2;
    }
    std::printf("密钥文件  : %s\n", o.pos[0].c_str());
    std::printf("算法      : %s\n", tdes::algName(alg));
    std::printf("密钥长度  : %zu 字节\n", key.size());
    std::printf("密钥HEX   : %s\n", tdes::toHex(key).c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    tdes::enableUtf8Console();
#ifdef _WIN32
    (void)argc;
    (void)argv;
    const std::vector<std::string> args = getArgs();
#else
    const std::vector<std::string> args = getArgs(argc, argv);
#endif

    Options o;
    std::string err;
    if (args.size() < 2) {
        printUsage();
        return 1;
    }
    if (!parseOptions(args, o, err)) {
        std::fprintf(stderr, "参数错误: %s\n", err.c_str());
        return 2;
    }

    // ------------------------------ selftest ------------------------------
    if (o.cmd == "selftest" || o.cmd == "test") {
        return tdes::selfTest(true) == 0 ? 0 : 1;
    }
    if (o.cmd == "help" || o.cmd.empty()) {
        printUsage();
        return 0;
    }

    // ------------------------------- genkey -------------------------------
    if (o.cmd == "genkey") {
        std::vector<std::uint8_t> key;
        tdes::randomKey(o.alg, key);
        std::printf("算法    : %s\n", tdes::algName(o.alg));
        std::printf("密钥HEX : %s\n", tdes::toHex(key).c_str());
        std::printf("密钥长度: %zu 字节\n", key.size());
        if (!o.outFile.empty()) {  // 直接导出为密钥文件，便于保管与传递
            if (!tdes::writeKeyFile(o.outFile, o.alg, key, err)) {
                std::fprintf(stderr, "错误: %s\n", err.c_str());
                return 4;
            }
            std::printf("密钥文件: %s\n", o.outFile.c_str());
        }
        return 0;
    }

    // ------------------------------ keyexport -----------------------------
    if (o.cmd == "keyexport" || o.cmd == "keyout") {
        if (o.pos.size() != 1) {
            std::fprintf(stderr, "错误: 用法 tdes keyexport <密钥文件> -k <HEX> [--alg ...]\n");
            return 2;
        }
        return doKeyExport(o);
    }

    // ------------------------------- keyinfo ------------------------------
    if (o.cmd == "keyinfo" || o.cmd == "keyfile" || o.cmd == "keyimport") {
        if (o.pos.size() != 1) {
            std::fprintf(stderr, "错误: 用法 tdes keyinfo <密钥文件>\n");
            return 2;
        }
        return doKeyInfo(o);
    }

    // ------------------------------ subkeys -------------------------------
    if (o.cmd == "subkeys" || o.cmd == "keys") {
        return doSubkeys(o);
    }

    // ------------------------------- block --------------------------------
    if (o.cmd == "block") {
        return doBlock(o);
    }

    // ------------------------------- enc/dec ------------------------------
    const bool isEnc = (o.cmd == "enc" || o.cmd == "encrypt" || o.cmd == "e");
    const bool isDec = (o.cmd == "dec" || o.cmd == "decrypt" || o.cmd == "d");
    if (!isEnc && !isDec) {
        std::fprintf(stderr, "未知子命令: %s\n", o.cmd.c_str());
        printUsage();
        return 2;
    }
    if (o.pos.size() != 2) {
        if (o.pos.size() > 2) {
            std::fprintf(stderr, "错误: 参数过多（%zu 个），enc/dec 只需要 <输入文件> 和 <输出文件>；\n"
                                 "      密钥请用 -k <HEX> 或 -kf <密钥文件>（注意 -k 不能省略），多余的参数：%s\n",
                         o.pos.size(), o.pos[2].c_str());
        } else {
            std::fprintf(stderr, "错误: 需要给出 <输入文件> 和 <输出文件> 两个路径\n");
        }
        return 2;
    }

    // 密钥来源：-k <HEX> 或 -kf <密钥文件> / -k @<密钥文件>
    // 解密时算法从密文文件头读取，这里只按密钥长度做长度上的预检，故允许“按长度推断”
    tdes::Alg keyAlg = o.alg;
    std::vector<std::uint8_t> key;
    std::string keyHex;
    if (!resolveKey(o, isDec && !o.raw, keyAlg, key, keyHex, err)) {
        std::fprintf(stderr, "错误: %s\n", err.c_str());
        return 2;
    }

    const std::string inPath = o.pos[0];
    const std::string outPath = o.pos[1];
    std::error_code ec;
    if (!o.force && fs::exists(fs::u8path(outPath), ec)) {
        std::fprintf(stderr, "错误: 输出文件已存在（如需覆盖请加 -f）: %s\n", outPath.c_str());
        return 3;
    }

    tdes::Params p;
    p.alg = o.alg;
    p.mode = o.mode;
    p.raw = o.raw;
    if (!o.ivHex.empty()) {
        if (!tdes::parseHexBytes(o.ivHex, p.iv, tdes::IV_SIZE)) {
            std::fprintf(stderr, "错误: IV 必须是 16 个十六进制字符\n");
            return 2;
        }
        p.ivGiven = true;
    }

    tdes::FileResult res;
    const auto t0 = std::chrono::steady_clock::now();
    bool ok = false;
    tdes::Params used = p;
    if (isEnc) {
        ok = tdes::encryptFile(inPath, outPath, key, p, res, err);
        used = p;  // 加密时 IV 可能由函数随机生成，需取回才能正确显示
    } else {
        ok = tdes::decryptFile(inPath, outPath, key, p, used, res, err);
    }
    const auto t1 = std::chrono::steady_clock::now();
    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (!ok) {
        std::fprintf(stderr, "失败: %s\n", err.c_str());
        return 4;
    }
    if (!o.quiet) {
        if (isEnc && o.raw && o.mode == tdes::Mode::CBC && o.ivHex.empty()) {
            std::printf("提示: --raw 模式下没有文件头可以存放 IV，本次使用全 0 的 IV；\n"
                        "      如需其它值请用 -iv 指定，并告知解密方。\n");
        }
        if (isDec && !o.raw && o.modeGiven && o.mode != used.mode) {
            std::printf("提示: 命令行指定的模式 %s 与密文文件头记录的 %s 不一致，已按文件头处理。\n",
                        tdes::modeName(o.mode), tdes::modeName(used.mode));
        }
        if (!o.keyFile.empty()) std::printf("密钥来源  : %s（算法取自密钥文件）\n", o.keyFile.c_str());
        printStats(isEnc, used, res, inPath, outPath, ms);
    }
    return 0;
}
