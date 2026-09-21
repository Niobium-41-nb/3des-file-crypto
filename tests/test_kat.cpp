// ============================================================================
//  test_kat.cpp —— 扩展测试：文件级端到端、异常路径与性能测试
//  ---------------------------------------------------------------------------
//  与 src/selftest.cpp 的分工：
//    selftest.cpp  纯算法层（标准向量、填充、模式性质），随工具一起发布，可用
//                  `tdes selftest` 随时运行；
//    test_kat.cpp  系统层（真实文件读写、文件头校验、错误注入）与性能测试。
// ============================================================================
#include "tdes.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using tdes::Alg;
using tdes::FileResult;
using tdes::Mode;
using tdes::Params;

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& name, const std::string& detail = std::string()) {
    std::printf("[%s] %-38s %s\n", ok ? "PASS" : "FAIL", name.c_str(), detail.c_str());
    if (ok) ++g_pass; else ++g_fail;
}

bool readFile(const std::string& p, std::vector<std::uint8_t>& v) {
    std::ifstream f(fs::u8path(p), std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    const std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    v.assign((std::size_t)n, 0);
    if (n > 0) f.read(reinterpret_cast<char*>(v.data()), n);
    return true;
}

bool writeFile(const std::string& p, const std::vector<std::uint8_t>& v) {
    std::ofstream f(fs::u8path(p), std::ios::binary | std::ios::trunc);
    if (!f) return false;
    if (!v.empty()) f.write(reinterpret_cast<const char*>(v.data()), (std::streamsize)v.size());
    return (bool)f;
}

// ----------------------- 1. 文件级往返（含 --raw） -----------------------
void testFileRoundTrip(const fs::path& dir) {
    const Alg algs[3] = {Alg::DES, Alg::TDES2, Alg::TDES3};
    const Mode modes[2] = {Mode::ECB, Mode::CBC};
    const std::size_t sizes[] = {0, 1, 1000, 1048576};
    std::mt19937_64 rng(99991ULL);

    for (Alg a : algs) {
        for (Mode m : modes) {
            for (std::size_t n : sizes) {
                std::vector<std::uint8_t> plain(n);
                for (auto& b : plain) b = (std::uint8_t)(rng() & 0xFF);

                const std::string plainPath = (dir / "plain.bin").string();
                const std::string encPath = (dir / "cipher.bin").string();
                const std::string decPath = (dir / "back.bin").string();
                writeFile(plainPath, plain);

                std::vector<std::uint8_t> key;
                tdes::randomKey(a, key);
                Params p;
                p.alg = a;
                p.mode = m;

                std::string err;
                FileResult r1{}, r2{};
                Params used;
                bool ok = tdes::encryptFile(plainPath, encPath, key, p, r1, err) &&
                          tdes::decryptFile(encPath, decPath, key, p, used, r2, err);

                std::vector<std::uint8_t> back;
                ok = ok && readFile(decPath, back) && back == plain;
                // 密文长度 = 文件头 + 明文向上取整到 8 字节（PKCS#7 至少填 1 字节）
                const std::uint64_t expect = tdes::HEADER_SIZE + ((n / 8) + 1) * 8;
                ok = ok && (r1.outBytes == expect);

                const std::string tag = std::string(tdes::algName(a)) + "/" + tdes::modeName(m) +
                                        " n=" + std::to_string(n);
                check(ok, tag, ok ? "往返一致，密文 " + std::to_string(r1.outBytes) + " 字节" : err);

                // --raw：不写文件头的裸密文
                Params pr = p;
                pr.raw = true;
                const std::string rawPath = (dir / "raw.bin").string();
                const std::string rawBack = (dir / "rawback.bin").string();
                FileResult r3{}, r4{};
                std::string errR;
                bool okR = tdes::encryptFile(plainPath, rawPath, key, pr, r3, errR) &&
                           tdes::decryptFile(rawPath, rawBack, key, pr, used, r4, errR);
                std::vector<std::uint8_t> backR;
                okR = okR && readFile(rawBack, backR) && backR == plain;
                check(okR, "--raw " + tag, okR ? "往返一致" : errR);
            }
        }
    }
}

// -------------------------- 2. 错误注入（安全性质） --------------------------
void testErrorPaths(const fs::path& dir) {
    const std::string plainPath = (dir / "ep_plain.bin").string();
    const std::string encPath = (dir / "ep_cipher.bin").string();
    const std::string decPath = (dir / "ep_back.bin").string();

    std::vector<std::uint8_t> plain(1024);
    for (std::size_t i = 0; i < plain.size(); ++i) plain[i] = (std::uint8_t)(i * 7 + 3);
    writeFile(plainPath, plain);

    std::vector<std::uint8_t> key;
    tdes::randomKey(Alg::TDES3, key);
    Params p;
    p.alg = Alg::TDES3;
    p.mode = Mode::CBC;
    std::string err;
    FileResult r;
    tdes::encryptFile(plainPath, encPath, key, p, r, err);

    // (1) 错误密钥：改 1 个有效密钥位（每个字节最低位是奇偶校验位，会被 PC-1 丢弃）
    std::vector<std::uint8_t> wrong = key;
    wrong[5] ^= 0x80;
    Params used;
    FileResult r2;
    bool failed = !tdes::decryptFile(encPath, decPath, wrong, p, used, r2, err);
    check(failed, "错误密钥被拒绝", failed ? err : "竟然成功");

    // (2) 文件头魔数被破坏
    std::vector<std::uint8_t> cbuf;
    readFile(encPath, cbuf);
    std::vector<std::uint8_t> bad1 = cbuf;
    bad1[0] ^= 0xFF;
    writeFile(encPath, bad1);
    failed = !tdes::decryptFile(encPath, decPath, key, p, used, r2, err);
    check(failed, "文件头魔数校验生效", failed ? "已拒绝非法密文" : "未检出");

    // (3) 文件头中的原始长度被篡改
    std::vector<std::uint8_t> bad2 = cbuf;
    bad2[tdes::OFF_SIZE + 7] ^= 0x01;
    writeFile(encPath, bad2);
    failed = !tdes::decryptFile(encPath, decPath, key, p, used, r2, err);
    check(failed, "明文长度一致性校验生效", failed ? "已拒绝被篡改的密文" : "未检出");

    // (4) 密文被截断
    std::vector<std::uint8_t> bad3(cbuf.begin(), cbuf.end() - 3);
    writeFile(encPath, bad3);
    failed = !tdes::decryptFile(encPath, decPath, key, p, used, r2, err);
    check(failed, "密文截断被拒绝", failed ? "长度非 8 的倍数" : "未检出");

    // 复原，供后续使用
    writeFile(encPath, cbuf);
}

// ------------------------------ 3. 性能测试 ------------------------------
void benchmark() {
    const std::size_t MB = 1048576;
    std::vector<std::uint8_t> key;
    tdes::randomKey(Alg::TDES3, key);
    std::uint8_t iv[8];
    tdes::randomIV(iv);
    std::string err;

    const std::size_t total = 16 * MB;
    std::vector<std::uint8_t> base(total);
    std::mt19937_64 rng(7ULL);
    for (auto& b : base) b = (std::uint8_t)(rng() & 0xFF);

    const char* names[3] = {"DES  /CBC", "3DES2/CBC", "3DES3/CBC"};
    const Alg algs[3] = {Alg::DES, Alg::TDES2, Alg::TDES3};
    std::printf("\n---------- 性能测试（%zu MB 缓冲区，单位 MB/s） ----------\n", total / MB);
    for (int i = 0; i < 3; ++i) {
        std::vector<std::uint8_t> buf = base;
        auto t0 = std::chrono::steady_clock::now();
        tdes::transform(buf, key, algs[i], Mode::CBC, iv, true, err);
        auto t1 = std::chrono::steady_clock::now();
        tdes::transform(buf, key, algs[i], Mode::CBC, iv, false, err);
        auto t2 = std::chrono::steady_clock::now();
        const double encMs = (double)std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;
        const double decMs = (double)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() / 1000.0;
        const double mb = (double)total / MB;
        std::printf("%-10s 加密 %7.1f ms (%6.1f MB/s)   解密 %7.1f ms (%6.1f MB/s)\n",
                    names[i], encMs, mb / (encMs / 1000.0), decMs, mb / (decMs / 1000.0));
    }
}

}  // namespace

int main() {
    tdes::enableUtf8Console();
    std::printf("=========== 文件级端到端测试 ===========\n");

    const fs::path dir = fs::temp_directory_path() / "tdes_e2e";
    fs::remove_all(dir);
    fs::create_directories(dir);

    testFileRoundTrip(dir);
    std::printf("---------------------------------------\n");
    testErrorPaths(dir);
    std::printf("---------------------------------------\n");
    std::printf("用例总数 %d，通过 %d，失败 %d\n", g_pass + g_fail, g_pass, g_fail);

    benchmark();

    fs::remove_all(dir);
    return g_fail == 0 ? 0 : 1;
}
