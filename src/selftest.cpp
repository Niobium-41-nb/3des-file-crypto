// ============================================================================
//  selftest.cpp —— 内置自检：标准向量(KAT)、填充规则、工作模式与置换一致性
//  ---------------------------------------------------------------------------
//  设计说明：
//    * KAT（Known Answer Test）期望值由 .NET 的 DES / TripleDES
//      （System.Security.Cryptography，ECB、无填充）独立计算得到，
//      生成脚本见 tools/dotnet_vectors.ps1，因此是“第三方参照值”。
//    * 除 KAT 外，还验证：IP 与 IP^-1 互逆、28 位循环左移的周期性、
//      PKCS#7 填充边界、三种算法 x 两种模式的往返一致性、
//      ECB 的模式弱点与 CBC 的 IV 效应、错误密钥必然被检出。
// ============================================================================
#include "tdes.h"

#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace tdes {

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& name, const std::string& detail) {
    std::printf("[%s] %-40s %s\n", ok ? "PASS" : "FAIL", name.c_str(), detail.c_str());
    if (ok) ++g_pass; else ++g_fail;
}

// ---------------------------- 标准测试向量 ----------------------------
struct Kat {
    Alg alg;
    const char* key;
    const char* pt;
    const char* ct;
};

const Kat KATS[] = {
    {Alg::DES,   "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"},
    {Alg::DES,   "0123456789ABCDEF", "0000000000000000", "D5D44FF720683D0D"},
    {Alg::DES,   "FEDCBA9876543210", "0123456789ABCDEF", "ED39D950FA74BCC4"},
    {Alg::TDES2, "0123456789ABCDEF23456789ABCDEF01", "0123456789ABCDEF", "A6BB373E196B375E"},
    {Alg::TDES3, "0123456789ABCDEF23456789ABCDEF013456789ABCDEF012", "5468652071756663", "7CB155E0DA5878C5"},
    {Alg::TDES3, "0123456789ABCDEF23456789ABCDEF013456789ABCDEF012", "0000000000000000", "412973AC537DE730"},
};

std::string shortKey(const std::string& k) {
    return k.size() <= 16 ? k : k.substr(0, 8) + ".." + k.substr(k.size() - 8);
}

void testKat() {
    for (const Kat& v : KATS) {
        std::string err;
        std::vector<std::uint8_t> key;
        std::uint8_t pt[8], ct[8], out[8];
        parseKeyHex(v.key, v.alg, key, err);
        parseHexBytes(v.pt, pt, 8);
        parseHexBytes(v.ct, ct, 8);
        const std::vector<des::SubKeys> ks = buildSubKeys(key, v.alg);
        const std::string tag = std::string(algName(v.alg)) + " K=" + shortKey(v.key);

        encryptBlock(pt, out, ks, v.alg);
        const std::string enc = toHex(out, 8);
        check(enc == v.ct, "KAT 加密 " + tag, "C=" + enc + " (期望 " + v.ct + ")");

        decryptBlock(ct, out, ks, v.alg);
        const std::string dec = toHex(out, 8);
        check(dec == v.pt, "KAT 解密 " + tag, "P=" + dec + " (期望 " + v.pt + ")");
    }
}

// K1 = K2 = K3 时，3DES-EDE 退化为单 DES
void testDegenerate() {
    std::string err;
    std::vector<std::uint8_t> k1;
    parseKeyHex("133457799BBCDFF1", Alg::DES, k1, err);
    std::vector<std::uint8_t> k3 = k1;
    k3.insert(k3.end(), k1.begin(), k1.end());
    k3.insert(k3.end(), k1.begin(), k1.end());

    std::uint8_t pt[8], cDes[8], c3Des[8];
    parseHexBytes("0123456789ABCDEF", pt, 8);
    const std::vector<des::SubKeys> ksDes = buildSubKeys(k1, Alg::DES);
    const std::vector<des::SubKeys> ks3 = buildSubKeys(k3, Alg::TDES3);
    encryptBlock(pt, cDes, ksDes, Alg::DES);
    encryptBlock(pt, c3Des, ks3, Alg::TDES3);
    check(std::memcmp(cDes, c3Des, 8) == 0, "3DES(K,K,K) == DES",
          "DES=" + toHex(cDes, 8) + " 3DES=" + toHex(c3Des, 8));
}

// 整体置换链路的可逆性（IP/IP^-1 与轮函数的组合）与 28 位循环左移周期性
void testPermutation() {
    std::mt19937_64 rng(20260921ULL);
    bool ipOk = true, rotOk = true;
    std::string err;
    std::vector<std::uint8_t> key;
    parseKeyHex("133457799BBCDFF1", Alg::DES, key, err);
    const std::vector<des::SubKeys> ks = buildSubKeys(key, Alg::DES);
    for (int i = 0; i < 512; ++i) {
        std::uint8_t in[8], mid[8], back[8];
        const des::u64 v = rng();
        des::u64ToBytes(v, in);
        encryptBlock(in, mid, ks, Alg::DES);
        decryptBlock(mid, back, ks, Alg::DES);
        if (std::memcmp(in, back, 8) != 0) { ipOk = false; break; }
    }
    check(ipOk, "随机分组 E/D 可逆 (512 组)", "D(E(P)) == P");

    // 循环左移只在 28 位半区内进行，故比较时应先把原值也截到 28 位
    des::u64 v = rng();
    const des::u64 orig = v & 0x0FFFFFFFULL;
    for (int i = 0; i < 28; ++i) v = des::rotateLeft28(v, 1);
    rotOk = (v == orig);
    check(rotOk, "28 位半区循环左移周期性", "左移 28 次回到原值");
}

// PKCS#7 填充边界
void testPadding() {
    const std::size_t sizes[] = {0, 1, 7, 8, 9, 15, 16, 17, 100};
    bool ok = true;
    std::string bad;
    for (std::size_t n : sizes) {
        std::vector<std::uint8_t> data(n, 0x5A);
        pkcs7Pad(data, 8);
        if (data.size() % 8 != 0) { ok = false; bad = "长度未对齐"; break; }
        if (data.size() <= n) { ok = false; bad = "未增加填充"; break; }
        if (!pkcs7Unpad(data, 8) || data.size() != n) { ok = false; bad = "去填充失败"; break; }
        for (std::size_t i = 0; i < n; ++i) {
            if (data[i] != 0x5A) { ok = false; bad = "明文被破坏"; break; }
        }
        if (!ok) break;
    }
    // 非法填充必须被拒绝
    std::vector<std::uint8_t> badPad = {1, 2, 3, 4, 5, 6, 7, 0x09};
    const bool rejected = !pkcs7Unpad(badPad, 8);
    check(ok, "PKCS#7 填充/去填充 (8 种长度)", bad.empty() ? "全部一致" : bad);
    check(rejected, "非法填充值被拒绝", "0x09 > 8 时返回失败");
}

// 三种算法 x 两种模式 x 多种长度的往返一致性
void testRoundTrip() {
    const Alg algs[3] = {Alg::DES, Alg::TDES2, Alg::TDES3};
    const Mode modes[2] = {Mode::ECB, Mode::CBC};
    const std::size_t sizes[] = {1, 7, 8, 9, 16, 17, 1000, 100000};
    std::mt19937_64 rng(12345ULL);
    bool ok = true;
    std::string bad;
    int cases = 0;

    for (Alg a : algs) {
        for (Mode m : modes) {
            for (std::size_t n : sizes) {
                std::vector<std::uint8_t> key;
                randomKey(a, key);
                std::vector<std::uint8_t> plain(n);
                for (auto& b : plain) b = (std::uint8_t)(rng() & 0xFF);

                std::uint8_t iv[8];
                randomIV(iv);

                std::string err;
                std::vector<std::uint8_t> buf = plain;
                if (!transform(buf, key, a, m, iv, true, err) ||
                    !transform(buf, key, a, m, iv, false, err)) {
                    ok = false; bad = std::string(algName(a)) + "/" + modeName(m) + " " + err; break;
                }
                if (buf != plain) {
                    ok = false;
                    bad = std::string(algName(a)) + "/" + modeName(m) + " n=" + std::to_string(n) + " 明文不一致";
                    break;
                }
                ++cases;
            }
            if (!ok) break;
        }
        if (!ok) break;
    }
    check(ok, "加解密往返一致性", bad.empty() ? std::to_string(cases) + " 组 (3 算法 x 2 模式 x 8 长度)" : bad);
}

// ECB 弱点：相同明文块 -> 相同密文块；CBC 下相同参数但 IV 不同 -> 密文不同
void testModeProperties() {
    std::vector<std::uint8_t> key;
    randomKey(Alg::TDES3, key);
    const std::vector<std::uint8_t> plain(32, 0x41);  // 4 个完全相同的明文块
    std::string err;

    std::uint8_t iv0[8] = {0};
    std::vector<std::uint8_t> ecb = plain;
    transform(ecb, key, Alg::TDES3, Mode::ECB, iv0, true, err);
    const bool sameBlocks = std::memcmp(ecb.data(), ecb.data() + 8, 8) == 0 &&
                            std::memcmp(ecb.data(), ecb.data() + 16, 8) == 0;
    check(sameBlocks, "ECB 模式弱点复现", "4 个相同明文块产生相同密文块");

    std::uint8_t ivA[8] = {0};
    std::uint8_t ivB[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    std::vector<std::uint8_t> ca = plain, cb = plain;
    transform(ca, key, Alg::TDES3, Mode::CBC, ivA, true, err);
    transform(cb, key, Alg::TDES3, Mode::CBC, ivB, true, err);
    const bool ivEffect = (ca != cb) && std::memcmp(ca.data(), cb.data(), 8) != 0;
    check(ivEffect, "CBC 密文受 IV 影响", "IV 不同则首块密文即不同");

    const bool diffBlocks = std::memcmp(ca.data(), ca.data() + 8, 8) != 0 &&
                            std::memcmp(ca.data(), ca.data() + 16, 8) != 0;
    check(diffBlocks, "CBC 隐藏 ECB 的模式弱点", "相同明文块产生不同密文块");
}

// 错误密钥与篡改：固定密钥/IV/明文，保证结果确定可复现
void testIntegrity() {
    std::string err;
    std::vector<std::uint8_t> key;
    parseKeyHex("0123456789ABCDEF23456789ABCDEF01", Alg::TDES2, key, err);
    std::vector<std::uint8_t> plain(64);
    for (std::size_t i = 0; i < plain.size(); ++i) plain[i] = (std::uint8_t)i;
    const std::uint8_t iv[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

    std::vector<std::uint8_t> ct = plain;
    transform(ct, key, Alg::TDES2, Mode::CBC, iv, true, err);

    // (1) 错误密钥（仅错 1 个有效密钥位）绝不可能得到正确明文；
    //     注意 PKCS#7 填充校验存在约 1/256 的漏检率，所以只断言“明文必错”。
    std::vector<std::uint8_t> wrong = key;
    wrong[0] ^= 0x80;  // 最高位才是有效密钥位，低位的奇偶校验位会被 PC-1 丢弃
    std::vector<std::uint8_t> buf = ct;
    const bool decOk = transform(buf, wrong, Alg::TDES2, Mode::CBC, iv, false, err);
    check(!decOk || buf != plain, "错误密钥得不到正确明文",
          decOk ? "解密未报错但明文已乱码" : "已被填充校验拒绝");

    // (1b) DES 每个字节的最低比特是奇偶校验位，密钥编排一开始就由 PC-1 丢弃，
    //      因此只翻转它不会改变任何子密钥，密文/明文完全不受到影响。
    std::vector<std::uint8_t> parityOnly = key;
    parityOnly[0] ^= 0x01;
    buf = ct;
    const bool decOkP = transform(buf, parityOnly, Alg::TDES2, Mode::CBC, iv, false, err);
    check(decOkP && buf == plain, "奇偶校验位不参与密钥编排",
          (decOkP && buf == plain) ? "仅翻转 LSB 后仍能正确解密" : "结果发生变化");

    // (2) 篡改末字节：影响最后一个分组，填充校验应拒绝
    std::vector<std::uint8_t> t1 = ct;
    t1[t1.size() - 1] ^= 0x01;
    buf = t1;
    const bool rej1 = !transform(buf, key, Alg::TDES2, Mode::CBC, iv, false, err);
    check(rej1, "末字节篡改被检出", rej1 ? "已被填充校验拒绝" : "未检出");

    // (3) 篡改中间分组：CBC 只保证机密性、不保证完整性，
    //     解密可能“静默”通过，但解出的明文一定已被破坏——这正是需要额外
    //     MAC（如 HMAC）的原因。
    std::vector<std::uint8_t> t2 = ct;
    t2[16] ^= 0x80;
    buf = t2;
    const bool decOk2 = transform(buf, key, Alg::TDES2, Mode::CBC, iv, false, err);
    const bool garbled = !decOk2 || buf != plain;
    check(garbled, "中间分组篡改破坏明文",
          decOk2 ? "解密未报错，但明文已乱码（CBC 无完整性保护）" : "已被填充校验拒绝");
}

}  // namespace

int selfTest(bool verbose) {
    (void)verbose;
    std::printf("=========== DES / 3DES 内置自检 ===========\n");
    g_pass = 0;
    g_fail = 0;
    testKat();
    testDegenerate();
    testPermutation();
    testPadding();
    testRoundTrip();
    testModeProperties();
    testIntegrity();
    std::printf("-------------------------------------------\n");
    std::printf("用例总数 %d，通过 %d，失败 %d\n", g_pass + g_fail, g_pass, g_fail);
    return g_fail;
}

}  // namespace tdes
