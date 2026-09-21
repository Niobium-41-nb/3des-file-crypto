// ============================================================================
//  tdes.cpp —— 3DES 分组运算、CBC/ECB 模式、PKCS#7 填充与文件容器实现
// ============================================================================
#include "tdes.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>

namespace fs = std::filesystem;

namespace tdes {

// ============================ 基础工具 ============================

const char* algName(Alg a) {
    switch (a) {
        case Alg::DES:   return "DES";
        case Alg::TDES2: return "3DES-2Key";
        case Alg::TDES3: return "3DES-3Key";
    }
    return "?";
}

const char* modeName(Mode m) {
    switch (m) {
        case Mode::ECB: return "ECB";
        case Mode::CBC: return "CBC";
    }
    return "?";
}

std::size_t keyBytes(Alg a) {
    switch (a) {
        case Alg::DES:   return 8;
        case Alg::TDES2: return 16;
        case Alg::TDES3: return 24;
    }
    return 0;
}

#ifdef _WIN32
#include <windows.h>
#endif

void enableUtf8Console() {
#ifdef _WIN32
    // 控制台默认代码页（简体中文 Windows 为 GBK/936）无法直接显示 UTF-8 字节，
    // 因此把输出代码页切换为 UTF-8；源文件中的中文字面量本身就是 UTF-8 编码。
    SetConsoleOutputCP(CP_UTF8);
#endif
}

std::string toHex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0x0F]);
    }
    return s;
}

std::string toHex(const std::vector<std::uint8_t>& v) { return toHex(v.data(), v.size()); }

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parseHexBytes(const std::string& hex, std::uint8_t* out, std::size_t n) {
    if (hex.size() != n * 2) return false;
    for (std::size_t i = 0; i < n; ++i) {
        int hi = hexVal(hex[2 * i]);
        int lo = hexVal(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (std::uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool parseKeyHex(const std::string& hex, Alg a, std::vector<std::uint8_t>& key, std::string& err) {
    const std::size_t want = keyBytes(a) * 2;  // 十六进制字符数
    if (hex.size() != want) {
        err = std::string("密钥长度不匹配：") + algName(a) + " 需要 " + std::to_string(want) +
              " 个十六进制字符（" + std::to_string(keyBytes(a)) + " 字节），实际 " + std::to_string(hex.size()) + " 个";
        return false;
    }
    key.assign(keyBytes(a), 0);
    if (!parseHexBytes(hex, key.data(), key.size())) {
        err = "密钥中含有非法的十六进制字符（只允许 0-9 / a-f / A-F）";
        return false;
    }
    return true;
}

// 随机数发生器：以 random_device 为主，混入高精度时钟，避免在部分 MinGW 上
// random_device 退化为确定性序列
static std::mt19937_64& rng() {
    static std::mt19937_64 gen = [] {
        std::random_device rd;
        unsigned int seeds[5];
        for (int i = 0; i < 3; ++i) seeds[i] = (unsigned int)rd();
        seeds[3] = (unsigned int)std::chrono::high_resolution_clock::now().time_since_epoch().count();
        seeds[4] = (unsigned int)std::chrono::steady_clock::now().time_since_epoch().count();
        std::seed_seq seq(seeds, seeds + 5);
        return std::mt19937_64(seq);
    }();
    return gen;
}

bool randomKey(Alg a, std::vector<std::uint8_t>& key) {
    key.assign(keyBytes(a), 0);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : key) b = (std::uint8_t)dist(rng());
    return true;
}

bool randomIV(std::uint8_t iv[IV_SIZE]) {
    std::uniform_int_distribution<int> dist(0, 255);
    for (std::size_t i = 0; i < IV_SIZE; ++i) iv[i] = (std::uint8_t)dist(rng());
    return true;
}

// ============================ PKCS#7 填充 ============================

void pkcs7Pad(std::vector<std::uint8_t>& data, std::size_t blockSize) {
    std::size_t pad = blockSize - (data.size() % blockSize);
    if (pad == 0) pad = blockSize;  // 恰好整块时填充一整块，保证去填充可判定
    data.insert(data.end(), pad, (std::uint8_t)pad);
}

bool pkcs7Unpad(std::vector<std::uint8_t>& data, std::size_t blockSize) {
    if (data.empty() || data.size() % blockSize != 0) return false;
    const std::uint8_t pad = data.back();
    if (pad == 0 || pad > blockSize) return false;
    for (std::size_t i = data.size() - pad; i < data.size(); ++i) {
        if (data[i] != pad) return false;
    }
    data.resize(data.size() - pad);
    return true;
}

// ============================ 分组加解密 ============================

std::vector<des::SubKeys> buildSubKeys(const std::vector<std::uint8_t>& key, Alg a) {
    std::vector<des::SubKeys> ks;
    if (a == Alg::DES) {
        ks.resize(1);
        des::keySchedule(key.data(), ks[0]);
    } else if (a == Alg::TDES2) {
        ks.resize(3);
        des::keySchedule(key.data(), ks[0]);       // K1
        des::keySchedule(key.data() + 8, ks[1]);   // K2
        des::keySchedule(key.data(), ks[2]);       // K3 = K1
    } else {
        ks.resize(3);
        des::keySchedule(key.data(), ks[0]);
        des::keySchedule(key.data() + 8, ks[1]);
        des::keySchedule(key.data() + 16, ks[2]);
    }
    return ks;
}

void encryptBlock(const std::uint8_t in[des::BLOCK_SIZE], std::uint8_t out[des::BLOCK_SIZE],
                  const std::vector<des::SubKeys>& ks, Alg a) {
    if (a == Alg::DES) {
        des::encryptBlock(in, out, ks[0]);
        return;
    }
    std::uint8_t t1[8], t2[8];
    des::encryptBlock(in, t1, ks[0]);   // C1 = E_K1(P)
    des::decryptBlock(t1, t2, ks[1]);   // C2 = D_K2(C1)
    des::encryptBlock(t2, out, ks[2]);  // C  = E_K3(C2)
}

void decryptBlock(const std::uint8_t in[des::BLOCK_SIZE], std::uint8_t out[des::BLOCK_SIZE],
                  const std::vector<des::SubKeys>& ks, Alg a) {
    if (a == Alg::DES) {
        des::decryptBlock(in, out, ks[0]);
        return;
    }
    std::uint8_t t1[8], t2[8];
    des::decryptBlock(in, t1, ks[2]);   // D_K3
    des::encryptBlock(t1, t2, ks[1]);   // E_K2
    des::decryptBlock(t2, out, ks[0]);  // D_K1
}

// ====================== 缓冲区整体加解密（含填充） ======================

bool transform(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& key, Alg alg, Mode mode,
               const std::uint8_t iv[IV_SIZE], bool encrypt, std::string& err) {
    if (encrypt) {
        pkcs7Pad(buf, des::BLOCK_SIZE);  // 加密前补齐到分组整数倍
    } else if (buf.empty() || buf.size() % des::BLOCK_SIZE != 0) {
        err = "密文长度非法（应为 8 的整数倍且非空），文件可能损坏或不是密文";
        return false;
    }

    const std::vector<des::SubKeys> ks = buildSubKeys(key, alg);
    const std::size_t n = buf.size() / des::BLOCK_SIZE;
    std::vector<std::uint8_t> out(buf.size());

    std::uint8_t prev[IV_SIZE];
    std::memcpy(prev, iv, IV_SIZE);  // CBC 链接变量，初值为 IV

    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t blk[8], res[8];
        std::memcpy(blk, buf.data() + i * 8, 8);

        if (mode == Mode::CBC && encrypt) {
            for (int j = 0; j < 8; ++j) blk[j] ^= prev[j];  // C_i = E(P_i XOR C_{i-1})
        }
        if (encrypt) {
            encryptBlock(blk, res, ks, alg);
        } else {
            decryptBlock(blk, res, ks, alg);
        }
        if (mode == Mode::CBC) {
            if (encrypt) {
                std::memcpy(prev, res, 8);
            } else {
                for (int j = 0; j < 8; ++j) res[j] ^= prev[j];  // P_i = D(C_i) XOR C_{i-1}
                std::memcpy(prev, blk, 8);                      // 更新链接变量为当前密文块
            }
        }
        std::memcpy(out.data() + i * 8, res, 8);
    }
    buf.swap(out);

    if (!encrypt && !pkcs7Unpad(buf, des::BLOCK_SIZE)) {
        err = "PKCS#7 去填充校验失败：密钥错误、模式不匹配或密文被篡改";
        return false;
    }
    return true;
}

// ============================ 文件读写 ============================

static bool readAll(const std::string& path, std::vector<std::uint8_t>& out, std::string& err) {
    // 使用 u8path 使 Windows 下的中文路径也能正确打开（内部走宽字符 API）
    fs::path p = fs::u8path(path);
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        err = "无法打开输入文件：" + path;
        return false;
    }
    f.seekg(0, std::ios::end);
    std::streamoff len = f.tellg();
    if (len < 0) {
        err = "无法获取输入文件长度：" + path;
        return false;
    }
    f.seekg(0, std::ios::beg);
    out.assign((std::size_t)len, 0);
    if (len > 0) {
        f.read(reinterpret_cast<char*>(out.data()), len);
        if (f.gcount() != len) {
            err = "读取输入文件失败：" + path;
            return false;
        }
    }
    return true;
}

static bool writeAll(const std::string& path, const std::vector<std::uint8_t>& data, std::string& err) {
    fs::path p = fs::u8path(path);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) {
        err = "无法创建输出文件：" + path;
        return false;
    }
    if (!data.empty()) f.write(reinterpret_cast<const char*>(data.data()), (std::streamsize)data.size());
    if (!f) {
        err = "写入输出文件失败：" + path;
        return false;
    }
    return true;
}

// ============================ 文件级加解密 ============================

bool encryptFile(const std::string& inPath, const std::string& outPath, const std::vector<std::uint8_t>& key,
                 Params& p, FileResult& res, std::string& err) {
    if (key.size() != keyBytes(p.alg)) {
        err = "密钥长度与算法不匹配";
        return false;
    }
    std::vector<std::uint8_t> buf;
    if (!readAll(inPath, buf, err)) return false;
    res.inBytes = buf.size();

    if (!p.ivGiven) {
        if (p.mode == Mode::ECB) {
            std::memset(p.iv, 0, IV_SIZE);  // ECB 不需要 IV，统一置零
        } else if (!p.raw) {
            randomIV(p.iv);  // 非 raw：IV 随密文一起写入文件头，解密时可自动还原
        }
        // raw + CBC：没有文件头可存放 IV，只能沿用调用者给定的值（默认全 0），
        // 调用方必须把它当作公开参数一并告知解密方。
    }

    if (!transform(buf, key, p.alg, p.mode, p.iv, true, err)) return false;
    res.blocks = buf.size() / des::BLOCK_SIZE;

    if (p.raw) {
        if (!writeAll(outPath, buf, err)) return false;
        res.outBytes = buf.size();
        return true;
    }

    std::vector<std::uint8_t> out;
    out.reserve(HEADER_SIZE + buf.size());
    out.push_back('T');
    out.push_back('D');
    out.push_back('S');
    out.push_back('1');
    out.push_back((std::uint8_t)p.alg);
    out.push_back((std::uint8_t)p.mode);
    out.insert(out.end(), p.iv, p.iv + IV_SIZE);
    const std::uint64_t n = res.inBytes;
    for (int i = 7; i >= 0; --i) out.push_back((std::uint8_t)((n >> (8 * i)) & 0xFF));
    out.insert(out.end(), buf.begin(), buf.end());

    if (!writeAll(outPath, out, err)) return false;
    res.outBytes = out.size();
    return true;
}

bool decryptFile(const std::string& inPath, const std::string& outPath, const std::vector<std::uint8_t>& key,
                 Params p, Params& used, FileResult& res, std::string& err) {
    std::vector<std::uint8_t> buf;
    if (!readAll(inPath, buf, err)) return false;
    res.inBytes = buf.size();

    used = p;
    bool haveSize = false;
    std::uint64_t origSize = 0;

    if (!p.raw) {
        if (buf.size() < HEADER_SIZE || std::memcmp(buf.data() + OFF_MAGIC, "TDS1", 4) != 0) {
            err = "文件头校验失败：不是本工具生成的密文（如需解密不含文件头的裸密文，请加 --raw）";
            return false;
        }
        used.alg = (Alg)buf[OFF_ALG];
        used.mode = (Mode)buf[OFF_MODE];
        std::memcpy(used.iv, buf.data() + OFF_IV, IV_SIZE);
        used.ivGiven = true;
        if ((int)used.alg < 1 || (int)used.alg > 3 || (int)used.mode < 1 || (int)used.mode > 2) {
            err = "文件头中的算法/模式字段非法，文件可能已损坏";
            return false;
        }
        for (int i = 0; i < 8; ++i) origSize = (origSize << 8) | buf[OFF_SIZE + i];
        haveSize = true;
        buf.erase(buf.begin(), buf.begin() + HEADER_SIZE);
    }

    if (key.size() != keyBytes(used.alg)) {
        err = std::string("密钥长度与密文中的算法（") + algName(used.alg) + "）不匹配";
        return false;
    }

    if (!transform(buf, key, used.alg, used.mode, used.iv, false, err)) return false;
    res.blocks = res.inBytes / des::BLOCK_SIZE;

    if (haveSize && buf.size() != origSize) {
        err = "解密后长度与文件头记录不一致：得到 " + std::to_string(buf.size()) +
              " 字节，文件头记录 " + std::to_string(origSize) + " 字节（密钥或文件可能不正确）";
        return false;
    }

    if (!writeAll(outPath, buf, err)) return false;
    res.outBytes = buf.size();
    return true;
}

}  // namespace tdes
