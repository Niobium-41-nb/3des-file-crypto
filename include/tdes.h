// ============================================================================
//  tdes.h —— 三重 DES（3DES/EDE）+ CBC/ECB 工作模式 + 文件容器
//  ---------------------------------------------------------------------------
//  在三重 DES 中，加密过程为 C = E_K3( D_K2( E_K1(P) ) )，
//  解密过程为 P = D_K1( E_K2( D_K3(C) ) )，即“加密—解密—加密”（EDE）。
//  当 K1 = K2 = K3 时退化为普通 DES，因此单个 DES 只是本模块的一个特例。
// ============================================================================
#ifndef TDES_H
#define TDES_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "des.h"

namespace tdes {

// 算法类型（数值与密文文件头中的字段一致，便于持久化）
enum class Alg : int {
    DES   = 1,  // 单 DES，8 字节密钥
    TDES2 = 2,  // 双密钥 3DES：K3 = K1，16 字节密钥
    TDES3 = 3   // 三密钥 3DES，24 字节密钥
};

// 工作模式
enum class Mode : int {
    ECB = 1,  // 电子密码本
    CBC = 2   // 密码分组链接
};

const std::size_t IV_SIZE     = 8;   // CBC 初始向量长度 = 分组长度
const std::size_t HEADER_SIZE = 22;  // 自描述文件头长度

// 自描述文件头布局（共 22 字节，全部大端）：
//   偏移 0..3   : 魔数 "TDS1"
//   偏移 4      : alg（1=DES, 2=3DES-2Key, 3=3DES-3Key）
//   偏移 5      : mode（1=ECB, 2=CBC）
//   偏移 6..13  : IV（ECB 模式恒为 0）
//   偏移 14..21 : 明文原始长度 origSize（用于解密后校验与去填充）
static const std::size_t OFF_MAGIC = 0;
static const std::size_t OFF_ALG   = 4;
static const std::size_t OFF_MODE  = 5;
static const std::size_t OFF_IV    = 6;
static const std::size_t OFF_SIZE  = 14;

// 一次加/解密操作的参数
struct Params {
    Alg alg = Alg::TDES3;      // 算法
    Mode mode = Mode::CBC;     // 工作模式
    bool raw = false;          // true = 不写/不读文件头（便于与其它实现互操作）
    bool ivGiven = false;      // true = 使用外部指定的 iv
    std::uint8_t iv[IV_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0};
};

// 结果统计
struct FileResult {
    std::uint64_t inBytes  = 0;  // 输入文件大小
    std::uint64_t outBytes = 0;  // 输出文件大小
    std::uint64_t blocks   = 0;  // 处理的分组数
};

// ------------------------------ 辅助函数 ------------------------------
const char* algName(Alg a);    // "DES" / "3DES-2Key" / "3DES-3Key"
const char* modeName(Mode m);  // "ECB" / "CBC"
std::size_t keyBytes(Alg a);   // 该算法要求的密钥字节数

// 在 Windows 控制台下把输出代码页切换为 UTF-8，保证中文信息正常显示
void enableUtf8Console();

std::string toHex(const std::uint8_t* p, std::size_t n);
std::string toHex(const std::vector<std::uint8_t>& v);
bool parseHexBytes(const std::string& hex, std::uint8_t* out, std::size_t n);
bool parseKeyHex(const std::string& hex, Alg a, std::vector<std::uint8_t>& key, std::string& err);

bool randomKey(Alg a, std::vector<std::uint8_t>& key);
bool randomIV(std::uint8_t iv[IV_SIZE]);

// ---------------------------- 填充与分组运算 ----------------------------
void pkcs7Pad(std::vector<std::uint8_t>& data, std::size_t blockSize);
bool pkcs7Unpad(std::vector<std::uint8_t>& data, std::size_t blockSize);

// 按 alg 对单个分组做加/解密（DES 或 3DES-EDE）
void encryptBlock(const std::uint8_t in[des::BLOCK_SIZE], std::uint8_t out[des::BLOCK_SIZE],
                  const std::vector<des::SubKeys>& ks, Alg a);
void decryptBlock(const std::uint8_t in[des::BLOCK_SIZE], std::uint8_t out[des::BLOCK_SIZE],
                  const std::vector<des::SubKeys>& ks, Alg a);

// 由密钥字节扩展出 1 或 3 组子密钥
std::vector<des::SubKeys> buildSubKeys(const std::vector<std::uint8_t>& key, Alg a);

// 对整段缓冲区加密/解密（加密时做 PKCS#7 填充，解密时去填充），原地修改
bool transform(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& key, Alg alg, Mode mode,
               const std::uint8_t iv[IV_SIZE], bool encrypt, std::string& err);

// ------------------------------ 文件级接口 ------------------------------
// 注意：p 按引用传入，因为非 raw 模式下若未指定 IV，函数会随机生成并写回 p.iv，
//       调用者据此才能显示/记录本次使用的 IV。
bool encryptFile(const std::string& inPath, const std::string& outPath, const std::vector<std::uint8_t>& key,
                 Params& p, FileResult& res, std::string& err);

// 解密：非 raw 模式下 alg/mode/iv 从文件头读取，used 返回实际使用的参数
bool decryptFile(const std::string& inPath, const std::string& outPath, const std::vector<std::uint8_t>& key,
                 Params p, Params& used, FileResult& res, std::string& err);

// 内置已知答案测试（KAT）与往返测试，返回失败用例数
int selfTest(bool verbose);

}  // namespace tdes

#endif  // TDES_H
