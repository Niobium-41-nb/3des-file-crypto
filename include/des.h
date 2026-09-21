// ============================================================================
//  des.h —— DES（Data Encryption Standard）分组密码算法内核接口
//  ---------------------------------------------------------------------------
//  本模块只依赖 C++ 标准库，完全手写实现 FIPS 46-3 规定的 DES 算法，
//  不调用 OpenSSL / CryptoAPI 等任何现成密码库。
//
//  一个分组 = 64 位 = 8 字节，密钥 = 64 位（含 8 个奇偶校验位，有效密钥 56 位）。
// ============================================================================
#ifndef DES_H
#define DES_H

#include <cstddef>
#include <cstdint>

namespace des {

using u64 = std::uint64_t;
using u32 = std::uint32_t;

// DES 分组长度与密钥长度（字节）
const std::size_t BLOCK_SIZE = 8;
const std::size_t KEY_SIZE   = 8;

// 16 轮子密钥，每个 48 位（右对齐保存在 u64 的低 48 位中）
struct SubKeys {
    u64 k[16];
};

// ---------------------------- 内部工具函数 ----------------------------
// 通用“查表置换”：把 in 的低 inWidth 位按 table 给出的位号重新排列成 n 位输出
//   table 采用 FIPS 46-3 的 1-based 编址习惯：位号 1 表示 in 的最高位
//   inWidth  : 输入的有效位宽（64/56/32 等）
//   n        : 输出位宽（即 table 的元素个数）
//   返回值    : 置换结果，右对齐存放在 u64 中
u64 permute(u64 in, const int* table, int n, int inWidth);

// 28 位半区循环左移 n 位（密钥编排用）
u64 rotateLeft28(u64 v, int n);

// 轮函数 f(R, K)：E 扩展 -> 与子密钥异或 -> S 盒代换 -> P 置换
u64 feistel(u32 r, u64 subKey);

// 把 S 盒的 6 位输入拆成行号与列号（均从 0 开始计数，直接作为表格下标）：
//   行号 = 第 1 位与第 6 位拼成的 2 位二进制
//          00→第 1 行、01→第 2 行、10→第 3 行、11→第 4 行
//   列号 = 中间 4 位组成的二进制数
//          0000→第 1 列、0001→第 2 列、…、1111→第 16 列
// 例：输入 1-0110-0（即二进制 101100，0x2C）→ 行 10（第 3 行 idx=2）、列 0110（第 7 列 idx=6）
inline void sboxIndex(int sixBits, int& row, int& col) {
    row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
    col = (sixBits >> 1) & 0x0F;
}

// 查询 S 盒取值（仅供教学与测试）：box 0..7 对应 S1..S8，row 0..3，col 0..15
// 越界返回 -1。用于核对“教材两处误值”等细节，不参与加密主流程。
int sboxValue(int box, int row, int col);

// 大端字节序与 64 位整数之间的转换（DES 以比特串为准，故统一用大端解读）
u64 bytesToU64(const std::uint8_t b[BLOCK_SIZE]);
void u64ToBytes(u64 v, std::uint8_t b[BLOCK_SIZE]);

// ------------------------------ 对外接口 ------------------------------
// 密钥编排：由 8 字节密钥生成 16 个 48 位子密钥
void keySchedule(const std::uint8_t key[KEY_SIZE], SubKeys& sk);

// 单个分组的加密 / 解密（ECB 语义，调用者负责分组与填充）
void encryptBlock(const std::uint8_t in[BLOCK_SIZE], std::uint8_t out[BLOCK_SIZE], const SubKeys& sk);
void decryptBlock(const std::uint8_t in[BLOCK_SIZE], std::uint8_t out[BLOCK_SIZE], const SubKeys& sk);

}  // namespace des

#endif  // DES_H
