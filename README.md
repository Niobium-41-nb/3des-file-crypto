# 3DES 文件加解密小软件

信息安全实验：手写实现 DES / 三重 DES 算法，并对**任意文件**（文本、二进制、中文文件名均可）进行加解密。

## 1. 功能特点

| 项目 | 说明 |
| --- | --- |
| 算法 | 单 DES（64 位分组 / 56 位有效密钥）、3DES-EDE（双密钥 112 位 / 三密钥 168 位） |
| 工作模式 | ECB、CBC（默认 CBC，IV 随机生成并随密文保存） |
| 填充 | PKCS#7（补足 8 字节整数倍，且总能无歧义去填充） |
| 文件类型 | 任意二进制文件；支持中文文件名与中文路径 |
| 文件头 | 22 字节自描述头：魔数 `TDS1` + 算法 + 模式 + IV + 明文原始长度 |
| 互操作 | `--raw` 模式可输出/读取不含文件头的裸密文，已与 .NET `TripleDES` 双向互解 |
| 自检 | `tdes selftest` 内置 25 个用例（含 12 个标准向量 KAT） |
| 实现约束 | 纯 C++17 标准库，不调用 OpenSSL / CryptoAPI 等任何现成密码库 |

## 2. 目录结构

```
3DES文件加解密/
├── include/
│   ├── des.h            DES 算法内核接口（分组、密钥、子密钥结构）
│   └── tdes.h           3DES + 工作模式 + 填充 + 文件容器的接口
├── src/
│   ├── des.cpp          DES 核心：标准表、轮函数、密钥编排、分组加解密
│   ├── tdes.cpp         3DES-EDE、ECB/CBC、PKCS#7、文件读写与自描述文件头
│   ├── selftest.cpp     内置自检（KAT / 填充 / 模式性质 / 完整性）
│   └── main.cpp         命令行界面（参数解析、统计输出）
├── tests/
│   └── test_kat.cpp     文件级端到端测试、错误注入与性能测试
├── tools/
│   ├── dotnet_vectors.ps1   用 .NET 计算标准向量（第三方参照值）
│   └── crosscheck.ps1       与 .NET DES/TripleDES 的交叉验证
├── demo/                演示用文件（明文 / 密文 / 还原结果）
├── report/
│   └── report.tex       实验报告（XeLaTeX 源码）
├── Makefile
└── README.md
```

## 3. 编译

需要 MinGW-w64（g++ 支持 C++17）。在本目录下：

```powershell
mingw32-make            # 编译 tdes.exe
mingw32-make test       # 编译并运行全部测试
```

也可直接调用编译器：

```powershell
g++ -std=c++17 -O2 -Wall -Wextra -Iinclude -static -static-libgcc -static-libstdc++ `
    -o tdes.exe src/des.cpp src/tdes.cpp src/selftest.cpp src/main.cpp
```

> `-o` 使用相对路径是为了绕开 MinGW `ld` 无法处理含中文的**绝对**输出路径的问题；
> `-static-libgcc -static-libstdc++` 可避免 PATH 中多套 MinGW 运行库混用导致程序退出时崩溃。

VS Code 用户可直接运行任务：`3DES: 编译 tdes.exe`、`3DES: 运行内置自检`、`3DES: 编译并运行全部测试`、`3DES: 与 .NET 实现交叉验证`。

## 4. 使用方法

```
tdes selftest                                    运行内置自检（标准向量 KAT）
tdes genkey [--alg des|3des2|3des3]              生成随机密钥
tdes subkeys -k <HEX> [--alg ...]                打印 16 轮子密钥
tdes block [-e|-d] -k <HEX> -p <16位HEX> [--alg ...]
tdes enc <明文文件> <密文文件> -k <HEX> [选项]   加密文件
tdes dec <密文文件> <明文文件> -k <HEX> [选项]   解密文件
```

选项：

| 选项 | 含义 |
| --- | --- |
| `-k <HEX>` | 密钥（十六进制）：DES = 16 字符，3DES-2Key = 32 字符，3DES-3Key = 48 字符 |
| `--alg <N>` | `des` / `3des2` / `3des3`（默认 `3des3`） |
| `-m <MODE>` | `cbc` / `ecb`（默认 `cbc`；解密时以密文文件头记录为准） |
| `-iv <HEX>` | 显式指定 8 字节 IV（默认非 raw 模式随机生成；raw 模式需自行约定，缺省全 0） |
| `--raw` | 不写 / 不读 22 字节文件头，用于与其它实现互操作 |
| `-f` | 允许覆盖已存在的输出文件 |
| `-q` | 安静模式（`block` 子命令下只输出结果十六进制，便于脚本比对） |
| `-h` | 帮助 |

### 示例

```powershell
# 1) 生成密钥
.\tdes.exe genkey --alg 3des3
# 密钥HEX : D19FCEC956C9D946E8006F04C3106FC9260092AC091C9993

# 2) 加密与解密（支持中文文件名）
.\tdes.exe enc 'demo\信息明文.txt' 'demo\信息密文.3des' -k D19F...C9993
.\tdes.exe dec 'demo\信息密文.3des' 'demo\信息还原.txt' -k D19F...C9993

# 3) 校验还原结果
(Get-FileHash 'demo\信息明文.txt').Hash -eq (Get-FileHash 'demo\信息还原.txt').Hash   # True

# 4) 与标准向量对照（教学演示）
.\tdes.exe block -k 133457799BBCDFF1 -p 0123456789ABCDEF --alg des
# 输出密文   : 85E813540F0AB405
```

## 5. 密文文件格式（非 raw 模式）

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 4 | 魔数 `TDS1` |
| 4 | 1 | 算法：1 = DES，2 = 3DES-2Key，3 = 3DES-3Key |
| 5 | 1 | 模式：1 = ECB，2 = CBC |
| 6 | 8 | IV（ECB 模式恒为 0） |
| 14 | 8 | 明文原始长度（大端，用于去填充后校验） |
| 22 | 8k | 密文数据（PKCS#7 填充后，长度为 8 的整数倍） |

## 6. 测试

```powershell
.\tdes.exe selftest        # 25 个用例：12 个标准向量 KAT + 13 个性质/边界用例
.\test_kat.exe             # 52 个用例：文件级往返 + 错误注入 + 性能测试
powershell -NoProfile -ExecutionPolicy Bypass -File tools\crosscheck.ps1   # 与 .NET 交叉验证 16 项
```

标准向量来自教材经典向量与 .NET `System.Security.Cryptography`（DES / TripleDES，ECB，无填充），
两者与本程序输出完全一致。

## 7. 安全说明（本程序为教学实现）

* DES 有效密钥仅 56 位，早已可被穷举破解；3DES 的 168 位密钥因“中间相遇”攻击实际安全强度约 112 位。
* ECB 模式会泄漏明文的分组重复结构（自检用例 `ECB 模式弱点复现` 演示了这一点），实际应用应使用 CBC 并每次更换随机 IV。
* 本程序只用 PKCS#7 填充校验与文件头长度校验做**弱完整性检查**：CBC 且被篡改的密文若不在末尾分组，解密仍可能“静默”通过（自检用例 `中间分组篡改破坏明文` 演示了这一点）。生产环境应使用 AES-GCM 或“加密后 MAC”（如 HMAC-SHA256）。
* 不要用它保护真实敏感数据；如需工程级加密请使用 OpenSSL 等成熟实现。
