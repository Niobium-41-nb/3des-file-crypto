================================================================
 3DES 文件加解密 —— 免安装便携版
================================================================

【怎么用】
  1) 图形界面：双击 tdes_gui.exe，选择输入文件（或直接把文件拖进窗口）；
     输出文件一栏会自动填好默认名，需要时可直接编辑，或点“另存为…”保存到
     任意目录/文件名（清空该栏 = 恢复自动命名）；
     输入十六进制密钥（或点“随机生成”），再点“加密 / 解密”。
  2) 命令行：在本目录打开 PowerShell，执行
         .\tdes.exe selftest        运行内置自检（39 个用例）
         .\tdes.exe genkey          生成随机密钥
         .\tdes.exe help            查看全部用法
     若要把 tdes 命令加到 PATH，可在 PowerShell 中执行（把 <本目录> 换成实际路径）：
         [Environment]::SetEnvironmentVariable('Path',
             [Environment]::GetEnvironmentVariable('Path','User') + ';<本目录>', 'User')

【环境要求】
  Windows 7 SP1 及以上，64 位。
  两个 exe 均已静态链接 C/C++ 运行库，不需要安装任何依赖、也不需要 DLL。

【版本与校验】
  版本     见 README.md / 发行版页面
  校验     发行版中的 SHA256SUMS.txt 给出两个 exe 的 SHA-256，
           可用 Get-FileHash tdes.exe -Algorithm SHA256 自行比对。

【安全提示】
  本程序是信息安全课程的**教学实现**（手写 DES / 3DES，未使用任何现成密码库）。
  DES 有效密钥仅 56 位，早已可被穷举；3DES 实际安全强度约 112 位；
  ECB 模式会泄漏明文分组结构。请勿用它保护真实敏感数据，
  工程场景应使用 AES-GCM / ChaCha20-Poly1305 等现代算法。
