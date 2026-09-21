// ============================================================================
//  gui.cpp —— 3DES 文件加解密工具的图形界面（纯 Win32 API，无第三方 GUI 库）
//  ---------------------------------------------------------------------------
//  设计要点：
//    * 一个主窗口 + 标准控件（EDIT / BUTTON / COMBOBOX / RADIO / 多行日志），
//      编译产物是与命令行版并列的独立程序 tdes_gui.exe；
//    * 全程使用宽字符（W 版）API 配合宽字符串字面量，保证中文界面正常显示；
//      而核心库统一使用 UTF-8 路径，故在边界处做 UTF-16 <-> UTF-8 转换；
//    * 加解密直接复用 des.cpp / tdes.cpp，与命令行版结果完全一致；
//    * 支持把文件直接拖到窗口上（WM_DROPFILES），并在完成后显示
//      算法、模式、IV、字节数、分组数、耗时与吞吐率；
//    * 输出路径可自定义：输出框预填按规则推导的默认名，可直接编辑，
//      也可用“另存为…”选择任意位置；清空输出框即恢复自动推导。
// ============================================================================

// 必须放在 windows.h 之前：启用宽字符 API，并声明 SetProcessDPIAware 等较新的接口
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601  // Windows 7 及以上
#endif

#include "des.h"
#include "tdes.h"

#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {

// ------------------------------ 控件 ID ------------------------------
enum : int {
    IDC_EDIT_FILE = 1001,
    IDC_BTN_BROWSE,
    IDC_EDIT_KEY,
    IDC_BTN_GENKEY,
    IDC_COMBO_ALG,
    IDC_RADIO_CBC,
    IDC_RADIO_ECB,
    IDC_BTN_ENC,
    IDC_BTN_DEC,
    IDC_EDIT_LOG,
    IDC_STATIC_STATUS,
    IDC_EDIT_OUT,        // 输出文件路径（留空 = 按规则自动推导）
    IDC_BTN_OUT_BROWSE   // “另存为…”：为输出文件指定路径
};

// ---------------------------- 布局常量（像素） ----------------------------
const int MARGIN      = 12;   // 窗口四周留白
const int LABEL_W     = 70;   // 标签宽度（容得下“输出文件:”）
const int BTN_SMALL_W = 104;  // “浏览…/随机生成/另存为…”按钮宽度
const int ROW1_Y      = 14;   // 输入文件
const int ROW2_Y      = 48;   // 输出文件
const int ROW3_Y      = 82;   // 密钥
const int ROW4_Y      = 116;  // 算法 / 模式
const int ROW5_Y      = 152;  // 加密 / 解密按钮
const int ACTION_H    = 38;   // 加密/解密按钮高度
const int LOG_Y       = 204;  // 日志区起始 y
const int STATUS_H    = 20;
const int MIN_W       = 560;
const int MIN_H       = 470;

HWND g_hFile = nullptr;    // 输入文件路径输入框
HWND g_hKey = nullptr;     // 密钥输入框
HWND g_hAlg = nullptr;     // 算法下拉框
HWND g_hCbc = nullptr;     // 模式：CBC
HWND g_hEcb = nullptr;     // 模式：ECB
HWND g_hEnc = nullptr;     // 加密按钮
HWND g_hDec = nullptr;     // 解密按钮
HWND g_hBrowse = nullptr;  // 浏览按钮
HWND g_hGenKey = nullptr;  // 随机密钥按钮
HWND g_hOut = nullptr;     // 输出文件路径输入框
HWND g_hOutBrowse = nullptr;  // “另存为…”按钮
HWND g_hModeLabel = nullptr;  // “模式:”标签（随窗口宽度移动）
HWND g_hLog = nullptr;     // 日志显示区
HWND g_hStatus = nullptr;  // 底部状态栏

HFONT g_hFont = nullptr;   // 全局界面字体
std::wstring g_logBuffer;  // 日志文本缓冲区（日志框为只读，靠重设文本刷新）

// 输出路径状态：g_outAuto 为 true 表示输出框内容由程序按规则推导（用户在输入
// 文件变化时会自动刷新默认名）；用户一旦手工编辑或“另存为”即置为 false，
// 此后尊重用户指定的路径。g_settingOut 用于区分“程序写入”与“用户输入”。
bool g_outAuto = true;
bool g_settingOut = false;

// ---------------------------- DPI 自适应 ----------------------------
// 下面的布局常量都按 96 DPI（100% 缩放）设计，实际使用前经 S() 换算成物理像素，
// 才能在高分屏（如 200% 缩放）下既不被压扁也不模糊。
int g_dpi = 96;

int S(int v) { return MulDiv(v, g_dpi, 96); }

void initDpi() {
    HDC dc = GetDC(nullptr);
    if (dc) {
        const int dpi = GetDeviceCaps(dc, LOGPIXELSX);
        if (dpi > 0) g_dpi = dpi;
        ReleaseDC(nullptr, dc);
    }
    if (g_dpi <= 0) g_dpi = 96;
}

// ============================ 编码转换工具 ============================

std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((std::size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((std::size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

std::wstring getText(HWND h) {
    const int n = GetWindowTextLengthW(h);
    if (n <= 0) return std::wstring();
    std::wstring s((std::size_t)n + 1, L'\0');
    GetWindowTextW(h, &s[0], n + 1);
    s.resize((std::size_t)n);
    return s;
}

// 去掉密钥里可能混入的空格、制表符和换行
std::wstring stripSpaces(const std::wstring& s) {
    std::wstring r;
    r.reserve(s.size());
    for (wchar_t c : s) {
        if (c != L' ' && c != L'\t' && c != L'\r' && c != L'\n') r.push_back(c);
    }
    return r;
}

bool fileExists(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// 大小写不敏感的后缀判断（用于识别 .3des / .3DES 等写法）
bool endsWithNoCase(const std::wstring& s, const std::wstring& suffix) {
    if (s.size() < suffix.size()) return false;
    const std::size_t off = s.size() - suffix.size();
    for (std::size_t i = 0; i < suffix.size(); ++i) {
        wchar_t a = s[off + i];
        wchar_t b = suffix[i];
        if (a >= L'A' && a <= L'Z') a = (wchar_t)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = (wchar_t)(b - L'A' + L'a');
        if (a != b) return false;
    }
    return true;
}

// ============================ 界面小工具 ============================

// 前置声明（输出路径校验里会用到这两个提示函数，定义在下方）
void setStatus(const std::wstring& text);
void showError(HWND hwnd, const std::wstring& text);

// 输出路径相关工具：默认名推导、目录/同名校验 ========================

bool dirExists(const std::wstring& dir) {
    const DWORD a = GetFileAttributesW(dir.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// 取路径所在目录（用于校验输出目录是否存在）
std::wstring parentDir(const std::wstring& path) {
    const std::size_t p = path.find_last_of(L"\\/");
    if (p == std::wstring::npos) return L".";
    if (p == 0) return path.substr(0, 1);
    return path.substr(0, p);
}

// 默认输出名：加密 → <原文件名>.3des
std::wstring defaultEncryptOut(const std::wstring& in) { return in + L".3des"; }

// 默认输出名：解密 → 去掉 .3des 后缀；若无该后缀则追加 .dec
std::wstring defaultDecryptOut(const std::wstring& in) {
    std::wstring out = in;
    const std::wstring suffix = L".3des";
    if (endsWithNoCase(out, suffix)) out.resize(out.size() - suffix.size());
    else out += L".dec";
    return out;
}

// 取绝对路径（用于判断输入/输出是否为同一个文件）
std::wstring fullPath(const std::wstring& p) {
    std::vector<wchar_t> buf(4096, L'\0');
    const DWORD n = GetFullPathNameW(p.c_str(), (DWORD)buf.size(), buf.data(), nullptr);
    if (n == 0 || n >= buf.size()) return p;
    return std::wstring(buf.data(), n);
}

bool samePath(const std::wstring& a, const std::wstring& b) {
    return _wcsicmp(fullPath(a).c_str(), fullPath(b).c_str()) == 0;
}

// 写入输出框，并标记为“程序写入”，避免被当成用户手工修改
void setOutText(const std::wstring& text) {
    if (!g_hOut) return;
    g_settingOut = true;
    SetWindowTextW(g_hOut, text.c_str());
    g_settingOut = false;
}

// 输入文件变化时刷新默认输出名（仅在用户尚未自定义输出路径时）
void updateOutDefault() {
    if (!g_outAuto || !g_hOut) return;
    const std::wstring in = getText(g_hFile);
    setOutText(in.empty() ? std::wstring() : defaultEncryptOut(in));
}

// 解析本次操作实际使用的输出路径：自动模式或输出框为空 → 按规则推导并回填
std::wstring resolveOutput(const std::wstring& in, bool encrypting) {
    std::wstring out = getText(g_hOut);
    if (out.empty()) g_outAuto = true;  // 清空输出框 = 恢复自动推导
    if (g_outAuto) {
        out = encrypting ? defaultEncryptOut(in) : defaultDecryptOut(in);
        setOutText(out);
    }
    return out;
}

// 输出路径的基本校验：目录存在，且不与输入文件是同一个文件
bool checkOutputPath(HWND hwnd, const std::wstring& in, const std::wstring& out) {
    const std::wstring dir = parentDir(out);
    if (!dirExists(dir)) {
        showError(hwnd, L"输出目录不存在：\n" + dir + L"\n\n请点击“另存为…”重新指定输出文件。");
        setStatus(L"输出目录不存在，操作已取消");
        return false;
    }
    if (samePath(in, out)) {
        showError(hwnd, L"输出文件不能与输入文件相同：\n" + out +
                            L"\n\n请点击“另存为…”换一个输出文件名。");
        setStatus(L"输出文件与输入文件相同，操作已取消");
        return false;
    }
    return true;
}

void setStatus(const std::wstring& text) {
    if (g_hStatus) SetWindowTextW(g_hStatus, text.c_str());
}

// 日志框设为只读，所以通过整体重设文本 + 滚动到底部来追加
void appendLog(const std::wstring& text) {
    if (!g_hLog) return;
    g_logBuffer += text;
    g_logBuffer += L"\r\n";
    SetWindowTextW(g_hLog, g_logBuffer.c_str());
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

void showError(HWND hwnd, const std::wstring& text) {
    MessageBoxW(hwnd, text.c_str(), L"错误", MB_OK | MB_ICONERROR);
}

int msgYesNo(HWND hwnd, const std::wstring& text) {
    return MessageBoxW(hwnd, text.c_str(), L"确认", MB_YESNO | MB_ICONQUESTION);
}

// 创建界面字体：取系统消息字体，DPI/语言相关的效果最自然
HFONT createUiFont() {
    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        HFONT f = CreateFontIndirectW(&ncm.lfMessageFont);
        if (f) return f;
    }
    return (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

HWND makeControl(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style,
                 int x, int y, int w, int h, int id) {
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, parent,
                             (HMENU)(INT_PTR)id, nullptr, nullptr);
    SendMessageW(c, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return c;
}

// 读取当前算法/模式选择
tdes::Alg currentAlg() {
    const int i = (int)SendMessageW(g_hAlg, CB_GETCURSEL, 0, 0);
    switch (i) {
        case 0: return tdes::Alg::DES;
        case 1: return tdes::Alg::TDES2;
        default: return tdes::Alg::TDES3;
    }
}

tdes::Mode currentMode() {
    return SendMessageW(g_hEcb, BM_GETCHECK, 0, 0) == BST_CHECKED ? tdes::Mode::ECB : tdes::Mode::CBC;
}

void refreshKeyHint() {
    // 根据算法把密钥框调整到合适的长度提示
    const std::size_t n = tdes::keyBytes(currentAlg());
    setStatus(L"提示：当前算法需要密钥长度为 " + std::to_wstring(n) + L" 字节（" +
              std::to_wstring(n * 2) + L" 个十六进制字符）");
}

// 让控件随窗口大小自适应（w/h 为客户端区的物理像素尺寸）
void layout(HWND hwnd, int w, int h) {
    (void)hwnd;  // 子控件位置直接用 MoveWindow 设置，无需父窗口句柄
    const int editW = w - S(LABEL_W + MARGIN + 4) - S(MARGIN + BTN_SMALL_W + MARGIN);
    const int smallX = w - S(MARGIN + BTN_SMALL_W);
    const int colX = S(LABEL_W + MARGIN);   // 输入框/下拉框统一的起始 x

    if (g_hFile) MoveWindow(g_hFile, colX, S(ROW1_Y), editW, S(24), TRUE);
    if (g_hBrowse) MoveWindow(g_hBrowse, smallX, S(ROW1_Y - 1), S(BTN_SMALL_W), S(26), TRUE);
    if (g_hOut) MoveWindow(g_hOut, colX, S(ROW2_Y), editW, S(24), TRUE);
    if (g_hOutBrowse) MoveWindow(g_hOutBrowse, smallX, S(ROW2_Y - 1), S(BTN_SMALL_W), S(26), TRUE);
    if (g_hKey) MoveWindow(g_hKey, colX, S(ROW3_Y), editW, S(24), TRUE);
    if (g_hGenKey) MoveWindow(g_hGenKey, smallX, S(ROW3_Y - 1), S(BTN_SMALL_W), S(26), TRUE);

    // 第四行：算法下拉框 + 模式单选按钮
    const int algW = S(150);
    const int modeLabelX = colX + algW + S(16);
    const int radioW = S(58);
    if (g_hAlg) MoveWindow(g_hAlg, colX, S(ROW4_Y), algW, S(200), TRUE);
    if (g_hModeLabel) MoveWindow(g_hModeLabel, modeLabelX, S(ROW4_Y + 4), S(44), S(20), TRUE);
    if (g_hCbc) MoveWindow(g_hCbc, modeLabelX + S(48), S(ROW4_Y + 1), radioW, S(22), TRUE);
    if (g_hEcb) MoveWindow(g_hEcb, modeLabelX + S(48) + radioW + S(6), S(ROW4_Y + 1), radioW, S(22), TRUE);

    // 第五行：加密 / 解密按钮
    const int btnW = S(170);
    if (g_hEnc) MoveWindow(g_hEnc, colX, S(ROW5_Y), btnW, S(ACTION_H), TRUE);
    if (g_hDec) MoveWindow(g_hDec, colX + btnW + S(20), S(ROW5_Y), btnW, S(ACTION_H), TRUE);

    if (g_hLog) {
        MoveWindow(g_hLog, S(MARGIN), S(LOG_Y), w - S(2 * MARGIN),
                   h - S(LOG_Y + STATUS_H + 2 * MARGIN), TRUE);
    }
    if (g_hStatus) {
        MoveWindow(g_hStatus, S(MARGIN), h - S(MARGIN + STATUS_H), w - S(2 * MARGIN), S(STATUS_H), TRUE);
    }
}

// ============================ 业务动作 ============================

// 选择文件
void onBrowse(HWND hwnd) {
    std::vector<wchar_t> buf(4096, L'\0');
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"所有文件\0*.*\0加密文件 (*.3des)\0*.3des\0\0";
    ofn.lpstrFile = buf.data();
    ofn.nMaxFile = (DWORD)buf.size();
    ofn.lpstrTitle = L"请选择要处理的文件";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (GetOpenFileNameW(&ofn)) {
        g_outAuto = true;  // 换了输入文件，输出名回到默认推导
        SetWindowTextW(g_hFile, buf.data());  // 触发 EN_CHANGE → 自动刷新输出框
        updateOutDefault();
        setStatus(L"已选择输入文件，可点击“加密”或“解密”");
    }
}

// 选择输出文件（“另存为…”）：允许把结果写到任意目录/文件名
void onBrowseOut(HWND hwnd) {
    const std::wstring in = getText(g_hFile);
    std::wstring cur = getText(g_hOut);
    if (cur.empty()) {
        // 输出框为空（= 自动推导）时，用默认名作为另存为的初始文件名
        cur = in.empty() ? std::wstring() : defaultEncryptOut(in);
    }

    std::vector<wchar_t> buf(4096, L'\0');
    if (!cur.empty() && cur.size() < buf.size() - 1) {
        std::copy(cur.begin(), cur.end(), buf.begin());
    }

    const bool looksCipher = endsWithNoCase(cur, L".3des");
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = looksCipher
        ? L"加密文件 (*.3des)\0*.3des\0所有文件 (*.*)\0*.*\0\0"
        : L"所有文件 (*.*)\0*.*\0加密文件 (*.3des)\0*.3des\0\0";
    ofn.lpstrFile = buf.data();
    ofn.nMaxFile = (DWORD)buf.size();
    ofn.lpstrTitle = L"请选择输出文件（若选中的是加密结果，请以 .3des 结尾）";
    ofn.lpstrDefExt = looksCipher ? L"3des" : nullptr;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (GetSaveFileNameW(&ofn)) {
        g_outAuto = false;  // 用户亲自指定了输出路径，之后不再自动覆盖
        setOutText(buf.data());
        setStatus(L"已指定输出路径，可点击“加密”或“解密”");
    }
}

// 生成随机密钥
void onGenKey() {
    std::vector<std::uint8_t> key;
    tdes::randomKey(currentAlg(), key);
    const std::wstring hex = utf8ToWide(tdes::toHex(key));
    SetWindowTextW(g_hKey, hex.c_str());
    setStatus(L"已生成随机密钥（" + std::to_wstring(key.size()) + L" 字节），请妥善保存");
}

// 打印一次操作的统计信息
void reportSuccess(const wchar_t* action, const tdes::Params& used, const tdes::FileResult& res,
                   const std::wstring& outPath, long long ms) {
    const double mb = (double)res.inBytes / 1048576.0;
    const double speed = ms > 0 ? mb / ((double)ms / 1000.0) : 0.0;

    std::wostringstream os;
    os << L"=== " << action << L"成功 ===" << L"\n"
       << L"算法      : " << utf8ToWide(tdes::algName(used.alg)) << L"\n"
       << L"工作模式  : " << utf8ToWide(tdes::modeName(used.mode)) << L"\n"
       << L"IV        : " << utf8ToWide(tdes::toHex(used.iv, tdes::IV_SIZE)) << L"\n"
       << L"输出文件  : " << outPath << L"\n"
       << L"输入大小  : " << res.inBytes << L" 字节\n"
       << L"输出大小  : " << res.outBytes << L" 字节\n"
       << L"分组数    : " << res.blocks << L"\n"
       << L"耗时      : " << ms << L" ms";
    if (speed > 0.0) {
        os << L"（约 " << std::fixed << std::setprecision(2) << speed << L" MB/s）";
    }
    appendLog(os.str());
    setStatus(std::wstring(action) + L"完成");
}

// 加密
void onEncrypt(HWND hwnd) {
    const std::wstring path = getText(g_hFile);
    if (path.empty()) {
        MessageBoxW(hwnd, L"请先选择要加密的文件（也可以直接把文件拖到窗口里）。", L"提示",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::wstring keyHexW = stripSpaces(getText(g_hKey));
    if (keyHexW.empty()) {
        MessageBoxW(hwnd, L"请输入密钥，或点击“随机生成”按钮。", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }

    const tdes::Alg alg = currentAlg();
    const tdes::Mode mode = currentMode();
    std::vector<std::uint8_t> key;
    std::string err;
    if (!tdes::parseKeyHex(wideToUtf8(keyHexW), alg, key, err)) {
        showError(hwnd, utf8ToWide(err));
        return;
    }

    // 输出路径：默认按 <原文件名>.3des 推导并回填，也可由用户编辑/另存为指定
    const std::wstring outPath = resolveOutput(path, true);
    if (!checkOutputPath(hwnd, path, outPath)) return;
    if (fileExists(outPath) &&
        msgYesNo(hwnd, L"输出文件已存在：\n" + outPath + L"\n\n是否覆盖？") != IDYES) {
        setStatus(L"已取消（输出文件已存在）");
        return;
    }

    tdes::Params p;
    p.alg = alg;
    p.mode = mode;
    tdes::FileResult res;
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = tdes::encryptFile(wideToUtf8(path), wideToUtf8(outPath), key, p, res, err);
    const auto t1 = std::chrono::steady_clock::now();
    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (!ok) {
        appendLog(L"[加密失败] " + utf8ToWide(err));
        showError(hwnd, L"加密失败：\n" + utf8ToWide(err));
        setStatus(L"加密失败");
        return;
    }
    reportSuccess(L"加密", p, res, outPath, ms);
}

// 解密：算法/模式/IV 从密文文件头读取，这里只按密钥长度推断算法以便解析密钥
void onDecrypt(HWND hwnd) {
    const std::wstring path = getText(g_hFile);
    if (path.empty()) {
        MessageBoxW(hwnd, L"请先选择要解密的文件（也可以直接把文件拖到窗口里）。", L"提示",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::wstring keyHexW = stripSpaces(getText(g_hKey));
    if (keyHexW.empty()) {
        MessageBoxW(hwnd, L"请输入密钥，或点击“随机生成”按钮。", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }

    tdes::Alg alg = currentAlg();
    if (keyHexW.size() == 16) alg = tdes::Alg::DES;
    else if (keyHexW.size() == 32) alg = tdes::Alg::TDES2;
    else if (keyHexW.size() == 48) alg = tdes::Alg::TDES3;

    std::vector<std::uint8_t> key;
    std::string err;
    if (!tdes::parseKeyHex(wideToUtf8(keyHexW), alg, key, err)) {
        showError(hwnd, utf8ToWide(err));
        return;
    }

    // 输出路径：默认去掉 .3des（否则追加 .dec）并回填，也可由用户编辑/另存为指定
    const std::wstring outPath = resolveOutput(path, false);
    if (!checkOutputPath(hwnd, path, outPath)) return;
    if (fileExists(outPath) &&
        msgYesNo(hwnd, L"输出文件已存在：\n" + outPath + L"\n\n是否覆盖？") != IDYES) {
        setStatus(L"已取消（输出文件已存在）");
        return;
    }

    tdes::Params p;
    p.alg = alg;
    p.mode = currentMode();  // 非 raw 模式下解密以文件头记录为准，这里仅作占位
    tdes::Params used;
    tdes::FileResult res;
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = tdes::decryptFile(wideToUtf8(path), wideToUtf8(outPath), key, p, used, res, err);
    const auto t1 = std::chrono::steady_clock::now();
    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (!ok) {
        appendLog(L"[解密失败] " + utf8ToWide(err));
        setStatus(L"解密失败");
        MessageBoxW(hwnd,
                    (L"解密失败：\n" + utf8ToWide(err) +
                     L"\n\n常见原因：密钥不正确，或该文件不是本工具生成的密文。")
                        .c_str(),
                    L"错误", MB_OK | MB_ICONERROR);
        return;
    }
    reportSuccess(L"解密", used, res, outPath, ms);
}

// ============================ 主窗口过程 ============================

LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g_hFont = createUiFont();

            makeControl(hwnd, L"STATIC", L"输入文件:", SS_LEFT, S(MARGIN), S(ROW1_Y + 4), S(LABEL_W), S(20), -1);
            g_hFile = makeControl(hwnd, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 0, S(ROW1_Y), 100,
                                  S(24), IDC_EDIT_FILE);
            g_hBrowse = makeControl(hwnd, L"BUTTON", L"浏览…", BS_PUSHBUTTON, 0, S(ROW1_Y), 100, S(26),
                                    IDC_BTN_BROWSE);

            makeControl(hwnd, L"STATIC", L"输出文件:", SS_LEFT, S(MARGIN), S(ROW2_Y + 4), S(LABEL_W), S(20), -1);
            g_hOut = makeControl(hwnd, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 0, S(ROW2_Y), 100,
                                 S(24), IDC_EDIT_OUT);
            g_hOutBrowse = makeControl(hwnd, L"BUTTON", L"另存为…", BS_PUSHBUTTON, 0, S(ROW2_Y), 100,
                                       S(26), IDC_BTN_OUT_BROWSE);

            makeControl(hwnd, L"STATIC", L"密钥:", SS_LEFT, S(MARGIN), S(ROW3_Y + 4), S(LABEL_W), S(20), -1);
            g_hKey = makeControl(hwnd, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | ES_UPPERCASE, 0,
                                 S(ROW3_Y), 100, S(24), IDC_EDIT_KEY);
            g_hGenKey = makeControl(hwnd, L"BUTTON", L"随机生成", BS_PUSHBUTTON, 0, S(ROW3_Y), 100, S(26),
                                    IDC_BTN_GENKEY);

            makeControl(hwnd, L"STATIC", L"算法:", SS_LEFT, S(MARGIN), S(ROW4_Y + 4), S(LABEL_W), S(20), -1);
            g_hAlg = makeControl(hwnd, L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL, S(LABEL_W + MARGIN),
                                 S(ROW4_Y), S(150), S(200), IDC_COMBO_ALG);
            SendMessageW(g_hAlg, CB_ADDSTRING, 0, (LPARAM)L"DES");
            SendMessageW(g_hAlg, CB_ADDSTRING, 0, (LPARAM)L"3DES-2Key");
            SendMessageW(g_hAlg, CB_ADDSTRING, 0, (LPARAM)L"3DES-3Key");
            SendMessageW(g_hAlg, CB_SETCURSEL, 2, 0);

            g_hModeLabel = makeControl(hwnd, L"STATIC", L"模式:", SS_LEFT, S(248), S(ROW4_Y + 4), S(44), S(20), -1);
            g_hCbc = makeControl(hwnd, L"BUTTON", L"CBC", BS_AUTORADIOBUTTON | WS_GROUP, S(296),
                                 S(ROW4_Y + 1), S(58), S(22), IDC_RADIO_CBC);
            g_hEcb = makeControl(hwnd, L"BUTTON", L"ECB", BS_AUTORADIOBUTTON, S(362), S(ROW4_Y + 1), S(58),
                                 S(22), IDC_RADIO_ECB);
            SendMessageW(g_hCbc, BM_SETCHECK, BST_CHECKED, 0);

            g_hEnc = makeControl(hwnd, L"BUTTON", L"加密 →", BS_DEFPUSHBUTTON, S(LABEL_W + MARGIN),
                                 S(ROW5_Y), S(170), S(ACTION_H), IDC_BTN_ENC);
            g_hDec = makeControl(hwnd, L"BUTTON", L"← 解密", BS_PUSHBUTTON, S(LABEL_W + MARGIN + 190),
                                 S(ROW5_Y), S(170), S(ACTION_H), IDC_BTN_DEC);

            g_hLog = makeControl(hwnd, L"EDIT", L"",
                                 WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                 S(MARGIN), S(LOG_Y), 100, 100, IDC_EDIT_LOG);
            g_hStatus = makeControl(hwnd, L"STATIC", L"就绪：选择文件 → 输入或生成密钥 → 点击加密/解密",
                                    SS_LEFT | SS_ENDELLIPSIS, S(MARGIN), 100, 100, S(STATUS_H), -1);

            DragAcceptFiles(hwnd, TRUE);

            appendLog(L"使用说明：\n"
                      L"  1) 点击“浏览…”选择输入文件，或把文件直接拖到本窗口；\n"
                      L"  2) 输出文件已自动填好默认名，需要时可直接编辑或用“另存为…”改到其它目录；\n"
                      L"  3) 输入十六进制密钥，或点击“随机生成”得到随机密钥；\n"
                      L"  4) 选择算法与工作模式后点击“加密”或“解密”。\n"
                      L"默认输出名：加密为 <原文件名>.3des，解密为去掉 .3des 后的原名（无该后缀则追加 .dec）。\n"
                      L"输出框留空 = 恢复自动推导；解密只用密钥即可，算法、模式与 IV 都记录在密文文件头中。");

            RECT rc;
            GetClientRect(hwnd, &rc);
            layout(hwnd, rc.right, rc.bottom);
            refreshKeyHint();
            SetFocus(g_hFile);
            return 0;
        }

        case WM_SIZE: {
            layout(hwnd, LOWORD(lp), HIWORD(lp));
            return 0;
        }

        case WM_GETMINMAXINFO: {
            auto* mmi = (MINMAXINFO*)lp;
            RECT r{0, 0, S(MIN_W), S(MIN_H)};
            AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
            mmi->ptMinTrackSize.x = r.right - r.left;
            mmi->ptMinTrackSize.y = r.bottom - r.top;
            return 0;
        }

        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wp;
            const UINT n = DragQueryFileW(hDrop, 0xFFFFFFFF, nullptr, 0);
            if (n > 0) {
                std::vector<wchar_t> buf(4096, L'\0');
                if (DragQueryFileW(hDrop, 0, buf.data(), (UINT)buf.size()) > 0) {
                    g_outAuto = true;  // 换了输入文件，输出名回到默认推导
                    SetWindowTextW(g_hFile, buf.data());
                    updateOutDefault();
                    setStatus(L"已载入拖入的文件");
                }
            }
            DragFinish(hDrop);
            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDC_BTN_BROWSE: onBrowse(hwnd); return 0;
                case IDC_BTN_OUT_BROWSE: onBrowseOut(hwnd); return 0;
                case IDC_BTN_GENKEY: onGenKey(); return 0;
                case IDC_BTN_ENC: onEncrypt(hwnd); return 0;
                case IDC_BTN_DEC: onDecrypt(hwnd); return 0;
                case IDC_EDIT_FILE:
                    // 输入文件变化 → 同步刷新默认输出名（不影响用户已自定义的路径）
                    if (HIWORD(wp) == EN_CHANGE) updateOutDefault();
                    return 0;
                case IDC_EDIT_OUT:
                    // 用户在输出框里手工改了内容 → 之后不再自动覆盖其选择；清空则恢复自动
                    if (HIWORD(wp) == EN_CHANGE && !g_settingOut) {
                        g_outAuto = false;
                        setStatus(L"已自定义输出路径（清空该框可恢复自动命名）");
                    }
                    return 0;
                case IDC_COMBO_ALG:
                    if (HIWORD(wp) == CBN_SELCHANGE) refreshKeyHint();
                    return 0;
                default: break;
            }
            return 0;
        }

        case WM_CLOSE: {
            DestroyWindow(hwnd);
            return 0;
        }

        case WM_DESTROY: {
            if (g_hFont) DeleteObject(g_hFont);
            PostQuitMessage(0);
            return 0;
        }

        default: break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

// ============================ 程序入口 ============================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInst;
    (void)lpCmdLine;

    SetProcessDPIAware();  // 高分屏下不做位图拉伸，界面更清晰
    initDpi();             // 取得系统 DPI，供 S() 换算布局尺寸

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"TdesGuiWindow";
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    if (!RegisterClassExW(&wc)) return 1;

    RECT r{0, 0, S(620), S(520)};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"3DES 任意文件加解密工具",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                r.right - r.left, r.bottom - r.top, nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        // 交给 IsDialogMessage 处理，可使用 Tab 键在控件之间切换
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
