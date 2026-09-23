// ============================================================================
//  gui.cpp —— 3DES 文件加解密工具的图形界面（纯 Win32 API，无第三方 GUI 库）
//  ---------------------------------------------------------------------------
//  界面风格：整体模仿 7-Zip 的主窗口，自上而下分为五层
//
//    ┌─ 菜单栏    文件 / 编辑 / 查看 / 工具 / 帮助
//    ├─ 工具栏    打开 · 加密 · 解密 │ 信息 · 随机密钥 · 测试 │ 关于
//    │            （自绘窗口类 TdesToolBar：图标全部用 GDI 现场绘制、
//    │              悬停/按下带立体反馈、带工具提示，不依赖任何图片资源）
//    ├─ 地址栏    [向上] [ 当前文件夹 / 文件路径 ▾ ]   仿资源管理器地址栏
//    ├─ 文件列表  ListView(report)：名称 / 大小 / 修改日期 / 属性 / 类型
//    │            可点击列头排序、双击进入目录或选中文件、右键菜单，
//    │            小图标同样由 GDI 绘制后转成 HICON 装入 ImageList
//    └─ 状态栏    标准 STATUSCLASSNAME，分三格显示对象数 / 字节数 / 提示
//
//  参数（密钥、算法、模式、输出文件）放在两个仿 7-Zip 的模态对话框里：
//    * “添加到加密包…”（对应 7-Zip 的“添加到压缩包”）—— 加密
//    * “解密到…”（对应 7-Zip 的“提取”）—— 解密
//  两个对话框都用 DialogBoxIndirectParamW + 内存中的 DLGTEMPLATE 构造，
//  因此不需要 .rc 资源，窗口类就是标准的 #32770。
//
//  其它要点：
//    * 全程宽字符（W 版）API，核心库统一使用 UTF-8 路径，边界处做转换；
//    * 加解密直接复用 des.cpp / tdes.cpp，与命令行版结果完全一致；
//    * 支持把文件直接拖到窗口上（WM_DROPFILES）与命令行参数启动；
//    * 高分屏下所有尺寸经 S() 按系统 DPI 换算；
//    * “信息”对话框能解析密文自描述文件头中的算法 / 模式 / IV / 原始长度。
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
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>  // 注意：必须放在 windows.h 之后
#include <windowsx.h>  // GET_X_LPARAM / GET_Y_LPARAM

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

// 应用程序图标资源 ID（与 assets/app.rc 保持一致）
#ifndef IDI_APPICON
#define IDI_APPICON 101
#endif

namespace {

// ================================ 控件 / 命令 ID ================================
enum : int {
    // ---- 主窗口子控件 ----
    IDC_TOOLBAR = 2001,
    IDC_UP,
    IDC_ADDR,
    IDC_LIST,
    IDC_LOG,
    IDC_STATUS,

    // ---- 工具栏 / 菜单命令 ----
    IDM_FILE_OPEN = 3001,
    IDM_FILE_ENC,
    IDM_FILE_DEC,
    IDM_FILE_EXIT,
    IDM_EDIT_COPYPATH,
    IDM_EDIT_PASTEPATH,
    IDM_EDIT_CLEARLOG,
    IDM_VIEW_LOG,
    IDM_VIEW_TOOLBAR,
    IDM_VIEW_REFRESH,
    IDM_TOOLS_GENKEY,
    IDM_TOOLS_INFO,
    IDM_TOOLS_TEST,
    IDM_HELP_USAGE,
    IDM_HELP_ABOUT,

    // ---- “添加到加密包”对话框 ----
    IDC_ENC_OUT = 4001,
    IDC_ENC_OUT_BROWSE,
    IDC_ENC_ALG,
    IDC_ENC_CBC,
    IDC_ENC_ECB,
    IDC_ENC_KEY,
    IDC_ENC_GENKEY,
    IDC_ENC_HINT,
    IDC_ENC_SHOWKEY,
    IDC_ENC_OVERWRITE,
    IDC_ENC_NOTE,

    // ---- “解密到…”对话框 ----
    IDC_DEC_OUT = 4101,
    IDC_DEC_OUT_BROWSE,
    IDC_DEC_KEY,
    IDC_DEC_HINT,
    IDC_DEC_SHOWKEY,
    IDC_DEC_OVERWRITE,
    IDC_DEC_NOTE,

    // ---- 通用文本信息对话框 ----
    IDC_TXT_EDIT = 4201,
    IDC_TXT_COPY
};

// ============================ 布局常量（96 DPI 逻辑像素） ============================
const int TB_H        = 32;   // 工具栏高度
const int TB_ICON     = 24;   // 工具栏图标逻辑尺寸
const int ADDR_H      = 24;   // 地址栏行高
const int LOG_H       = 132;  // 日志面板高度
const int MARGIN      = 4;
const int MIN_W       = 620;
const int MIN_H       = 420;

// 7-Zip 风格配色（自绘图标用）
const COLORREF NO_COLOR   = 0xFFFFFFFFu;
const COLORREF C_FOLDER   = RGB(255, 214, 122);
const COLORREF C_FOLDER_D = RGB(206, 150, 42);
const COLORREF C_PAPER    = RGB(253, 253, 253);
const COLORREF C_PAPER_D  = RGB(150, 158, 168);
const COLORREF C_BOX      = RGB(214, 222, 232);
const COLORREF C_BOX_L    = RGB(190, 200, 214);
const COLORREF C_BOX_D    = RGB(96, 108, 126);
const COLORREF C_GREEN    = RGB(56, 160, 62);
const COLORREF C_GREEN_D  = RGB(30, 110, 36);
const COLORREF C_RED      = RGB(206, 62, 52);
const COLORREF C_BLUE     = RGB(54, 104, 182);
const COLORREF C_BLUE_D   = RGB(32, 68, 130);
const COLORREF C_GOLD     = RGB(238, 190, 62);
const COLORREF C_GOLD_D   = RGB(178, 132, 20);
const COLORREF C_GRAY     = RGB(134, 142, 152);
const COLORREF C_GRAY_D   = RGB(78, 86, 96);
const COLORREF C_WHITE    = RGB(255, 255, 255);

// 图标种类
enum {
    ICON_FOLDER = 0,  // 文件夹（列表用）
    ICON_FILE,        // 普通文件（列表用）
    ICON_CIPHER,      // 加密文件（列表用，带小锁）
    ICON_UP,          // 向上一级 / 目录向外
    ICON_OPEN,        // 工具栏：打开
    ICON_ADD,         // 工具栏：加密（仿 7-Zip 的“添加”）
    ICON_EXTRACT,     // 工具栏：解密（仿 7-Zip 的“提取”）
    ICON_INFO,        // 工具栏：信息
    ICON_KEY,         // 工具栏：随机密钥
    ICON_TEST,        // 工具栏：内置自检
    ICON_ABOUT        // 工具栏：关于
};

const int IMG_FOLDER = 0;
const int IMG_FILE   = 1;
const int IMG_CIPHER = 2;

// ================================ 全局状态 ================================
HINSTANCE g_hInst     = nullptr;
HWND g_hMain          = nullptr;
HWND g_hToolBar       = nullptr;
HWND g_hUp            = nullptr;
HWND g_hAddr          = nullptr;
HWND g_hList          = nullptr;
HWND g_hLog           = nullptr;
HWND g_hStatus        = nullptr;
HFONT g_hFont         = nullptr;
HIMAGELIST g_hImlSmall = nullptr;
HACCEL g_hAccel       = nullptr;

int g_dpi      = 96;   // 系统 DPI（96 = 100%）
int g_statusH  = 22;   // 状态栏实际高度（物理像素）
bool g_showLog = true; // 日志面板是否可见

std::wstring g_inputFile;   // 当前输入文件（空 = 未选择）
std::wstring g_curDir;      // 文件列表当前目录
std::wstring g_logBuffer;   // 日志缓冲（只读 EDIT 靠整体重设文本刷新）
std::wstring g_sessionKey;  // 本次运行内记住的密钥（十六进制，仅在内存中）
std::wstring g_lastOut[2];  // [0]=加密 [1]=解密 上次使用的输出路径；空 = 按规则推导

bool g_hasUp        = false; // 列表里是否有“..”行
bool g_listFull     = false; // 目录项是否被截断（超过上限）
bool g_addrBusy     = false; // 防止刷新地址栏时递归触发通知
int  g_sortCol      = 0;     // 排序列
bool g_sortAsc      = true;  // 升序？
int  g_tbHot        = -1;    // 工具栏悬停项
int  g_tbPress      = -1;    // 工具栏按下项
bool g_tbTracking   = false;

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

// ============================ 编码 / 路径 小工具 ============================

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
    if (!h) return std::wstring();
    const int n = GetWindowTextLengthW(h);
    if (n <= 0) return std::wstring();
    std::wstring s((std::size_t)n + 1, L'\0');
    GetWindowTextW(h, &s[0], n + 1);
    s.resize((std::size_t)n);
    return s;
}

// 去掉密钥里可能混入的空格、制表符和换行（十六进制密钥常被分行复制）
std::wstring stripSpaces(const std::wstring& s) {
    std::wstring r;
    r.reserve(s.size());
    for (wchar_t c : s) {
        if (c != L' ' && c != L'\t' && c != L'\r' && c != L'\n') r.push_back(c);
    }
    return r;
}

std::wstring trim(const std::wstring& s) {
    const std::size_t a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return std::wstring();
    const std::size_t b = s.find_last_not_of(L" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool fileExists(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool dirExists(const std::wstring& dir) {
    const DWORD a = GetFileAttributesW(dir.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
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

bool isCipherName(const std::wstring& name) { return endsWithNoCase(name, L".3des"); }

// 取路径所在目录（用于校验输出目录是否存在）
std::wstring parentDir(const std::wstring& path) {
    const std::size_t p = path.find_last_of(L"\\/");
    if (p == std::wstring::npos) return L".";
    if (p == 0) return path.substr(0, 1);
    if (p == 2 && path[1] == L':') return path.substr(0, 3);  // 盘符根目录 "D:\"
    return path.substr(0, p);
}

bool isRootDir(const std::wstring& dir) {
    return dir.size() == 3 && dir[1] == L':' && (dir[2] == L'\\' || dir[2] == L'/');
}

// 拼接目录与文件名，避免出现重复的反斜杠
std::wstring joinPath(const std::wstring& dir, const std::wstring& name) {
    if (dir.empty()) return name;
    if (dir.back() == L'\\' || dir.back() == L'/') return dir + name;
    return dir + L"\\" + name;
}

std::wstring fileName(const std::wstring& path) {
    const std::size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(p + 1);
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

// ============================ 文本格式化 ============================

// Win32 的多行 EDIT 只把 CRLF 当作换行，单独的 \n 会被吞掉，
// 所以凡是要送进 EDIT 的文本都先做一次规范化。
std::wstring crlf(const std::wstring& s) {
    std::wstring r;
    r.reserve(s.size() + 16);
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == L'\n' && (i == 0 || s[i - 1] != L'\r')) r += L"\r\n";
        else r.push_back(s[i]);
    }
    return r;
}

// 千位分组：1234567 → "1,234,567"（仿 7-Zip 的“大小”列）
std::wstring groupDigits(std::uint64_t v) {
    wchar_t tmp[32];
    std::swprintf(tmp, 32, L"%llu", (unsigned long long)v);
    std::wstring s(tmp);
    std::wstring r;
    const int n = (int)s.size();
    for (int i = 0; i < n; ++i) {
        if (i > 0 && (n - i) % 3 == 0) r.push_back(L',');
        r.push_back(s[(std::size_t)i]);
    }
    return r;
}

std::wstring formatTime(const FILETIME& ft) {
    FILETIME local{};
    SYSTEMTIME st{};
    if (!FileTimeToLocalFileTime(&ft, &local)) return std::wstring();
    if (!FileTimeToSystemTime(&local, &st)) return std::wstring();
    wchar_t buf[64];
    std::swprintf(buf, 64, L"%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour,
                  st.wMinute);
    return buf;
}

// 属性列：文件夹显示 "D"，文件按 只读/隐藏/系统/存档 显示字母（仿 attrib）
std::wstring attrString(DWORD a, bool isDir) {
    std::wstring r;
    if (isDir) r += L"D";
    if (a & FILE_ATTRIBUTE_READONLY) r += L"R";
    if (a & FILE_ATTRIBUTE_HIDDEN) r += L"H";
    if (a & FILE_ATTRIBUTE_SYSTEM) r += L"S";
    if (a & FILE_ATTRIBUTE_ARCHIVE) r += L"A";
    if (r.empty()) r = L"-";
    return r;
}

// 类型列：按后缀给出中文说明（仿 7-Zip 的“类型”列）
std::wstring typeString(const std::wstring& name, bool isDir) {
    if (isDir) return L"文件夹";
    const std::size_t p = name.find_last_of(L'.');
    std::wstring ext = p == std::wstring::npos ? std::wstring() : name.substr(p + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    if (ext == L"3des") return L"3DES 加密文件";
    if (ext == L"txt") return L"文本文档";
    if (ext == L"bin") return L"二进制文件";
    if (ext == L"md") return L"Markdown 文档";
    if (ext == L"png" || ext == L"jpg" || ext == L"bmp" || ext == L"ico") return L"图像文件";
    if (ext == L"exe" || ext == L"dll") return L"程序文件";
    if (ext == L"zip" || ext == L"7z" || ext == L"rar") return L"压缩文件";
    if (ext.empty()) return L"文件";
    return ext + L" 文件";
}

// ============================ 7-Zip 风格的自绘图标 ============================
// 所有图标都在 24x24 的归一化网格里描述，再按目标矩形缩放绘制；
// 不使用任何位图/图标资源文件，因此换 DPI 也不会糊。

// 把颜色“去饱和并压浅”，用于禁用态（模仿 7-Zip 工具栏灰掉的按钮）
COLORREF shade(COLORREF c, bool dis) {
    if (!dis) return c;
    int g = (GetRValue(c) * 30 + GetGValue(c) * 59 + GetBValue(c) * 11) / 100;
    g = 178 + (g - 178) / 3;
    if (g < 0) g = 0;
    if (g > 255) g = 255;
    return RGB(g, g, g);
}

struct Painter {
    HDC dc;
    RECT r;
    COLORREF bg;  // “镂空”处填充的背景色（工具栏 = 按钮面色，图标位图 = 抠图色）
    bool dis;

    int X(int v) const { return r.left + MulDiv(v, r.right - r.left, 24); }
    int Y(int v) const { return r.top + MulDiv(v, r.bottom - r.top, 24); }
    int PW(int v) const {
        const int w = MulDiv(v, r.right - r.left, 24);
        return w < 1 ? 1 : w;
    }

    void box(int x0, int y0, int x1, int y1, COLORREF c) const {
        RECT q{X(x0), Y(y0), X(x1), Y(y1)};
        HBRUSH b = CreateSolidBrush(shade(c, dis));
        FillRect(dc, &q, b);
        DeleteObject(b);
    }

    // fill/edge 传 NO_COLOR 表示不填充 / 不描边
    void poly(const int* xy, int n, COLORREF fill, COLORREF edge, int penW = 1) const {
        std::vector<POINT> pts((std::size_t)n);
        for (int i = 0; i < n; ++i) pts[(std::size_t)i] = POINT{X(xy[2 * i]), Y(xy[2 * i + 1])};
        HGDIOBJ ob = nullptr, op = nullptr;
        HBRUSH b = nullptr;
        HPEN p = nullptr;
        if (fill == NO_COLOR) ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
        else {
            b = CreateSolidBrush(shade(fill, dis));
            ob = SelectObject(dc, b);
        }
        if (edge == NO_COLOR) op = SelectObject(dc, GetStockObject(NULL_PEN));
        else {
            p = CreatePen(PS_SOLID, PW(penW), shade(edge, dis));
            op = SelectObject(dc, p);
        }
        Polygon(dc, pts.data(), n);
        SelectObject(dc, ob);
        SelectObject(dc, op);
        if (b) DeleteObject(b);
        if (p) DeleteObject(p);
    }

    void oval(int x0, int y0, int x1, int y1, COLORREF fill, COLORREF edge = NO_COLOR,
              int penW = 1) const {
        HGDIOBJ ob = nullptr, op = nullptr;
        HBRUSH b = nullptr;
        HPEN p = nullptr;
        if (fill == NO_COLOR) ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
        else {
            b = CreateSolidBrush(shade(fill, dis));
            ob = SelectObject(dc, b);
        }
        if (edge == NO_COLOR) op = SelectObject(dc, GetStockObject(NULL_PEN));
        else {
            p = CreatePen(PS_SOLID, PW(penW), shade(edge, dis));
            op = SelectObject(dc, p);
        }
        Ellipse(dc, X(x0), Y(y0), X(x1), Y(y1));
        SelectObject(dc, ob);
        SelectObject(dc, op);
        if (b) DeleteObject(b);
        if (p) DeleteObject(p);
    }

    void line(int x0, int y0, int x1, int y1, COLORREF c, int w = 1) const {
        HPEN p = CreatePen(PS_SOLID, PW(w), shade(c, dis));
        HGDIOBJ op = SelectObject(dc, p);
        MoveToEx(dc, X(x0), Y(y0), nullptr);
        LineTo(dc, X(x1), Y(y1));
        SelectObject(dc, op);
        DeleteObject(p);
    }

    void glyph(const wchar_t* s, int x0, int y0, int x1, int y1, COLORREF c,
               const wchar_t* face = L"Microsoft YaHei") const {
        RECT q{X(x0), Y(y0), X(x1), Y(y1)};
        const int hgt = MulDiv(q.bottom - q.top, 10, 8);
        HFONT f = CreateFontW(-hgt, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                              DEFAULT_PITCH, face);
        HGDIOBJ of = SelectObject(dc, f);
        const int ob = SetBkMode(dc, TRANSPARENT);
        const COLORREF oc = SetTextColor(dc, shade(c, dis));
        DrawTextW(dc, s, -1, &q, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOCLIP);
        SetTextColor(dc, oc);
        SetBkMode(dc, ob);
        SelectObject(dc, of);
        DeleteObject(f);
    }
};

void drawIconShape(HDC dc, int kind, const RECT& rc, COLORREF bg, bool dis) {
    Painter p{dc, rc, bg, dis};

    // 文件夹（闭合，带左上角标签页；前板略亮，制造层次）
    static const int FOLDER_BACK[] = {2, 21, 2, 4, 9, 4, 11, 7, 22, 7, 22, 21};
    static const int FOLDER_FRONT[] = {2, 12, 22, 12, 20, 21, 4, 21};

    switch (kind) {
        case ICON_FOLDER:
        case ICON_OPEN:
            p.poly(FOLDER_BACK, 6, C_FOLDER, C_FOLDER_D);
            p.poly(FOLDER_FRONT, 4, RGB(255, 234, 176), C_FOLDER_D);
            break;

        case ICON_FILE:
            p.poly((const int[]){5, 2, 14, 2, 19, 8, 19, 22, 5, 22}, 5, C_PAPER, C_PAPER_D);
            p.poly((const int[]){14, 2, 19, 8, 14, 8}, 3, RGB(224, 230, 238), C_PAPER_D);
            p.box(8, 11, 16, 12, RGB(186, 196, 208));
            p.box(8, 15, 16, 16, RGB(186, 196, 208));
            break;

        case ICON_CIPHER:
            p.poly((const int[]){4, 2, 13, 2, 18, 8, 18, 22, 4, 22}, 5, C_PAPER, C_PAPER_D);
            p.poly((const int[]){13, 2, 18, 8, 13, 8}, 3, RGB(224, 230, 238), C_PAPER_D);
            p.box(7, 11, 15, 12, RGB(186, 196, 208));
            p.oval(11, 13, 18, 17, NO_COLOR, C_GOLD_D, 2);        // 锁梁
            p.poly((const int[]){10, 16, 19, 16, 19, 23, 10, 23}, 4, C_GOLD, C_GOLD_D);
            p.box(14, 18, 15, 20, C_GOLD_D);                      // 锁孔
            break;

        case ICON_UP:
            p.poly((const int[]){4, 13, 12, 3, 20, 13}, 3, C_BLUE, C_BLUE_D);
            p.poly((const int[]){8, 13, 16, 13, 16, 21, 8, 21}, 4, C_BLUE, C_BLUE_D);
            break;

        case ICON_ADD:  // 盒子 + 绿色加号（7-Zip 的“添加”）
            p.poly((const int[]){4, 8, 20, 8, 20, 21, 4, 21}, 4, C_BOX, C_BOX_D);
            p.poly((const int[]){3, 4, 21, 4, 21, 9, 3, 9}, 4, C_BOX_L, C_BOX_D);
            p.oval(12, 11, 23, 22, C_GREEN, C_GREEN_D);
            p.box(17, 14, 19, 20, C_WHITE);
            p.box(15, 16, 21, 18, C_WHITE);
            break;

        case ICON_EXTRACT:  // 盒子 + 红色向上箭头（7-Zip 的“提取”）
            p.poly((const int[]){3, 9, 21, 9, 21, 22, 3, 22}, 4, C_BOX, C_BOX_D);
            p.poly((const int[]){8, 11, 16, 11, 12, 3}, 3, C_RED, C_RED);
            p.poly((const int[]){10, 11, 14, 11, 14, 21, 10, 21}, 4, C_RED, C_RED);
            break;

        case ICON_INFO:
            p.oval(2, 2, 22, 22, C_BLUE, C_BLUE_D);
            p.oval(10, 5, 14, 9, C_WHITE);
            p.box(10, 11, 14, 19, C_WHITE);
            break;

        case ICON_KEY:
            p.oval(2, 5, 15, 18, C_GOLD, C_GOLD_D);
            p.oval(6, 9, 11, 14, bg);
            p.poly((const int[]){13, 10, 22, 10, 22, 14, 13, 14}, 4, C_GOLD, C_GOLD_D);
            p.poly((const int[]){16, 14, 18, 14, 18, 18, 16, 18}, 4, C_GOLD, C_GOLD_D);
            p.poly((const int[]){19, 14, 21, 14, 21, 18, 19, 18}, 4, C_GOLD, C_GOLD_D);
            break;

        case ICON_TEST:
            p.line(4, 13, 10, 20, C_GREEN_D, 3);
            p.line(10, 20, 21, 4, C_GREEN_D, 3);
            p.line(5, 13, 10, 17, C_GREEN, 4);
            p.line(10, 17, 20, 4, C_GREEN, 4);
            break;

        case ICON_ABOUT:
        default:
            p.oval(2, 2, 22, 22, C_GRAY, C_GRAY_D);
            p.glyph(L"?", 2, 2, 22, 22, C_WHITE);
            break;
    }
}

// 把图标画进 32bpp DIB 再转成 HICON（列表视图的小图标用）
HICON makeIcon(int kind, int w, int h) {
    if (w <= 0 || h <= 0) return nullptr;

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;  // 自上而下，内存顺序与像素顺序一致
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    HDC screen = GetDC(nullptr);
    void* bits = nullptr;
    HBITMAP hbm = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    HDC dc = CreateCompatibleDC(screen);
    HGDIOBJ oldBm = SelectObject(dc, hbm);

    const COLORREF KEY = RGB(255, 0, 255);  // 抠图色：图标本身不使用该颜色
    RECT all{0, 0, w, h};
    HBRUSH b = CreateSolidBrush(KEY);
    FillRect(dc, &all, b);
    DeleteObject(b);
    drawIconShape(dc, kind, all, KEY, false);

    // GDI 绘制不会写入 alpha 通道，这里手工补：仍是抠图色 → 全透明，其余 → 不透明
    auto* px = (std::uint32_t*)bits;
    const int n = w * h;
    for (int i = 0; i < n; ++i) {
        const std::uint32_t v = px[i] & 0x00FFFFFFu;
        px[i] = (v == 0x00FF00FFu) ? 0u : (v | 0xFF000000u);
    }
    GdiFlush();

    HBITMAP hMask = CreateBitmap(w, h, 1, 1, nullptr);
    HDC mdc = CreateCompatibleDC(screen);
    HGDIOBJ om = SelectObject(mdc, hMask);
    RECT mr{0, 0, w, h};
    FillRect(mdc, &mr, (HBRUSH)GetStockObject(BLACK_BRUSH));
    SelectObject(mdc, om);
    DeleteDC(mdc);

    ICONINFO ii{};
    ii.fIcon = TRUE;
    ii.hbmColor = hbm;
    ii.hbmMask = hMask;
    HICON ic = CreateIconIndirect(&ii);

    SelectObject(dc, oldBm);
    DeleteDC(dc);
    ReleaseDC(nullptr, screen);
    DeleteObject(hbm);
    DeleteObject(hMask);
    return ic;
}

// ============================ 仿 7-Zip 的自绘工具栏 ============================

struct TbItem {
    int id;             // 命令 ID（0 = 分隔线）
    int icon;           // 图标种类
    const wchar_t* text;  // 按钮文字
};

const TbItem TB_ITEMS[] = {
    {IDM_FILE_OPEN, ICON_OPEN, L"打开"},
    {IDM_FILE_ENC, ICON_ADD, L"加密"},
    {IDM_FILE_DEC, ICON_EXTRACT, L"解密"},
    {0, -1, nullptr},
    {IDM_TOOLS_INFO, ICON_INFO, L"信息"},
    {IDM_TOOLS_GENKEY, ICON_KEY, L"随机密钥"},
    {IDM_TOOLS_TEST, ICON_TEST, L"测试"},
    {0, -1, nullptr},
    {IDM_HELP_ABOUT, ICON_ABOUT, L"关于"},
};
const int TB_COUNT = (int)(sizeof(TB_ITEMS) / sizeof(TB_ITEMS[0]));

struct TbSlot {
    int index;  // TB_ITEMS 下标
    RECT rc;
};

std::vector<TbSlot> g_tbSlots;  // 布局结果（创建时按 DPI 算一次）
HWND g_hTip = nullptr;          // 工具提示

bool commandEnabled(int id);
void setStatusPanes(const std::wstring& a, const std::wstring& b, const std::wstring& c);

// 按当前 DPI 与字体度量算出每个按钮的矩形（只在创建工具栏前调用一次）
void tbComputeLayout(HDC dc) {
    g_tbSlots.clear();
    HGDIOBJ old = SelectObject(dc, g_hFont);
    const int padX = S(7), gap = S(6), btnH = S(26), btnY = S(3);

    int x = 0;
    for (int i = 0; i < TB_COUNT; ++i) {
        if (TB_ITEMS[i].icon < 0) {  // 分隔线占宽 1 + 左右间距
            RECT rc{x + 2 * S(5), btnY + S(3), x + 2 * S(5) + 1, btnY + btnH - S(3)};
            g_tbSlots.push_back({i, rc});
            x += 2 * S(5) + 1;
            continue;
        }
        SIZE sz{};
        GetTextExtentPoint32W(dc, TB_ITEMS[i].text, (int)wcslen(TB_ITEMS[i].text), &sz);
        const int w = padX + S(TB_ICON) + gap + sz.cx + padX;
        RECT rc{x, btnY, x + w, btnY + btnH};
        g_tbSlots.push_back({i, rc});
        x += w;
    }
    SelectObject(dc, old);
}

int tbHitTest(int px, int py) {
    for (std::size_t i = 0; i < g_tbSlots.size(); ++i) {
        const TbSlot& s = g_tbSlots[i];
        if (TB_ITEMS[s.index].icon < 0) continue;
        if (px >= s.rc.left && px < s.rc.right && py >= s.rc.top && py < s.rc.bottom)
            return (int)i;
    }
    return -1;
}

void tbPaint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc;
    GetClientRect(hwnd, &rc);

    FillRect(dc, &rc, GetSysColorBrush(COLOR_BTNFACE));
    RECT line{0, rc.bottom - 1, rc.right, rc.bottom};
    FillRect(dc, &line, GetSysColorBrush(COLOR_BTNSHADOW));
    RECT line2{0, rc.bottom - 2, rc.right, rc.bottom - 1};
    FillRect(dc, &line2, GetSysColorBrush(COLOR_BTNHIGHLIGHT));

    HGDIOBJ of = SelectObject(dc, g_hFont);
    SetBkMode(dc, TRANSPARENT);

    for (std::size_t i = 0; i < g_tbSlots.size(); ++i) {
        const TbSlot& s = g_tbSlots[i];
        const TbItem& it = TB_ITEMS[s.index];

        if (it.icon < 0) {  // 分隔线
            RECT l{s.rc.left, s.rc.top, s.rc.left + 1, s.rc.bottom};
            FillRect(dc, &l, GetSysColorBrush(COLOR_BTNSHADOW));
            RECT l2{s.rc.left + 1, s.rc.top, s.rc.left + 2, s.rc.bottom};
            FillRect(dc, &l2, GetSysColorBrush(COLOR_BTNHIGHLIGHT));
            continue;
        }

        const bool dis = !commandEnabled(it.id);
        const bool hot = ((int)i == g_tbHot) && !dis;
        const bool down = ((int)i == g_tbPress) && !dis;

        RECT r = s.rc;
        if (down) {
            DrawEdge(dc, &r, BDR_SUNKENOUTER, BF_RECT);
            r.left += 1;
            r.top += 1;
        } else if (hot) {
            DrawEdge(dc, &r, BDR_RAISEDINNER, BF_RECT);
        }

        RECT ic{r.left + S(5), r.top + (r.bottom - r.top - S(TB_ICON)) / 2,
                r.left + S(5) + S(TB_ICON), r.top + (r.bottom - r.top - S(TB_ICON)) / 2 + S(TB_ICON)};
        drawIconShape(dc, it.icon, ic, GetSysColor(COLOR_BTNFACE), dis);

        RECT tr{ic.right + S(6), r.top, r.right, r.bottom};
        SetTextColor(dc, GetSysColor(dis ? COLOR_GRAYTEXT : COLOR_BTNTEXT));
        DrawTextW(dc, it.text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }

    SelectObject(dc, of);
    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK tbProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g_hTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                     WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT,
                                     CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, nullptr,
                                     g_hInst, nullptr);
            if (g_hTip) {
                SetWindowPos(g_hTip, HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                for (std::size_t i = 0; i < g_tbSlots.size(); ++i) {
                    const TbSlot& s = g_tbSlots[i];
                    if (TB_ITEMS[s.index].icon < 0) continue;
                    TOOLINFOW ti{};
                    ti.cbSize = sizeof(ti);
                    ti.uFlags = TTF_SUBCLASS;
                    ti.hwnd = hwnd;
                    ti.uId = (UINT_PTR)i;
                    ti.rect = s.rc;
                    ti.lpszText = (LPWSTR)TB_ITEMS[s.index].text;
                    SendMessageW(g_hTip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
                }
            }
            return 0;
        }

        case WM_GETDLGCODE:
            return DLGC_WANTARROWS;  // 不参与 Tab 焦点轮转

        case WM_MOUSEACTIVATE:
            return MA_NOACTIVATE;  // 点工具栏不抢走输入框焦点

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
            tbPaint(hwnd);
            return 0;

        case WM_MOUSEMOVE: {
            const int i = tbHitTest(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
            if (i != g_tbHot) {
                g_tbHot = i;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            if (!g_tbTracking) {
                TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, hwnd, 0};
                TrackMouseEvent(&tme);
                g_tbTracking = true;
            }
            return 0;
        }

        case WM_MOUSELEAVE:
            g_tbTracking = false;
            if (g_tbHot >= 0) {
                g_tbHot = -1;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;

        case WM_LBUTTONDOWN: {
            const int i = tbHitTest(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
            if (i >= 0 && commandEnabled(TB_ITEMS[g_tbSlots[(std::size_t)i].index].id)) {
                g_tbPress = i;
                SetCapture(hwnd);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        }

        case WM_LBUTTONUP: {
            const int press = g_tbPress;
            g_tbPress = -1;
            if (GetCapture() == hwnd) ReleaseCapture();
            InvalidateRect(hwnd, nullptr, FALSE);
            if (press >= 0) {
                const int i = tbHitTest(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
                const int cmd = TB_ITEMS[g_tbSlots[(std::size_t)press].index].id;
                if (i == press && commandEnabled(cmd)) {
                    PostMessageW(GetParent(hwnd), WM_COMMAND, MAKEWPARAM((WORD)cmd, 0),
                                 (LPARAM)hwnd);
                }
            }
            return 0;
        }

        case WM_DESTROY:
            if (g_hTip) {
                DestroyWindow(g_hTip);
                g_hTip = nullptr;
            }
            return 0;

        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void registerToolBarClass(HINSTANCE hInst) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = tbProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"TdesToolBar";
    RegisterClassExW(&wc);
}

// ============================ 日志与状态栏 ============================

// 日志框设为只读，所以通过整体重设文本 + 滚动到底部来追加
void appendLog(const std::wstring& text) {
    if (!g_hLog) return;
    g_logBuffer += crlf(text);
    g_logBuffer += L"\r\n";
    SetWindowTextW(g_hLog, g_logBuffer.c_str());
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

std::wstring g_statMsg     = L"就绪：选择文件 → 加密 / 解密";
std::uint64_t g_sizeAll    = 0;  // 当前目录内文件总大小
std::uint64_t g_sizeSel    = 0;  // 已选中项总大小
int g_countAll             = 0;  // 当前目录内项目数

void setStatusPanes(const std::wstring& a, const std::wstring& b, const std::wstring& c) {
    if (!g_hStatus) return;
    SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)a.c_str());
    SendMessageW(g_hStatus, SB_SETTEXTW, 1, (LPARAM)b.c_str());
    SendMessageW(g_hStatus, SB_SETTEXTW, 2, (LPARAM)c.c_str());
}

void updateStatus() {
    const std::wstring a = std::to_wstring(g_countAll) + L" 个对象";
    std::wstring b;
    if (g_sizeSel > 0) b = L"已选择 " + groupDigits(g_sizeSel) + L" 字节";
    else b = groupDigits(g_sizeAll) + L" 字节";
    setStatusPanes(a, b, g_statMsg);
}

void setStatus(const std::wstring& msg) {
    g_statMsg = msg;
    updateStatus();
}

void showError(HWND hwnd, const std::wstring& text) {
    MessageBoxW(hwnd, text.c_str(), L"错误", MB_OK | MB_ICONERROR);
}

void showInfo(HWND hwnd, const std::wstring& text) {
    MessageBoxW(hwnd, text.c_str(), L"提示", MB_OK | MB_ICONINFORMATION);
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

// ============================ 文件列表（7-Zip 的“文件列表”区） ============================

struct FileEntry {
    std::wstring name;
    std::wstring full;
    std::uint64_t size = 0;
    FILETIME mtime{};
    DWORD attrs = 0;
    bool isDir = false;
};
std::vector<FileEntry> g_entries;

const int MAX_ENTRIES = 3000;  // 目录过大时只显示前若干项，避免界面卡顿

bool entryLess(const FileEntry& a, const FileEntry& b) {
    if (a.isDir != b.isDir) return a.isDir;  // 文件夹恒在前
    int c = 0;
    switch (g_sortCol) {
        case 1:
            c = (a.size < b.size) ? -1 : (a.size > b.size ? 1 : 0);
            break;
        case 2:
            c = CompareFileTime(&a.mtime, &b.mtime);
            break;
        case 3:
            c = _wcsicmp(attrString(a.attrs, a.isDir).c_str(), attrString(b.attrs, b.isDir).c_str());
            break;
        case 4:
            c = _wcsicmp(typeString(a.name, a.isDir).c_str(), typeString(b.name, b.isDir).c_str());
            break;
        default:
            c = _wcsicmp(a.name.c_str(), b.name.c_str());
            break;
    }
    if (c == 0) c = _wcsicmp(a.name.c_str(), b.name.c_str());
    return g_sortAsc ? (c < 0) : (c > 0);
}

void initListView() {
    ListView_SetExtendedListViewStyle(
        g_hList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP | LVS_EX_LABELTIP);

    struct Col {
        const wchar_t* text;
        int w;
        int fmt;
    };
    const Col cols[] = {
        {L"名称", 260, LVCFMT_LEFT},  {L"大小", 92, LVCFMT_RIGHT}, {L"修改日期", 138, LVCFMT_LEFT},
        {L"属性", 60, LVCFMT_LEFT},   {L"类型", 130, LVCFMT_LEFT},
    };
    for (int i = 0; i < (int)(sizeof(cols) / sizeof(cols[0])); ++i) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM;
        c.pszText = (LPWSTR)cols[i].text;
        c.cx = S(cols[i].w);
        c.fmt = cols[i].fmt;
        c.iSubItem = i;
        ListView_InsertColumn(g_hList, i, &c);
    }

    // 小图标：文件夹 / 文件 / 加密文件（全部由 GDI 现场绘制后转成 HICON）
    const int cx = GetSystemMetrics(SM_CXSMICON);
    const int cy = GetSystemMetrics(SM_CYSMICON);
    g_hImlSmall = ImageList_Create(cx, cy, ILC_COLOR32 | ILC_MASK, 4, 4);
    const int kinds[3] = {ICON_FOLDER, ICON_FILE, ICON_CIPHER};
    for (int k : kinds) {
        HICON ic = makeIcon(k, cx, cy);
        if (ic) {
            ImageList_AddIcon(g_hImlSmall, ic);
            DestroyIcon(ic);
        }
    }
    ListView_SetImageList(g_hList, g_hImlSmall, LVSIL_SMALL);
}

void fillListItems() {
    if (!g_hList) return;
    SendMessageW(g_hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hList);

    int row = 0;
    if (g_hasUp) {
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_IMAGE;
        it.iItem = row;
        it.iImage = IMG_FOLDER;
        it.pszText = (LPWSTR)L"..";
        ListView_InsertItem(g_hList, &it);
        ListView_SetItemText(g_hList, row, 4, (LPWSTR)L"向上一级");
        ++row;
    }

    for (const FileEntry& e : g_entries) {
        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_IMAGE;
        it.iItem = row;
        it.iImage = e.isDir ? IMG_FOLDER : (isCipherName(e.name) ? IMG_CIPHER : IMG_FILE);
        it.pszText = (LPWSTR)e.name.c_str();
        ListView_InsertItem(g_hList, &it);

        const std::wstring sz = e.isDir ? std::wstring(L"<文件夹>") : groupDigits(e.size);
        ListView_SetItemText(g_hList, row, 1, (LPWSTR)sz.c_str());
        const std::wstring tm = formatTime(e.mtime);
        ListView_SetItemText(g_hList, row, 2, (LPWSTR)tm.c_str());
        const std::wstring at = attrString(e.attrs, e.isDir);
        ListView_SetItemText(g_hList, row, 3, (LPWSTR)at.c_str());
        const std::wstring ty = typeString(e.name, e.isDir);
        ListView_SetItemText(g_hList, row, 4, (LPWSTR)ty.c_str());
        ++row;
    }

    SendMessageW(g_hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hList, nullptr, TRUE);
}

// 在列表里高亮当前的输入文件
void selectInputInList() {
    if (!g_hList || g_inputFile.empty()) return;
    const std::wstring nm = fileName(g_inputFile);
    for (int i = 0; i < (int)g_entries.size(); ++i) {
        if (_wcsicmp(g_entries[(std::size_t)i].name.c_str(), nm.c_str()) == 0) {
            const int r = g_hasUp ? i + 1 : i;
            ListView_SetItemState(g_hList, r, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(g_hList, r, FALSE);
            return;
        }
    }
}

void updateSelSize() {
    std::uint64_t total = 0;
    if (g_hList) {
        for (int i = 0; i < (int)g_entries.size(); ++i) {
            const int r = g_hasUp ? i + 1 : i;
            if (ListView_GetItemState(g_hList, r, LVIS_SELECTED) & LVIS_SELECTED) {
                const FileEntry& e = g_entries[(std::size_t)i];
                if (!e.isDir) total += e.size;
            }
        }
    }
    g_sizeSel = total;
    updateStatus();
}

// 切换文件列表显示的目录
void refreshFileList(const std::wstring& dir);
void setInputFile(const std::wstring& path, bool report);

void listActivate(int idx) {
    if (idx < 0) return;
    if (g_hasUp && idx == 0) {
        if (!isRootDir(g_curDir)) refreshFileList(parentDir(g_curDir));
        return;
    }
    const int e = g_hasUp ? idx - 1 : idx;
    if (e < 0 || e >= (int)g_entries.size()) return;
    const FileEntry& fe = g_entries[(std::size_t)e];
    if (fe.isDir) {
        refreshFileList(fe.full);
        return;
    }
    setInputFile(fe.full, true);
}

void setInputFile(const std::wstring& path, bool report) {
    g_inputFile = path;
    g_lastOut[0].clear();  // 换了输入文件，输出名回到默认推导
    g_lastOut[1].clear();
    selectInputInList();
    if (report) setStatus(L"已选择：" + fileName(path));
    // 目标文件变化后工具栏可用状态可能改变
    if (g_hToolBar) InvalidateRect(g_hToolBar, nullptr, FALSE);
}

void refreshFileList(const std::wstring& dir) {
    if (!dir.empty()) g_curDir = dir;
    if (g_curDir.empty()) g_curDir = fullPath(L".");

    // 地址栏与下拉列表跟随
    if (g_hAddr) {
        g_addrBusy = true;
        SetWindowTextW(g_hAddr, g_curDir.c_str());
        // SetWindowText 会连带把文本整体选中，收起选区避免“蓝块”
        SendMessageW(g_hAddr, CB_SETEDITSEL, 0, MAKELPARAM(0, 0));
        g_addrBusy = false;
    }
    if (g_hAddr) {
        // 下拉列表 = 目录层级（仿资源管理器地址栏）
        std::vector<std::wstring> items;
        std::wstring d = g_curDir;
        while (true) {
            items.push_back(d);
            if (isRootDir(d)) break;
            const std::wstring par = parentDir(d);
            if (par == d || par.empty()) break;
            d = par;
        }
        g_addrBusy = true;
        SendMessageW(g_hAddr, CB_RESETCONTENT, 0, 0);
        for (auto it = items.rbegin(); it != items.rend(); ++it) {
            SendMessageW(g_hAddr, CB_ADDSTRING, 0, (LPARAM)it->c_str());
        }
        SetWindowTextW(g_hAddr, g_curDir.c_str());
        SendMessageW(g_hAddr, CB_SETEDITSEL, 0, MAKELPARAM(0, 0));
        g_addrBusy = false;
    }

    g_entries.clear();
    g_listFull = false;
    g_hasUp = !isRootDir(g_curDir);

    const std::wstring pat = joinPath(g_curDir, L"*");
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            const std::wstring nm = fd.cFileName;
            if (nm == L"." || nm == L"..") continue;
            FileEntry e;
            e.name = nm;
            e.isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            e.attrs = fd.dwFileAttributes;
            e.mtime = fd.ftLastWriteTime;
            e.size = ((std::uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            e.full = joinPath(g_curDir, nm);
            g_entries.push_back(e);
            if ((int)g_entries.size() >= MAX_ENTRIES) {
                g_listFull = true;
                break;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    std::sort(g_entries.begin(), g_entries.end(), entryLess);
    g_countAll = (int)g_entries.size();
    g_sizeAll = 0;
    for (const FileEntry& e : g_entries) {
        if (!e.isDir) g_sizeAll += e.size;
    }

    fillListItems();
    selectInputInList();
    g_sizeSel = 0;
    updateStatus();

    if (g_listFull) setStatus(L"目录内项目过多，只显示前 " + std::to_wstring(MAX_ENTRIES) + L" 项");
}

// ============================ 地址栏 ============================

void commitAddress(HWND hwnd, bool report) {
    if (g_addrBusy) return;
    const std::wstring p = trim(getText(g_hAddr));
    if (p.empty()) return;
    const DWORD a = GetFileAttributesW(p.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) {
        if (report) showError(hwnd, L"路径不存在：\n" + p);
        return;
    }
    if ((a & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        refreshFileList(fullPath(p));
    } else {
        setInputFile(fullPath(p), report);
        refreshFileList(parentDir(fullPath(p)));
        selectInputInList();
    }
}

// ============================ 命令可用性 & 工具提示 ============================

bool commandEnabled(int id) {
    const bool hasFile = !g_inputFile.empty() && fileExists(g_inputFile);
    switch (id) {
        case IDM_FILE_ENC:
        case IDM_FILE_DEC:
            return hasFile;
        case IDM_TOOLS_INFO:
            return hasFile || !g_curDir.empty();
        case IDM_EDIT_COPYPATH:
            return hasFile;
        case IDM_EDIT_CLEARLOG:
            return !g_logBuffer.empty();
        case IDM_VIEW_REFRESH:
            return !g_curDir.empty();
        default:
            return true;
    }
}

// ============================ 加解密动作 ============================

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

struct OpParams {
    std::wstring in;
    std::wstring out;
    std::wstring keyHex;
    std::vector<std::uint8_t> key;
    tdes::Alg alg = tdes::Alg::TDES3;
    tdes::Mode mode = tdes::Mode::CBC;
    bool overwriteConfirm = true;
    bool decrypt = false;
};

// 输出路径的基本校验：目录存在，且不与输入文件是同一个文件
bool checkOutputPath(HWND hwnd, const std::wstring& in, const std::wstring& out) {
    const std::wstring dir = parentDir(out);
    if (!dirExists(dir)) {
        showError(hwnd, L"输出目录不存在：\n" + dir + L"\n\n请在对话框里重新指定输出文件。");
        setStatus(L"输出目录不存在，操作已取消");
        return false;
    }
    if (samePath(in, out)) {
        showError(hwnd, L"输出文件不能与输入文件相同：\n" + out + L"\n\n请换一个输出文件名。");
        setStatus(L"输出文件与输入文件相同，操作已取消");
        return false;
    }
    return true;
}

bool runOperation(HWND hwnd, const OpParams& p) {
    if (!checkOutputPath(hwnd, p.in, p.out)) return false;
    if (fileExists(p.out) && p.overwriteConfirm) {
        if (msgYesNo(hwnd, L"输出文件已存在：\n" + p.out + L"\n\n是否覆盖？") != IDYES) {
            setStatus(L"已取消（输出文件已存在）");
            return false;
        }
    }

    tdes::Params tp;
    tp.alg = p.alg;
    tp.mode = p.mode;
    tdes::Params used = tp;
    tdes::FileResult res;
    std::string err;

    const auto t0 = std::chrono::steady_clock::now();
    const bool ok =
        p.decrypt ? tdes::decryptFile(wideToUtf8(p.in), wideToUtf8(p.out), p.key, tp, used, res, err)
                  : tdes::encryptFile(wideToUtf8(p.in), wideToUtf8(p.out), p.key, tp, res, err);
    const auto t1 = std::chrono::steady_clock::now();
    const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (!ok) {
        appendLog((p.decrypt ? L"[解密失败] " : L"[加密失败] ") + utf8ToWide(err));
        std::wstring msg = (p.decrypt ? L"解密失败：\n" : L"加密失败：\n") + utf8ToWide(err);
        if (p.decrypt) msg += L"\n\n常见原因：密钥不正确，或该文件不是本工具生成的密文。";
        showError(hwnd, msg);
        setStatus(p.decrypt ? L"解密失败" : L"加密失败");
        return false;
    }

    reportSuccess(p.decrypt ? L"解密" : L"加密", used, res, p.out, ms);
    g_lastOut[p.decrypt ? 1 : 0] = p.out;
    refreshFileList(g_curDir);  // 结果可能就落在当前目录，刷新一下
    return true;
}

// ============================ 内存对话框模板（DLGTEMPLATE） ============================
// Windows 的对话框模板是若干 DWORD 对齐的变长结构。这里手工拼装，就能像 .rc 一样用
// DialogBoxIndirectParamW 弹出标准 #32770 对话框，而完全不需要资源编译器。
//   控件类原子：BUTTON=0x0080 EDIT=0x0081 STATIC=0x0082 LISTBOX=0x0083 COMBOBOX=0x0085

class DlgTpl {
public:
    // 关键点：DLGTEMPLATE / DLGITEMTEMPLATE 在内存布局里分别是 18 字节，
    // 但 C 结构体因 4 字节对齐会被 sizeof 补到 20 字节 —— 若照 sizeof 拼装，
    // 后面的菜单/类名/标题会整体后移 2 字节，模板即被解释成垃圾。
    static const std::size_t HDR = 18;

    DlgTpl(DWORD style, DWORD exStyle, short cx, short cy, const wchar_t* title, WORD ptSize,
           const wchar_t* face) {
        m_buf.resize(HDR);
        auto* t = (DLGTEMPLATE*)m_buf.data();
        t->style = style;
        t->dwExtendedStyle = exStyle;
        t->cdit = 0;
        t->x = 0;
        t->y = 0;
        t->cx = cx;
        t->cy = cy;
        putWord(0x0000);  // 无菜单
        putWord(0x0000);  // 默认窗口类
        putStr(title);
        if (style & DS_SETFONT) {
            putWord(ptSize);
            putStr(face);
        }
    }

    void item(DWORD style, short x, short y, short cx, short cy, WORD id, WORD cls,
              const wchar_t* text) {
        align4();
        const std::size_t at = m_buf.size();
        m_buf.resize(at + HDR);
        auto* it = (DLGITEMTEMPLATE*)(m_buf.data() + at);
        it->style = style | WS_CHILD | WS_VISIBLE;
        it->dwExtendedStyle = 0;
        it->x = x;
        it->y = y;
        it->cx = cx;
        it->cy = cy;
        it->id = id;
        putWord(0xFFFF);
        putWord(cls);
        putStr(text);
        putWord(0x0000);  // 无创建数据
        ++((DLGTEMPLATE*)m_buf.data())->cdit;
    }

    void sep(short x, short y, short cx) { item(SS_ETCHEDHORZ, x, y, cx, 1, (WORD)-1, 0x0082, L""); }

    DLGTEMPLATE* data() { return (DLGTEMPLATE*)m_buf.data(); }

private:
    std::vector<BYTE> m_buf;
    void align4() {
        while (m_buf.size() % 4) m_buf.push_back(0);
    }
    void putWord(WORD v) {
        m_buf.push_back((BYTE)(v & 0xFF));
        m_buf.push_back((BYTE)(v >> 8));
    }
    void putStr(const wchar_t* s) {
        if (s)
            for (const wchar_t* q = s; *q; ++q) putWord((WORD)*q);
        putWord(0x0000);
    }
};

const wchar_t* DLG_FACE = L"Microsoft YaHei";

void updateEncHint(HWND d) {
    const int sel = (int)SendDlgItemMessageW(d, IDC_ENC_ALG, CB_GETCURSEL, 0, 0);
    const std::size_t n = tdes::keyBytes((tdes::Alg)(sel + 1));
    const std::wstring t = L"需要 " + std::to_wstring(n) + L" 字节密钥（" +
                           std::to_wstring(n * 2) + L" 个十六进制字符）";
    SetDlgItemTextW(d, IDC_ENC_HINT, t.c_str());
}

void updateDecHint(HWND d) {
    const std::size_t n = stripSpaces(getText(GetDlgItem(d, IDC_DEC_KEY))).size();
    std::wstring t;
    if (n == 16) t = L"识别为 DES 密钥（8 字节）";
    else if (n == 32) t = L"识别为 3DES-2Key 密钥（16 字节）";
    else if (n == 48) t = L"识别为 3DES-3Key 密钥（24 字节）";
    else if (n == 0) t = L"请输入 16 / 32 / 48 个十六进制字符";
    else t = L"长度 " + std::to_wstring(n) + L" 不是 16/32/48，无法识别算法";
    SetDlgItemTextW(d, IDC_DEC_HINT, t.c_str());
}

struct EncCtx {
    std::wstring in;
    std::wstring out;
    tdes::Alg alg = tdes::Alg::TDES3;
    tdes::Mode mode = tdes::Mode::CBC;
    std::wstring key;
    bool overwriteConfirm = true;
    // 输出
    bool ok = false;
    std::wstring outPath;
    std::wstring keyHex;
    tdes::Alg algOut = tdes::Alg::TDES3;
    tdes::Mode modeOut = tdes::Mode::CBC;
};

INT_PTR CALLBACK encDlgProc(HWND d, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = (EncCtx*)GetWindowLongPtrW(d, GWLP_USERDATA);
    switch (msg) {
        case WM_INITDIALOG: {
            ctx = (EncCtx*)lp;
            SetWindowLongPtrW(d, GWLP_USERDATA, (LONG_PTR)ctx);
            HWND hAlg = GetDlgItem(d, IDC_ENC_ALG);
            SendMessageW(hAlg, CB_ADDSTRING, 0, (LPARAM)L"DES（单 DES，8 字节密钥）");
            SendMessageW(hAlg, CB_ADDSTRING, 0, (LPARAM)L"3DES-2Key（16 字节密钥）");
            SendMessageW(hAlg, CB_ADDSTRING, 0, (LPARAM)L"3DES-3Key（24 字节密钥，推荐）");
            SendMessageW(hAlg, CB_SETCURSEL, (WPARAM)((int)ctx->alg - 1), 0);
            CheckRadioButton(d, IDC_ENC_CBC, IDC_ENC_ECB,
                             ctx->mode == tdes::Mode::ECB ? IDC_ENC_ECB : IDC_ENC_CBC);
            SetDlgItemTextW(d, IDC_ENC_OUT, ctx->out.c_str());
            SetDlgItemTextW(d, IDC_ENC_KEY, ctx->key.c_str());
            SendDlgItemMessageW(d, IDC_ENC_KEY, EM_SETPASSWORDCHAR, (WPARAM)L'\x25CF', 0);
            SendDlgItemMessageW(d, IDC_ENC_KEY, EM_LIMITTEXT, 256, 0);
            CheckDlgButton(d, IDC_ENC_OVERWRITE,
                           ctx->overwriteConfirm ? BST_CHECKED : BST_UNCHECKED);
            updateEncHint(d);
            SetFocus(GetDlgItem(d, IDC_ENC_KEY));
            return FALSE;  // 焦点已自行设置
        }

        case WM_CTLCOLORSTATIC: {
            const int id = GetDlgCtrlID((HWND)lp);
            if (id == IDC_ENC_HINT || id == IDC_ENC_NOTE || id == IDC_DEC_HINT ||
                id == IDC_DEC_NOTE) {
                SetTextColor((HDC)wp, RGB(110, 116, 126));
                SetBkMode((HDC)wp, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_BTNFACE);
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_ENC_ALG:
                    if (HIWORD(wp) == CBN_SELCHANGE) updateEncHint(d);
                    return TRUE;

                case IDC_ENC_GENKEY: {
                    const int sel = (int)SendDlgItemMessageW(d, IDC_ENC_ALG, CB_GETCURSEL, 0, 0);
                    std::vector<std::uint8_t> key;
                    tdes::randomKey((tdes::Alg)(sel + 1), key);
                    SetDlgItemTextW(d, IDC_ENC_KEY, utf8ToWide(tdes::toHex(key)).c_str());
                    return TRUE;
                }

                case IDC_ENC_SHOWKEY: {
                    const bool show = IsDlgButtonChecked(d, IDC_ENC_SHOWKEY) == BST_CHECKED;
                    SendDlgItemMessageW(d, IDC_ENC_KEY, EM_SETPASSWORDCHAR,
                                        show ? 0 : (WPARAM)L'\x25CF', 0);
                    InvalidateRect(GetDlgItem(d, IDC_ENC_KEY), nullptr, TRUE);
                    return TRUE;
                }

                case IDC_ENC_OUT_BROWSE: {
                    std::vector<wchar_t> buf(4096, L'\0');
                    const std::wstring cur = getText(GetDlgItem(d, IDC_ENC_OUT));
                    if (!cur.empty() && cur.size() < buf.size() - 1)
                        std::copy(cur.begin(), cur.end(), buf.begin());
                    OPENFILENAMEW ofn{};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = d;
                    ofn.lpstrFilter = L"加密文件 (*.3des)\0*.3des\0所有文件 (*.*)\0*.*\0\0";
                    ofn.lpstrFile = buf.data();
                    ofn.nMaxFile = (DWORD)buf.size();
                    ofn.lpstrTitle = L"请选择输出文件";
                    ofn.lpstrDefExt = L"3des";
                    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_EXPLORER |
                                OFN_NOCHANGEDIR;
                    if (GetSaveFileNameW(&ofn)) SetDlgItemTextW(d, IDC_ENC_OUT, buf.data());
                    return TRUE;
                }

                case IDOK: {
                    const int sel = (int)SendDlgItemMessageW(d, IDC_ENC_ALG, CB_GETCURSEL, 0, 0);
                    const tdes::Alg alg = (tdes::Alg)(sel + 1);
                    const tdes::Mode mode = IsDlgButtonChecked(d, IDC_ENC_CBC) == BST_CHECKED
                                                ? tdes::Mode::CBC
                                                : tdes::Mode::ECB;

                    const std::wstring keyW = stripSpaces(getText(GetDlgItem(d, IDC_ENC_KEY)));
                    if (keyW.empty()) {
                        showError(d, L"请输入密钥，或点击“随机生成”。");
                        SetFocus(GetDlgItem(d, IDC_ENC_KEY));
                        return TRUE;
                    }
                    std::vector<std::uint8_t> key;
                    std::string err;
                    if (!tdes::parseKeyHex(wideToUtf8(keyW), alg, key, err)) {
                        showError(d, utf8ToWide(err));
                        SetFocus(GetDlgItem(d, IDC_ENC_KEY));
                        return TRUE;
                    }
                    const std::wstring out = trim(getText(GetDlgItem(d, IDC_ENC_OUT)));
                    if (out.empty()) {
                        showError(d, L"请指定输出文件路径。");
                        SetFocus(GetDlgItem(d, IDC_ENC_OUT));
                        return TRUE;
                    }
                    if (!dirExists(parentDir(out))) {
                        showError(d, L"输出目录不存在：\n" + parentDir(out));
                        return TRUE;
                    }
                    if (samePath(ctx->in, out)) {
                        showError(d, L"输出文件不能与输入文件相同，请换一个文件名。");
                        SetFocus(GetDlgItem(d, IDC_ENC_OUT));
                        return TRUE;
                    }

                    ctx->outPath = out;
                    ctx->keyHex = keyW;
                    ctx->algOut = alg;
                    ctx->modeOut = mode;
                    ctx->overwriteConfirm =
                        IsDlgButtonChecked(d, IDC_ENC_OVERWRITE) == BST_CHECKED;
                    ctx->ok = true;
                    EndDialog(d, IDOK);
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(d, IDCANCEL);
                    return TRUE;

                default:
                    break;
            }
            return FALSE;

        default:
            break;
    }
    return FALSE;
}

struct DecCtx {
    std::wstring in;
    std::wstring out;
    std::wstring key;
    bool overwriteConfirm = true;
    bool ok = false;
    std::wstring outPath;
    std::wstring keyHex;
    tdes::Alg algOut = tdes::Alg::TDES3;
};

INT_PTR CALLBACK decDlgProc(HWND d, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = (DecCtx*)GetWindowLongPtrW(d, GWLP_USERDATA);
    switch (msg) {
        case WM_INITDIALOG: {
            ctx = (DecCtx*)lp;
            SetWindowLongPtrW(d, GWLP_USERDATA, (LONG_PTR)ctx);
            SetDlgItemTextW(d, IDC_DEC_OUT, ctx->out.c_str());
            SetDlgItemTextW(d, IDC_DEC_KEY, ctx->key.c_str());
            SendDlgItemMessageW(d, IDC_DEC_KEY, EM_SETPASSWORDCHAR, (WPARAM)L'\x25CF', 0);
            SendDlgItemMessageW(d, IDC_DEC_KEY, EM_LIMITTEXT, 256, 0);
            CheckDlgButton(d, IDC_DEC_OVERWRITE,
                           ctx->overwriteConfirm ? BST_CHECKED : BST_UNCHECKED);
            updateDecHint(d);
            SetFocus(GetDlgItem(d, IDC_DEC_KEY));
            return FALSE;
        }

        case WM_CTLCOLORSTATIC: {
            const int id = GetDlgCtrlID((HWND)lp);
            if (id == IDC_DEC_HINT || id == IDC_DEC_NOTE) {
                SetTextColor((HDC)wp, RGB(110, 116, 126));
                SetBkMode((HDC)wp, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_BTNFACE);
            }
            break;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_DEC_KEY:
                    if (HIWORD(wp) == EN_CHANGE) updateDecHint(d);
                    return TRUE;

                case IDC_DEC_SHOWKEY: {
                    const bool show = IsDlgButtonChecked(d, IDC_DEC_SHOWKEY) == BST_CHECKED;
                    SendDlgItemMessageW(d, IDC_DEC_KEY, EM_SETPASSWORDCHAR,
                                        show ? 0 : (WPARAM)L'\x25CF', 0);
                    InvalidateRect(GetDlgItem(d, IDC_DEC_KEY), nullptr, TRUE);
                    return TRUE;
                }

                case IDC_DEC_OUT_BROWSE: {
                    std::vector<wchar_t> buf(4096, L'\0');
                    const std::wstring cur = getText(GetDlgItem(d, IDC_DEC_OUT));
                    if (!cur.empty() && cur.size() < buf.size() - 1)
                        std::copy(cur.begin(), cur.end(), buf.begin());
                    OPENFILENAMEW ofn{};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = d;
                    ofn.lpstrFilter = L"所有文件 (*.*)\0*.*\0\0";
                    ofn.lpstrFile = buf.data();
                    ofn.nMaxFile = (DWORD)buf.size();
                    ofn.lpstrTitle = L"请选择解密结果的输出文件";
                    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_EXPLORER |
                                OFN_NOCHANGEDIR;
                    if (GetSaveFileNameW(&ofn)) SetDlgItemTextW(d, IDC_DEC_OUT, buf.data());
                    return TRUE;
                }

                case IDOK: {
                    const std::wstring keyW = stripSpaces(getText(GetDlgItem(d, IDC_DEC_KEY)));
                    if (keyW.empty()) {
                        showError(d, L"请输入解密密钥。");
                        SetFocus(GetDlgItem(d, IDC_DEC_KEY));
                        return TRUE;
                    }
                    // 解密时算法由密钥长度推断（真正的算法/模式/IV 记录在密文文件头里）
                    tdes::Alg alg = tdes::Alg::TDES3;
                    if (keyW.size() == 16) alg = tdes::Alg::DES;
                    else if (keyW.size() == 32) alg = tdes::Alg::TDES2;
                    else if (keyW.size() == 48) alg = tdes::Alg::TDES3;
                    std::vector<std::uint8_t> key;
                    std::string err;
                    if (!tdes::parseKeyHex(wideToUtf8(keyW), alg, key, err)) {
                        showError(d, utf8ToWide(err));
                        SetFocus(GetDlgItem(d, IDC_DEC_KEY));
                        return TRUE;
                    }
                    const std::wstring out = trim(getText(GetDlgItem(d, IDC_DEC_OUT)));
                    if (out.empty()) {
                        showError(d, L"请指定输出文件路径。");
                        SetFocus(GetDlgItem(d, IDC_DEC_OUT));
                        return TRUE;
                    }
                    if (!dirExists(parentDir(out))) {
                        showError(d, L"输出目录不存在：\n" + parentDir(out));
                        return TRUE;
                    }
                    if (samePath(ctx->in, out)) {
                        showError(d, L"输出文件不能与输入文件相同，请换一个文件名。");
                        SetFocus(GetDlgItem(d, IDC_DEC_OUT));
                        return TRUE;
                    }

                    ctx->outPath = out;
                    ctx->keyHex = keyW;
                    ctx->algOut = alg;
                    ctx->overwriteConfirm =
                        IsDlgButtonChecked(d, IDC_DEC_OVERWRITE) == BST_CHECKED;
                    ctx->ok = true;
                    EndDialog(d, IDOK);
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(d, IDCANCEL);
                    return TRUE;

                default:
                    break;
            }
            return FALSE;

        default:
            break;
    }
    return FALSE;
}

// ------------------------ 通用文本信息对话框（“信息/使用说明”） ------------------------

struct TxtCtx {
    std::wstring text;
};

INT_PTR CALLBACK txtDlgProc(HWND d, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_INITDIALOG: {
            auto* ctx = (TxtCtx*)lp;
            SetWindowLongPtrW(d, GWLP_USERDATA, (LONG_PTR)ctx);
            SetDlgItemTextW(d, IDC_TXT_EDIT, crlf(ctx->text).c_str());
            SendDlgItemMessageW(d, IDC_TXT_EDIT, EM_SETSEL, 0, 0);  // 不要默认全选
            // 自行设置焦点：若返回 TRUE，对话框管理器会把焦点给第一个控件，
            // 而“聚焦 EDIT 会自动全选”，整块蓝色反显不好看
            SetFocus(GetDlgItem(d, IDOK));
            return FALSE;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_TXT_COPY: {
                    HWND h = GetDlgItem(d, IDC_TXT_EDIT);
                    const int len = GetWindowTextLengthW(h);
                    if (len <= 0) return TRUE;
                    std::vector<wchar_t> buf((std::size_t)len + 1, L'\0');
                    GetWindowTextW(h, buf.data(), len + 1);
                    if (OpenClipboard(d)) {
                        EmptyClipboard();
                        const std::size_t bytes = ((std::size_t)len + 1) * sizeof(wchar_t);
                        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
                        if (hg) {
                            void* dst = GlobalLock(hg);
                            if (dst) {
                                memcpy(dst, buf.data(), bytes);
                                GlobalUnlock(hg);
                                if (SetClipboardData(CF_UNICODETEXT, hg)) hg = nullptr;
                            }
                            if (hg) GlobalFree(hg);
                        }
                        CloseClipboard();
                    }
                    return TRUE;
                }
                case IDOK:
                case IDCANCEL:
                    EndDialog(d, IDOK);
                    return TRUE;
                default:
                    break;
            }
            return FALSE;

        default:
            break;
    }
    return FALSE;
}

void showTextDialog(HWND owner, const wchar_t* title, const std::wstring& text) {
    DlgTpl tpl(DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT, 0, 300, 190, title,
               9, DLG_FACE);
    tpl.item(ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER | WS_TABSTOP, 7, 7,
             286, 150, IDC_TXT_EDIT, 0x0081, L"");
    tpl.item(BS_PUSHBUTTON | WS_TABSTOP, 7, 165, 78, 15, IDC_TXT_COPY, 0x0080,
             L"复制到剪贴板");
    tpl.item(BS_DEFPUSHBUTTON | WS_TABSTOP, 237, 165, 56, 15, IDOK, 0x0080, L"确定");

    TxtCtx ctx{text};
    DialogBoxIndirectParamW(g_hInst, tpl.data(), owner, txtDlgProc, (LPARAM)&ctx);
}

// ------------------------------ 两个业务对话框的封装 ------------------------------

// 本次操作的目标文件：优先取文件列表里选中的那一行，否则用“当前输入文件”
std::wstring selectedTarget() {
    if (g_hList) {
        const int sel = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);
        const int e = g_hasUp ? sel - 1 : sel;
        if (e >= 0 && e < (int)g_entries.size() && !g_entries[(std::size_t)e].isDir)
            return g_entries[(std::size_t)e].full;
    }
    return g_inputFile;
}

void cmdEncrypt(HWND hwnd) {
    const std::wstring target = selectedTarget();
    if (target.empty() || !fileExists(target)) {
        showInfo(hwnd, L"请先在文件列表里选择一个文件（或用“打开”按钮）。");
        return;
    }

    EncCtx ctx;
    ctx.in = target;
    ctx.out = g_lastOut[0].empty() ? defaultEncryptOut(target) : g_lastOut[0];
    ctx.alg = tdes::Alg::TDES3;
    ctx.mode = tdes::Mode::CBC;
    ctx.key = g_sessionKey;  // 本次运行内复用上次的密钥（不落盘）

    DlgTpl tpl(DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT, 0, 336, 158,
               L"添加到加密包", 9, DLG_FACE);
    tpl.item(SS_LEFT, 7, 10, 36, 10, (WORD)-1, 0x0082, L"加密到:");
    tpl.item(ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 45, 8, 224, 14, IDC_ENC_OUT, 0x0081,
             L"");
    tpl.item(BS_PUSHBUTTON | WS_TABSTOP, 274, 8, 55, 14, IDC_ENC_OUT_BROWSE, 0x0080, L"浏览…");
    tpl.sep(5, 28, 326);
    tpl.item(SS_LEFT, 7, 36, 36, 10, (WORD)-1, 0x0082, L"加密格式:");
    tpl.item(CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP, 45, 34, 116, 90, IDC_ENC_ALG, 0x0085,
             L"");
    tpl.item(SS_LEFT, 170, 36, 40, 10, (WORD)-1, 0x0082, L"工作模式:");
    tpl.item(BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 212, 34, 40, 11, IDC_ENC_CBC, 0x0080,
             L"CBC");
    tpl.item(BS_AUTORADIOBUTTON | WS_TABSTOP, 256, 34, 40, 11, IDC_ENC_ECB, 0x0080, L"ECB");
    tpl.item(SS_LEFT, 7, 57, 36, 10, (WORD)-1, 0x0082, L"密钥:");
    tpl.item(ES_PASSWORD | ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 45, 55, 224, 14, IDC_ENC_KEY,
             0x0081, L"");
    tpl.item(BS_PUSHBUTTON | WS_TABSTOP, 274, 55, 55, 14, IDC_ENC_GENKEY, 0x0080, L"随机生成");
    tpl.item(SS_LEFT, 45, 72, 284, 10, IDC_ENC_HINT, 0x0082, L"");
    tpl.item(BS_AUTOCHECKBOX | WS_TABSTOP, 45, 86, 52, 11, IDC_ENC_SHOWKEY, 0x0080, L"显示密钥");
    tpl.item(BS_AUTOCHECKBOX | WS_TABSTOP, 108, 86, 130, 11, IDC_ENC_OVERWRITE, 0x0080,
             L"覆盖已有文件前先确认");
    tpl.sep(5, 101, 326);
    tpl.item(SS_LEFT, 7, 105, 322, 22, IDC_ENC_NOTE, 0x0082,
             L"使用 CBC 模式时每次都会随机生成初始向量并写入密文文件头，"
             L"解密时自动读取，无需手工记录。");
    tpl.item(BS_DEFPUSHBUTTON | WS_TABSTOP, 216, 134, 55, 16, IDOK, 0x0080, L"确定");
    tpl.item(BS_PUSHBUTTON | WS_TABSTOP, 274, 134, 55, 16, IDCANCEL, 0x0080, L"取消");

    if (DialogBoxIndirectParamW(g_hInst, tpl.data(), hwnd, encDlgProc, (LPARAM)&ctx) != IDOK ||
        !ctx.ok) {
        setStatus(L"已取消加密");
        return;
    }

    g_sessionKey = ctx.keyHex;

    OpParams p;
    p.in = ctx.in;
    p.out = ctx.outPath;
    p.keyHex = ctx.keyHex;
    p.alg = ctx.algOut;
    p.mode = ctx.modeOut;
    p.overwriteConfirm = ctx.overwriteConfirm;
    p.decrypt = false;
    std::string err;
    // 密钥在对话框里已校验过，这里理论上不会失败
    if (!tdes::parseKeyHex(wideToUtf8(p.keyHex), p.alg, p.key, err)) return;
    runOperation(hwnd, p);
}

void cmdDecrypt(HWND hwnd) {
    const std::wstring target = selectedTarget();
    if (target.empty() || !fileExists(target)) {
        showInfo(hwnd, L"请先在文件列表里选择一个文件（或用“打开”按钮）。");
        return;
    }

    DecCtx ctx;
    ctx.in = target;
    ctx.out = g_lastOut[1].empty() ? defaultDecryptOut(target) : g_lastOut[1];
    ctx.key = g_sessionKey;

    DlgTpl tpl(DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT, 0, 306, 136,
               L"解密到…", 9, DLG_FACE);
    tpl.item(SS_LEFT, 7, 10, 36, 10, (WORD)-1, 0x0082, L"解密到:");
    tpl.item(ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 45, 8, 194, 14, IDC_DEC_OUT, 0x0081, L"");
    tpl.item(BS_PUSHBUTTON | WS_TABSTOP, 244, 8, 55, 14, IDC_DEC_OUT_BROWSE, 0x0080, L"浏览…");
    tpl.sep(5, 28, 296);
    tpl.item(SS_LEFT, 7, 37, 36, 10, (WORD)-1, 0x0082, L"密钥:");
    tpl.item(ES_PASSWORD | ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP, 45, 35, 194, 14, IDC_DEC_KEY,
             0x0081, L"");
    tpl.item(BS_AUTOCHECKBOX | WS_TABSTOP, 244, 37, 55, 11, IDC_DEC_SHOWKEY, 0x0080, L"显示密钥");
    tpl.item(SS_LEFT, 45, 53, 254, 10, IDC_DEC_HINT, 0x0082, L"");
    tpl.item(BS_AUTOCHECKBOX | WS_TABSTOP, 45, 68, 130, 11, IDC_DEC_OVERWRITE, 0x0080,
             L"覆盖已有文件前先确认");
    tpl.sep(5, 84, 296);
    tpl.item(SS_LEFT, 7, 88, 292, 20, IDC_DEC_NOTE, 0x0082,
             L"算法、工作模式与 IV 都保存在密文文件头中，此处只需提供密钥。");
    tpl.item(BS_DEFPUSHBUTTON | WS_TABSTOP, 186, 114, 55, 16, IDOK, 0x0080, L"确定");
    tpl.item(BS_PUSHBUTTON | WS_TABSTOP, 244, 114, 55, 16, IDCANCEL, 0x0080, L"取消");

    if (DialogBoxIndirectParamW(g_hInst, tpl.data(), hwnd, decDlgProc, (LPARAM)&ctx) != IDOK ||
        !ctx.ok) {
        setStatus(L"已取消解密");
        return;
    }

    g_sessionKey = ctx.keyHex;

    OpParams p;
    p.in = ctx.in;
    p.out = ctx.outPath;
    p.keyHex = ctx.keyHex;
    p.alg = ctx.algOut;
    p.mode = tdes::Mode::CBC;  // 非 raw 模式下以文件头为准，这里仅作占位
    p.overwriteConfirm = ctx.overwriteConfirm;
    p.decrypt = true;
    std::string err;
    if (!tdes::parseKeyHex(wideToUtf8(p.keyHex), p.alg, p.key, err)) {
        showError(hwnd, utf8ToWide(err));
        return;
    }
    runOperation(hwnd, p);
}

// ============================ 信息 / 自检 / 关于 ============================

// 解析密文自描述文件头（算法 / 模式 / IV / 原始长度）
struct CipherInfo {
    bool ok = false;
    int alg = 0;
    int mode = 0;
    std::uint8_t iv[tdes::IV_SIZE]{};
    std::uint64_t origSize = 0;
    std::uint64_t fileSize = 0;
};

CipherInfo readCipherInfo(const std::wstring& path) {
    CipherInfo ci;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return ci;
    LARGE_INTEGER sz{};
    if (GetFileSizeEx(h, &sz)) ci.fileSize = (std::uint64_t)sz.QuadPart;
    BYTE buf[tdes::HEADER_SIZE]{};
    DWORD rd = 0;
    if (ReadFile(h, buf, (DWORD)tdes::HEADER_SIZE, &rd, nullptr) && rd == tdes::HEADER_SIZE &&
        buf[0] == 'T' && buf[1] == 'D' && buf[2] == 'S' && buf[3] == '1') {
        ci.ok = true;
        ci.alg = buf[tdes::OFF_ALG];
        ci.mode = buf[tdes::OFF_MODE];
        std::copy(buf + tdes::OFF_IV, buf + tdes::OFF_IV + tdes::IV_SIZE, ci.iv);
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | buf[tdes::OFF_SIZE + i];
        ci.origSize = v;
    }
    CloseHandle(h);
    return ci;
}

std::wstring algText(int a) {
    switch (a) {
        case 1: return L"DES（单 DES）";
        case 2: return L"3DES-2Key";
        case 3: return L"3DES-3Key";
        default: return L"未知";
    }
}

std::wstring modeText(int m) {
    switch (m) {
        case 1: return L"ECB（电子密码本）";
        case 2: return L"CBC（密码分组链接）";
        default: return L"未知";
    }
}

// 仿 7-Zip 的“信息”窗口排版：标签按显示宽度补齐，冒号对齐
std::wstring field(const wchar_t* label, const std::wstring& value) {
    std::wstring l = label;
    int width = 0;
    for (wchar_t c : l) width += (c > 0x2000) ? 2 : 1;  // 汉字按两个半角宽计
    while (width < 10) {
        l += L' ';
        ++width;
    }
    return l + L" : " + value + L"\n";
}

std::wstring buildFileInfo(const std::wstring& path) {
    if (path.empty() || !fileExists(path)) return L"未选择文件。";
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return L"无法读取文件属性。";
    const std::uint64_t size = ((std::uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    const bool isDir = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

    std::wstring s;
    s += field(L"名称", fileName(path));
    s += field(L"位置", parentDir(path));
    s += field(L"大小", groupDigits(size) + L" 字节");
    s += field(L"修改时间", formatTime(fad.ftLastWriteTime));
    s += field(L"创建时间", formatTime(fad.ftCreationTime));
    s += field(L"属性", attrString(fad.dwFileAttributes, isDir));
    s += field(L"类型", typeString(fileName(path), isDir));

    if (!isDir && isCipherName(path)) {
        const CipherInfo ci = readCipherInfo(path);
        s += L"\n—————— 密文自描述文件头（22 字节）——————\n";
        if (ci.ok) {
            s += field(L"魔数", L"TDS1");
            s += field(L"算法", algText(ci.alg));
            s += field(L"工作模式", modeText(ci.mode));
            s += field(L"IV", utf8ToWide(tdes::toHex(ci.iv, tdes::IV_SIZE)));
            s += field(L"原始长度", groupDigits(ci.origSize) + L" 字节");
            s += field(L"分组数", groupDigits((ci.fileSize - tdes::HEADER_SIZE) / 8));
            s += field(L"填充", L"PKCS#7"); 
            s += L"\n密文 = 22 字节文件头 + PKCS#7 填充后的数据。\n"
                 L"算法、工作模式与 IV 均可直接解密，无需另外记录。";
        } else {
            s += L"该文件的头部不是本工具的 TDS1 格式，\n"
                 L"可能由其它实现生成，或使用了 raw（无文件头）模式。";
        }
    }
    return s;
}

void cmdInfo(HWND hwnd) {
    const std::wstring target = selectedTarget();
    if (target.empty()) {
        showInfo(hwnd, L"请先选择一个文件。");
        return;
    }
    showTextDialog(hwnd, L"信息", buildFileInfo(target));
}

void cmdSelfTest(HWND hwnd) {
    setStatus(L"正在运行内置自检…");
    const int failures = tdes::selfTest(false);
    std::wstring msg;
    if (failures == 0) {
        msg = L"内置自检全部通过。\n\n"
              L"覆盖内容：FIPS 46-3 标准向量(KAT)、IP/IP⁻¹ 互逆、PKCS#7 填充、"
              L"三种算法 × 两种模式的往返一致性、ECB 模式弱点与 CBC 的 IV 效应、"
              L"错误密钥必然被检出。";
        appendLog(L"[自检] 全部通过（失败 0 项）");
        setStatus(L"内置自检通过");
    } else {
        msg = L"内置自检失败 " + std::to_wstring(failures) + L" 项，请检查实现。";
        appendLog(L"[自检] 失败 " + std::to_wstring(failures) + L" 项");
        setStatus(L"内置自检失败");
    }
    showTextDialog(hwnd, L"内置自检结果", msg);
}

void cmdAbout(HWND hwnd) {
    const std::wstring txt =
        L"3DES 任意文件加解密工具  v1.2.0\n\n"
        L"手写实现 FIPS 46-3 规定的 DES 算法内核与 3DES（EDE）组合，\n"
        L"配合 CBC / ECB 两种工作模式与 PKCS#7 填充，\n"
        L"完全不依赖 OpenSSL、CryptoAPI 等任何现成密码库。\n\n"
        L"界面为纯 Win32 API 手工绘制，工具栏与列表图标全部由 GDI 现场生成，\n"
        L"整体布局模仿 7-Zip 的主窗口。\n\n"
        L"信息安全课程实验 · 2026";
    showTextDialog(hwnd, L"关于 3DES 文件加解密", txt);
}

void cmdUsage(HWND hwnd) {
    const std::wstring txt =
        L"使用说明\n"
        L"————————————————————\n"
        L"1) 在文件列表里双击文件即选中它，也可用“打开”按钮或把文件拖到窗口上；\n"
        L"2) 地址栏显示当前文件夹，输入路径回车即可跳转（下拉列表为目录层级）；\n"
        L"3) 点击“加密”按钮弹出“添加到加密包”对话框：选择加密格式、工作模式，\n"
        L"   输入十六进制密钥（或点“随机生成”），确认输出文件名后点“确定”；\n"
        L"4) 点击“解密”按钮弹出“解密到…”对话框：只需输入密钥，\n"
        L"   算法、工作模式与 IV 都会从密文文件头自动读取；\n"
        L"5) “信息”可以查看当前文件详情，对 .3des 文件还会解析出文件头中的\n"
        L"   算法、模式、IV、原始长度等信息；\n"
        L"6) “测试”会运行内置的已知答案测试（KAT）与往返一致性检查。\n\n"
        L"快捷键：Ctrl+O 打开，Ctrl+E 加密，Ctrl+D 解密，Ctrl+K 随机密钥，\n"
        L"        F5 刷新列表，F1 使用说明。\n\n"
        L"默认输出名：加密为 <原文件名>.3des，解密为去掉 .3des 后的原名（无该后缀则追加 .dec）。\n"
        L"安全提示：密钥只保存在内存中，程序退出即丢失，请务必自行妥善保管。";
    showTextDialog(hwnd, L"使用说明", txt);
}

// ============================ 剪贴板 ============================

void copyPath(HWND hwnd) {
    if (g_inputFile.empty()) return;
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    const std::size_t bytes = (g_inputFile.size() + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hg) {
        void* dst = GlobalLock(hg);
        if (dst) {
            memcpy(dst, g_inputFile.c_str(), bytes);
            GlobalUnlock(hg);
            if (SetClipboardData(CF_UNICODETEXT, hg)) hg = nullptr;
        }
        if (hg) GlobalFree(hg);
    }
    CloseClipboard();
    setStatus(L"已复制文件路径");
}

void pastePath(HWND hwnd) {
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) {
        showInfo(hwnd, L"剪贴板里没有文本。");
        return;
    }
    if (!OpenClipboard(hwnd)) return;
    std::wstring s;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        const wchar_t* p = (const wchar_t*)GlobalLock(h);
        if (p) {
            s = p;
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    s = trim(s);
    if (s.size() >= 2 && s.front() == L'"' && s.back() == L'"') s = s.substr(1, s.size() - 2);
    if (s.empty()) return;
    if (!fileExists(s)) {
        showError(hwnd, L"剪贴板中的路径不存在：\n" + s);
        return;
    }
    SetWindowTextW(g_hAddr, s.c_str());
    commitAddress(hwnd, true);
    setStatus(L"已从剪贴板载入路径");
}

// ============================ 主窗口布局 ============================

void layoutMain(HWND hwnd, int w, int h) {
    (void)hwnd;
    const int tbH = S(TB_H);
    const int sbH = g_statusH;

    if (g_hToolBar) MoveWindow(g_hToolBar, 0, 0, w, tbH, TRUE);

    int y = tbH + S(4);
    if (g_hUp) MoveWindow(g_hUp, S(MARGIN), y, S(ADDR_H), S(ADDR_H), TRUE);
    if (g_hAddr)
        MoveWindow(g_hAddr, S(MARGIN) + S(ADDR_H) + S(4), y, w - S(2 * MARGIN) - S(ADDR_H) - S(4),
                   S(240), TRUE);
    y += S(ADDR_H) + S(6);

    const int bottom = h - sbH;
    const int logH = g_showLog ? S(LOG_H) : 0;
    int listH = bottom - y - logH - (g_showLog ? S(4) : 0) - S(MARGIN);
    if (listH < S(60)) listH = S(60);

    if (g_hList) MoveWindow(g_hList, S(MARGIN), y, w - S(2 * MARGIN), listH, TRUE);
    if (g_hLog) {
        if (g_showLog) {
            MoveWindow(g_hLog, S(MARGIN), y + listH + S(4), w - S(2 * MARGIN), logH - S(4), TRUE);
            ShowWindow(g_hLog, SW_SHOW);
        } else {
            ShowWindow(g_hLog, SW_HIDE);
        }
    }

    // 文件列表的“名称”列自动拉伸，其余列保持固定宽度
    if (g_hList) {
        const int other = S(92 + 138 + 60 + 130) + S(2) * 2;
        int nw = w - S(2 * MARGIN) - other - S(2) * 2;
        if (nw < S(120)) nw = S(120);
        ListView_SetColumnWidth(g_hList, 0, nw);
    }

    if (g_hStatus) {
        int parts[3] = {S(160), S(160) + S(190), -1};
        SendMessageW(g_hStatus, SB_SETPARTS, 3, (LPARAM)parts);
    }

    // 分格变化后必须重设文字（SB_SETPARTS 之前设置的格位会被丢弃）
    updateStatus();
}

// ============================ 菜单与快捷键 ============================

HMENU buildMenu() {
    HMENU m = CreateMenu();

    HMENU f = CreatePopupMenu();
    AppendMenuW(f, MF_STRING, IDM_FILE_OPEN, L"打开文件(&O)…\tCtrl+O");
    AppendMenuW(f, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(f, MF_STRING, IDM_FILE_ENC, L"加密…(&A)\tCtrl+E");
    AppendMenuW(f, MF_STRING, IDM_FILE_DEC, L"解密…(&E)\tCtrl+D");
    AppendMenuW(f, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(f, MF_STRING, IDM_FILE_EXIT, L"退出(&X)");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)f, L"文件(&F)");

    HMENU e = CreatePopupMenu();
    AppendMenuW(e, MF_STRING, IDM_EDIT_COPYPATH, L"复制文件路径(&C)");
    AppendMenuW(e, MF_STRING, IDM_EDIT_PASTEPATH, L"从剪贴板载入路径(&V)");
    AppendMenuW(e, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(e, MF_STRING, IDM_EDIT_CLEARLOG, L"清空日志(&L)");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)e, L"编辑(&E)");

    HMENU v = CreatePopupMenu();
    AppendMenuW(v, MF_STRING, IDM_VIEW_LOG, L"显示日志面板(&L)");
    AppendMenuW(v, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(v, MF_STRING, IDM_VIEW_REFRESH, L"刷新(&R)\tF5");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)v, L"查看(&V)");

    HMENU t = CreatePopupMenu();
    AppendMenuW(t, MF_STRING, IDM_TOOLS_GENKEY, L"随机生成密钥(&K)\tCtrl+K");
    AppendMenuW(t, MF_STRING, IDM_TOOLS_INFO, L"文件信息(&I)");
    AppendMenuW(t, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(t, MF_STRING, IDM_TOOLS_TEST, L"内置自检(&T)");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)t, L"工具(&T)");

    HMENU hp = CreatePopupMenu();
    AppendMenuW(hp, MF_STRING, IDM_HELP_USAGE, L"使用说明(&H)\tF1");
    AppendMenuW(hp, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hp, MF_STRING, IDM_HELP_ABOUT, L"关于 3DES 文件加解密(&A)");
    AppendMenuW(m, MF_POPUP, (UINT_PTR)hp, L"帮助(&H)");

    return m;
}

HACCEL buildAccel() {
    ACCEL a[] = {
        {FVIRTKEY | FCONTROL, 'O', IDM_FILE_OPEN},
        {FVIRTKEY | FCONTROL, 'E', IDM_FILE_ENC},
        {FVIRTKEY | FCONTROL, 'D', IDM_FILE_DEC},
        {FVIRTKEY | FCONTROL, 'K', IDM_TOOLS_GENKEY},
        {FVIRTKEY, VK_F5, IDM_VIEW_REFRESH},
        {FVIRTKEY, VK_F1, IDM_HELP_USAGE},
    };
    return CreateAcceleratorTableW(a, (int)(sizeof(a) / sizeof(a[0])));
}

// ============================ 主窗口过程 ============================

void onOpenFile(HWND hwnd) {
    std::vector<wchar_t> buf(4096, L'\0');
    if (!g_inputFile.empty() && g_inputFile.size() < buf.size() - 1)
        std::copy(g_inputFile.begin(), g_inputFile.end(), buf.begin());

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter =
        L"所有文件\0*.*\0加密文件 (*.3des)\0*.3des\0"
        L"文本文件 (*.txt)\0*.txt\0\0";
    ofn.lpstrFile = buf.data();
    ofn.nMaxFile = (DWORD)buf.size();
    ofn.lpstrTitle = L"请选择要处理的文件";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return;

    const std::wstring p = fullPath(buf.data());
    setInputFile(p, true);
    refreshFileList(parentDir(p));
    selectInputInList();
}

void onGenKey(HWND hwnd) {
    std::vector<std::uint8_t> key;
    tdes::randomKey(tdes::Alg::TDES3, key);
    const std::wstring hex = utf8ToWide(tdes::toHex(key));
    g_sessionKey = hex;
    appendLog(L"[随机密钥] " + hex);
    setStatus(L"已生成 24 字节随机密钥");
    showTextDialog(hwnd, L"随机密钥（3DES-3Key，24 字节）",
                   L"已生成一次性随机密钥，可直接复制到加密对话框中使用。\n"
                   L"关闭本窗口后它会保留在内存中，方便紧接着执行解密。\n\n" + hex);
}

void showListMenu(HWND hwnd) {
    HMENU m = CreatePopupMenu();
    const UINT okE = commandEnabled(IDM_FILE_ENC) ? 0u : (UINT)MF_GRAYED;
    const UINT okD = commandEnabled(IDM_FILE_DEC) ? 0u : (UINT)MF_GRAYED;
    const UINT okC = commandEnabled(IDM_EDIT_COPYPATH) ? 0u : (UINT)MF_GRAYED;
    AppendMenuW(m, MF_STRING | okE, IDM_FILE_ENC, L"加密…");
    AppendMenuW(m, MF_STRING | okD, IDM_FILE_DEC, L"解密…");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, IDM_TOOLS_INFO, L"信息");
    AppendMenuW(m, MF_STRING | okC, IDM_EDIT_COPYPATH, L"复制文件路径");
    POINT pt;
    GetCursorPos(&pt);
    TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
    DestroyMenu(m);
}

LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g_hFont = createUiFont();

            // 状态栏先建：主窗口布局需要它的高度
            g_hStatus =
                CreateWindowExW(0, STATUSCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)IDC_STATUS, g_hInst, nullptr);
            SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            SendMessageW(g_hStatus, WM_SIZE, 0, 0);
            RECT sr;
            GetWindowRect(g_hStatus, &sr);
            g_statusH = sr.bottom - sr.top;

            // 工具栏：先用主窗口 DC 按 DPI 算好各按钮矩形，再创建窗口
            HDC dc = GetDC(hwnd);
            tbComputeLayout(dc);
            ReleaseDC(hwnd, dc);
            g_hToolBar = CreateWindowExW(WS_EX_NOACTIVATE, L"TdesToolBar", L"",
                                         WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 0, 0, hwnd,
                                         (HMENU)(INT_PTR)IDC_TOOLBAR, g_hInst, nullptr);

            // 地址栏行：“向上”按钮 + 路径下拉框
            g_hUp = CreateWindowExW(0, L"BUTTON", L"", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0,
                                    0, 0, hwnd, (HMENU)(INT_PTR)IDC_UP, g_hInst, nullptr);
            g_hAddr = CreateWindowExW(0, L"COMBOBOX", L"",
                                      WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_AUTOHSCROLL |
                                          WS_VSCROLL | WS_TABSTOP,
                                      0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)IDC_ADDR, g_hInst, nullptr);
            SendMessageW(g_hAddr, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            // 文件列表
            g_hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                      WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS |
                                          WS_TABSTOP,
                                      0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)IDC_LIST, g_hInst, nullptr);
            SendMessageW(g_hList, WM_SETFONT, (WPARAM)g_hFont, TRUE);
            initListView();

            // 日志面板
            g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
                                         WS_VSCROLL | ES_AUTOVSCROLL,
                                     0, 0, 0, 0, hwnd, (HMENU)(INT_PTR)IDC_LOG, g_hInst, nullptr);
            SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            DragAcceptFiles(hwnd, TRUE);

            appendLog(L"使用说明：\n"
                      L"  1) 在文件列表里单击 / 双击选中要处理的文件，也可用“打开”按钮或把文件拖到窗口上；\n"
                      L"  2) 地址栏显示当前文件夹，输入路径回车即可跳转（下拉列表为目录层级）；\n"
                      L"  3) 点击“加密”弹出“添加到加密包”对话框，选择加密格式与工作模式、"
                      L"输入或随机生成密钥；\n"
                      L"  4) 点击“解密”弹出“解密到…”对话框，只需提供密钥即可；\n"
                      L"  5) “信息”可查看文件详情，对 .3des 文件还会解析密文文件头；\n"
                      L"  6) “测试”运行内置 KAT 与往返一致性自检。\n"
                      L"默认输出名：加密为 <原文件名>.3des，解密为去掉 .3des 后的原名（无该后缀则追加 .dec）。");

            refreshFileList(fullPath(L"."));
            RECT rc;
            GetClientRect(hwnd, &rc);
            layoutMain(hwnd, rc.right, rc.bottom);
            SetFocus(g_hList);  // 仿 7-Zip：启动后焦点就在文件列表上
            return 0;
        }

        case WM_SIZE: {
            if (g_hStatus) SendMessageW(g_hStatus, WM_SIZE, 0, 0);
            layoutMain(hwnd, LOWORD(lp), HIWORD(lp));
            return 0;
        }

        case WM_GETMINMAXINFO: {
            auto* mmi = (MINMAXINFO*)lp;
            RECT r{0, 0, S(MIN_W), S(MIN_H)};
            AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, TRUE);
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
                    const std::wstring p = fullPath(buf.data());
                    const DWORD a = GetFileAttributesW(p.c_str());
                    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
                        refreshFileList(p);
                        setStatus(L"已载入拖入的文件夹");
                    } else {
                        setInputFile(p, false);
                        refreshFileList(parentDir(p));
                        selectInputInList();
                        setStatus(L"已载入拖入的文件：" + fileName(p));
                    }
                }
            }
            DragFinish(hDrop);
            return 0;
        }

        case WM_DRAWITEM: {
            auto* di = (DRAWITEMSTRUCT*)lp;
            if (di->CtlID == IDC_UP) {
                RECT r = di->rcItem;
                FillRect(di->hDC, &r, GetSysColorBrush(COLOR_BTNFACE));
                if (di->itemState & ODS_SELECTED) DrawEdge(di->hDC, &r, BDR_SUNKENOUTER, BF_RECT);
                else DrawEdge(di->hDC, &r, BDR_RAISEDINNER, BF_RECT);
                RECT ic{r.left + S(3), r.top + S(3), r.right - S(3), r.bottom - S(3)};
                drawIconShape(di->hDC, ICON_UP, ic, GetSysColor(COLOR_BTNFACE), false);
                return TRUE;
            }
            break;
        }

        case WM_INITMENUPOPUP: {
            HMENU m = (HMENU)wp;
            const int ids[] = {IDM_FILE_ENC,  IDM_FILE_DEC,      IDM_EDIT_COPYPATH,
                               IDM_EDIT_CLEARLOG, IDM_VIEW_REFRESH, IDM_TOOLS_INFO};
            for (int id : ids) {
                EnableMenuItem(m, (UINT)id, commandEnabled(id) ? MF_ENABLED : MF_GRAYED);
            }
            CheckMenuItem(m, IDM_VIEW_LOG, g_showLog ? MF_CHECKED : MF_UNCHECKED);
            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDM_FILE_OPEN:
                    onOpenFile(hwnd);
                    return 0;
                case IDM_FILE_ENC:
                    cmdEncrypt(hwnd);
                    return 0;
                case IDM_FILE_DEC:
                    cmdDecrypt(hwnd);
                    return 0;
                case IDM_FILE_EXIT:
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    return 0;
                case IDM_EDIT_COPYPATH:
                    copyPath(hwnd);
                    return 0;
                case IDM_EDIT_PASTEPATH:
                    pastePath(hwnd);
                    return 0;
                case IDM_EDIT_CLEARLOG:
                    g_logBuffer.clear();
                    if (g_hLog) SetWindowTextW(g_hLog, L"");
                    setStatus(L"日志已清空");
                    if (g_hToolBar) InvalidateRect(g_hToolBar, nullptr, FALSE);
                    return 0;
                case IDM_VIEW_LOG: {
                    g_showLog = !g_showLog;
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    layoutMain(hwnd, rc.right, rc.bottom);
                    setStatus(g_showLog ? L"已显示日志面板" : L"已隐藏日志面板");
                    return 0;
                }
                case IDM_VIEW_REFRESH:
                    refreshFileList(g_curDir);
                    setStatus(L"已刷新");
                    return 0;
                case IDM_TOOLS_GENKEY:
                    onGenKey(hwnd);
                    return 0;
                case IDM_TOOLS_INFO:
                    cmdInfo(hwnd);
                    return 0;
                case IDM_TOOLS_TEST:
                    cmdSelfTest(hwnd);
                    return 0;
                case IDM_HELP_USAGE:
                    cmdUsage(hwnd);
                    return 0;
                case IDM_HELP_ABOUT:
                    cmdAbout(hwnd);
                    return 0;

                case IDC_UP:
                    if (!isRootDir(g_curDir)) refreshFileList(parentDir(g_curDir));
                    return 0;

                case IDC_ADDR:
                    if (HIWORD(wp) == CBN_EDITCHANGE) commitAddress(hwnd, false);
                    else if (HIWORD(wp) == CBN_SELENDOK) commitAddress(hwnd, true);
                    return 0;

                default:
                    break;
            }
            return 0;
        }

        case WM_NOTIFY: {
            auto* nh = (NMHDR*)lp;
            if (nh->idFrom == IDC_LIST) {
                switch (nh->code) {
                    case LVN_ITEMACTIVATE:
                        listActivate((int)((NMITEMACTIVATE*)nh)->iItem);
                        return 0;
                    case LVN_ITEMCHANGED:
                        updateSelSize();
                        return 0;
                    case LVN_COLUMNCLICK: {
                        auto* nv = (NMLISTVIEW*)nh;
                        if (nv->iSubItem == g_sortCol) g_sortAsc = !g_sortAsc;
                        else {
                            g_sortCol = nv->iSubItem;
                            g_sortAsc = true;
                        }
                        std::sort(g_entries.begin(), g_entries.end(), entryLess);
                        fillListItems();
                        selectInputInList();
                        setStatus(L"已按“" + std::wstring(g_sortCol == 0   ? L"名称"
                                                          : g_sortCol == 1 ? L"大小"
                                                          : g_sortCol == 2 ? L"修改日期"
                                                          : g_sortCol == 3 ? L"属性"
                                                                           : L"类型") +
                                  (g_sortAsc ? L"”升序排列" : L"”降序排列"));
                        return 0;
                    }
                    case NM_RCLICK:
                        showListMenu(hwnd);
                        return 0;
                    default:
                        break;
                }
            }
            break;
        }

        case WM_SETFOCUS:
            if (g_hList) SetFocus(g_hList);
            return 0;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY: {
            if (g_hImlSmall) {
                ImageList_Destroy(g_hImlSmall);
                g_hImlSmall = nullptr;
            }
            if (g_hAccel) {
                DestroyAcceleratorTable(g_hAccel);
                g_hAccel = nullptr;
            }
            if (g_hFont) {
                DeleteObject(g_hFont);
                g_hFont = nullptr;
            }
            PostQuitMessage(0);
            return 0;
        }

        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

// ============================ 程序入口 ============================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInst;
    g_hInst = hInst;

    SetProcessDPIAware();  // 高分屏下不做位图拉伸，界面更清晰
    initDpi();             // 取得系统 DPI，供 S() 换算布局尺寸

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icc);

    registerToolBarClass(hInst);

    // 拖到 exe 上启动 / 命令行带路径时，先记下来，等窗口建好再载入
    std::wstring startupArg;
    if (lpCmdLine && *lpCmdLine) {
        std::string a(lpCmdLine);
        const std::size_t b = a.find_last_not_of(" \t\r\n");
        if (b != std::string::npos) a.resize(b + 1);
        const std::size_t s = a.find_first_not_of(" \t\r\n");
        if (s != std::string::npos && s > 0) a = a.substr(s);
        if (a.size() >= 2 && a.front() == '"' && a.back() == '"') a = a.substr(1, a.size() - 2);
        if (!a.empty()) {
            // 宽字符入口未启用，lpCmdLine 按系统 ANSI 代码页传入
            const int n = MultiByteToWideChar(CP_ACP, 0, a.c_str(), (int)a.size(), nullptr, 0);
            std::wstring w((std::size_t)n, L'\0');
            MultiByteToWideChar(CP_ACP, 0, a.c_str(), (int)a.size(), &w[0], n);
            startupArg = w;
        }
    }

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = wndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"TdesGuiWindow";
    // 窗口/任务栏图标取自 exe 内嵌的图标资源；若资源缺失则退回系统默认图标
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_APPICON));
    if (!wc.hIcon) wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                   LR_DEFAULTCOLOR);
    if (!wc.hIconSm) wc.hIconSm = wc.hIcon;
    if (!RegisterClassExW(&wc)) return 1;

    g_hAccel = buildAccel();
    HMENU hMenu = buildMenu();

    RECT r{0, 0, S(900), S(640)};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, TRUE);
    g_hMain = CreateWindowExW(0, wc.lpszClassName, L"3DES 任意文件加解密工具",
                              WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                              r.right - r.left, r.bottom - r.top, nullptr, hMenu, hInst, nullptr);
    if (!g_hMain) return 1;

    ShowWindow(g_hMain, nCmdShow);
    UpdateWindow(g_hMain);
    SetFocus(g_hList);  // 窗口真正可见后再落实一次焦点（仿 7-Zip 落在文件列表上）

    // 命令行 / 拖放的起始文件
    if (!startupArg.empty() && fileExists(startupArg)) {
        const DWORD a = GetFileAttributesW(startupArg.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) {
            refreshFileList(fullPath(startupArg));
        } else {
            setInputFile(fullPath(startupArg), false);
            refreshFileList(parentDir(fullPath(startupArg)));
            selectInputInList();
            setStatus(L"已载入：" + fileName(startupArg));
        }
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (g_hAccel && TranslateAcceleratorW(g_hMain, g_hAccel, &msg)) continue;
        // 交给 IsDialogMessage 处理，可使用 Tab 键在控件之间切换
        if (!IsDialogMessageW(g_hMain, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
