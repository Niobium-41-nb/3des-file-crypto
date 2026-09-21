# ============================================================================
#  3DES 文件加解密工具 —— GNU Makefile (MinGW-w64 / g++)
#  ---------------------------------------------------------------------------
#  用法（在 Windows 下用 mingw32-make）:
#     mingw32-make            编译命令行工具 tdes.exe 与图形界面 tdes_gui.exe
#     mingw32-make gui        只编译图形界面
#     mingw32-make test       编译并运行内置自检 + 文件级测试
#     mingw32-make gui-test   运行图形界面端到端测试
#     mingw32-make clean      清理编译产物
#
#  说明：-o 一律使用相对路径，避免 MinGW 的 ld 无法处理含中文的绝对输出路径。
#        静态链接 libgcc/libstdc++，避免多套 MinGW 运行库混用导致退出时崩溃。
# ============================================================================
CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude -static -static-libgcc -static-libstdc++
CORE     := src/des.cpp src/tdes.cpp src/selftest.cpp
TOOL     := $(CORE) src/main.cpp
GUI      := src/gui.cpp src/des.cpp src/tdes.cpp
HEADERS  := include/des.h include/tdes.h

.PHONY: all gui test gui-test clean

all: tdes.exe tdes_gui.exe

tdes.exe: $(TOOL) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o tdes.exe $(TOOL)

# 图形界面：-mwindows 表示无控制台窗口，额外链接 comdlg32（文件对话框）
gui: tdes_gui.exe

tdes_gui.exe: $(GUI) $(HEADERS)
	$(CXX) $(CXXFLAGS) -mwindows -o tdes_gui.exe $(GUI) -lcomdlg32

test_kat.exe: tests/test_kat.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o test_kat.exe tests/test_kat.cpp $(CORE)

test: tdes.exe test_kat.exe
	./tdes.exe selftest
	./test_kat.exe

# 图形界面端到端测试（脚本驱动控件，无需手工点击）
gui-test: tdes_gui.exe
	powershell -NoProfile -ExecutionPolicy Bypass -File tools/gui_smoke.ps1

clean:
	-$(RM) tdes.exe tdes_gui.exe test_kat.exe
