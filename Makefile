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
WX       := windres
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude -static -static-libgcc -static-libstdc++
CORE     := src/des.cpp src/tdes.cpp src/selftest.cpp
TOOL     := $(CORE) src/main.cpp
GUI      := src/gui.cpp src/des.cpp src/tdes.cpp
HEADERS  := include/des.h include/tdes.h
RES      := assets/app_res.o
RESDEP   := assets/app.rc assets/icon.ico

.PHONY: all gui test gui-test icon clean

all: tdes.exe tdes_gui.exe

# 图标 + 版本信息资源（windres 编译，链进两个 exe；需 --codepage=65001 才能正确读入中文）
$(RES): $(RESDEP)
	$(WX) --codepage=65001 -i assets/app.rc -o $(RES)

tdes.exe: $(TOOL) $(HEADERS) $(RES)
	$(CXX) $(CXXFLAGS) -o tdes.exe $(TOOL) $(RES)

# 图形界面：-mwindows 表示无控制台窗口，额外链接 comdlg32（文件对话框）
gui: tdes_gui.exe

tdes_gui.exe: $(GUI) $(HEADERS) $(RES)
	$(CXX) $(CXXFLAGS) -mwindows -o tdes_gui.exe $(GUI) $(RES) -lcomdlg32

test_kat.exe: tests/test_kat.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o test_kat.exe tests/test_kat.cpp $(CORE)

test: tdes.exe test_kat.exe
	./tdes.exe selftest
	./test_kat.exe

# 图形界面端到端测试（脚本驱动控件，无需手工点击）
gui-test: tdes_gui.exe
	powershell -NoProfile -ExecutionPolicy Bypass -File tools/gui_smoke.ps1

# 重新生成图标（需要 Python + Pillow）
icon:
	python tools/make_icon.py

clean:
	-$(RM) tdes.exe tdes_gui.exe test_kat.exe $(RES)
