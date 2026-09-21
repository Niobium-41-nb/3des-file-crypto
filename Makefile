# ============================================================================
#  3DES 文件加解密工具 —— GNU Makefile (MinGW-w64 / g++)
#  ---------------------------------------------------------------------------
#  用法（在 Windows 下用 mingw32-make）:
#     mingw32-make            编译命令行工具 tdes.exe
#     mingw32-make test       编译并运行内置自检 + 文件级测试
#     mingw32-make clean      清理编译产物
#
#  说明：-o 一律使用相对路径，避免 MinGW 的 ld 无法处理含中文的绝对输出路径。
#        静态链接 libgcc/libstdc++，避免多套 MinGW 运行库混用导致退出时崩溃。
# ============================================================================
CXX      := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude -static -static-libgcc -static-libstdc++
CORE     := src/des.cpp src/tdes.cpp src/selftest.cpp
TOOL     := $(CORE) src/main.cpp
HEADERS  := include/des.h include/tdes.h

.PHONY: all test clean

all: tdes.exe

tdes.exe: $(TOOL) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o tdes.exe $(TOOL)

test_kat.exe: tests/test_kat.cpp $(CORE) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o test_kat.exe tests/test_kat.cpp $(CORE)

test: tdes.exe test_kat.exe
	./tdes.exe selftest
	./test_kat.exe

clean:
	-del /q tdes.exe test_kat.exe 2>nul
