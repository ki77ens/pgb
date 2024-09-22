# Makefile for compiling kernel-mode driver

# Directories
SRC_DIR := C:\Users\Shadow\skm\kernel-mode-hooking\src
INCLUDE_DIR := C:\Users\Shadow\skm\kernel-mode-hooking\include
BUILD_DIR := C:\Users\Shadow\skm\kernel-mode-hooking\build
DEBUG_DIR := $(BUILD_DIR)\Debug
RELEASE_DIR := $(BUILD_DIR)\Release
MSBUILD_PATH := C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin

# Driver name
DRIVER_NAME := MyDriver.sys

# Source files
SRC_FILES := $(wildcard $(SRC_DIR)\*.c) $(wildcard $(SRC_DIR)\*.cpp)

# Targets
.PHONY: all debug release clean

all: debug release

debug: $(DEBUG_DIR)\$(DRIVER_NAME)

release: $(RELEASE_DIR)\$(DRIVER_NAME)

$(DEBUG_DIR)\$(DRIVER_NAME): $(SRC_FILES)
	@echo Compiling debug version...
	@mkdir $(DEBUG_DIR) 2>nul || true
	"$(MSBUILD_PATH)\MSBuild.exe" $(SRC_DIR)\YourProjectFile.vcxproj /p:Configuration=Debug

$(RELEASE_DIR)\$(DRIVER_NAME): $(SRC_FILES)
	@echo Compiling release version...
	@mkdir $(RELEASE_DIR) 2>nul || true
	"$(MSBUILD_PATH)\MSBuild.exe" $(SRC_DIR)\YourProjectFile.vcxproj /p:Configuration=Release

clean:
	@echo Cleaning build directories...
	@rd /s /q $(BUILD_DIR)
