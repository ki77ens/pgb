#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <stdint.h>    
#include "C:\Users\betty\Desktop\pgb\include\utils.h"

void log_debug(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void log_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void* allocate_memory(SIZE_T size) {
    void* memory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (memory == NULL) {
        log_error("err: Memory allocation failed: %lu\n", GetLastError());
    } else {
        log_debug("dbg: Memory allocated at: %p\n", memory);
    }
    return memory;
}

void free_memory(void* memory) {
    if (memory != NULL) {
        VirtualFree(memory, 0, MEM_RELEASE);
        log_debug("dbg: Memory at %p freed\n", memory);
    }
}

uint64_t read_msr(uint32_t reg) {
    uint32_t edx, eax;
    __asm__ volatile (
        "rdmsr"
        : "=d" (edx), "=a" (eax) 
        : "c" (reg)
    );
    return ((uint64_t)edx << 32) | eax;
}

void write_msr(uint32_t reg, uint64_t value) {
    uint32_t edx = (value >> 32);
    uint32_t eax = (value & 0xFFFFFFFF);
    __asm__ volatile (
        "wrmsr"
        : 
        : "c" (reg), "d" (edx), "a" (eax)
    );
}

BOOL is_admin() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    log_debug("dbg: Admin check: %s\n", isAdmin ? "TRUE" : "FALSE");
    return isAdmin;
}

DWORD get_process_id_by_name(const char* processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        log_error("err: CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (strcmp(pe.szExeFile, processName) == 0) {
                processId = pe.th32ProcessID;
                log_debug("dbg: Found process %s with PID: %lu\n", processName, processId);
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    if (processId == 0) {
        log_error("dbg: Process %s not found\n", processName);
    }

    return processId;
}