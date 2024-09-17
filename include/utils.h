#ifndef UTILS_H
#define UTILS_H

#include <Windows.h>
#include <stdint.h> 

void log_debug(const char* format, ...);
void log_error(const char* format, ...);

void* allocate_memory(SIZE_T size);
void free_memory(void* memory);

uint64_t read_msr(uint32_t reg);
void write_msr(uint32_t reg, uint64_t value);

BOOL is_admin();
DWORD get_process_id_by_name(const char* processName);

#endif 
