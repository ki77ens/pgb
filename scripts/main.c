#include <stdio.h>
#include "C:\Users\betty\Desktop\pgb\include\utils.h"

int main() {
    // Test Memory Allocation and Deallocation
    void* memory = allocate_memory(1024);  // Allocate 1 KB
    if (memory) {
        printf("Memory allocation successful.\n");
        free_memory(memory);  // Free allocated memory
    } else {
        printf("Memory allocation failed.\n");
    }

    // Test Admin Privileges Check
    if (is_admin()) {
        printf("Running as administrator.\n");
    } else {
        printf("Not running as administrator.\n");
    }

    // Test Getting Process ID by Process Name
    DWORD pid = get_process_id_by_name("notepad.exe");
    if (pid != 0) {
        printf("Notepad.exe Process ID: %lu\n", pid);
    } else {
        printf("Process not found.\n");
    }

    getchar();

    return 0;
}
