#include <ntddk.h>
#include <intrin.h>
#include "intelpt.h"
#include "utils.h"

#define TRACE_BUFFER_SIZE 0x10000
#define PATCHED_FUNCTION_OFFSET 0x1234

static void* traceBuffer = NULL;

#define IA32_RTIT_CTL 0x570
#define IA32_RTIT_STATUS 0x571
#define IA32_RTIT_OUTPUT_BASE 0x560
#define IA32_RTIT_OUTPUT_MASK_PTRS 0x561

#define KdPrintError(msg) KdPrint(("Error: %s\n", msg))
#define KdPrintDebug(msg, ...) KdPrint(("[DEBUG] " msg "\n", ##__VA_ARGS__))

NTSTATUS EnableIntelPT() {
    traceBuffer = allocate_memory(TRACE_BUFFER_SIZE);
    if (traceBuffer == NULL) {
        KdPrintError("Failed to allocate trace buffer.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    try {
        __writemsr(IA32_RTIT_OUTPUT_BASE, (uint64_t)traceBuffer);
        __writemsr(IA32_RTIT_OUTPUT_MASK_PTRS, ((TRACE_BUFFER_SIZE - 1) & 0xFFFFFFFF));
    } except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrintError("Exception occurred while writing to MSRs.");
        free_memory(traceBuffer);
        traceBuffer = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    uint64_t rtit_ctl = __readmsr(IA32_RTIT_CTL);
    rtit_ctl |= 0x1;
    try {
        __writemsr(IA32_RTIT_CTL, rtit_ctl);
    } except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrintError("Exception occurred while writing IA32_RTIT_CTL MSR.");
        free_memory(traceBuffer);
        traceBuffer = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    KdPrintDebug("Intel PT enabled, buffer at: %p", traceBuffer);

    void* targetAddress = (void*)((uintptr_t)traceBuffer + PATCHED_FUNCTION_OFFSET);
    uint8_t patch[] = {0x90, 0x90}; 
    memcpy(targetAddress, patch, sizeof(patch));

    return STATUS_SUCCESS;
}

NTSTATUS DisableIntelPT() {
    uint64_t rtit_ctl = __readmsr(IA32_RTIT_CTL);
    rtit_ctl &= ~0x1;
    try {
        __writemsr(IA32_RTIT_CTL, rtit_ctl);
    } except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrintError("Exception occurred while writing IA32_RTIT_CTL MSR.");
        return STATUS_UNSUCCESSFUL;
    }

    KdPrintDebug("Intel PT disabled.");

    if (traceBuffer) {
        free_memory(traceBuffer);
        traceBuffer = NULL;
    }

    return STATUS_SUCCESS;
}

void DumpTraceBuffer() {
    if (traceBuffer == NULL) {
        KdPrintError("Trace buffer is not allocated!");
        return;
    }

    uint8_t* buffer = (uint8_t*)traceBuffer;
    for (size_t i = 0; i < 0x100; i++) {
        KdPrintDebug("0x%02x ", buffer[i]);
        if (i % 16 == 15) {
            KdPrintDebug("");
        }
    }
}

void ReadIntelPTStatus() {
    uint64_t status = __readmsr(IA32_RTIT_STATUS);
    KdPrintDebug("Intel PT status: 0x%llx", status);
}