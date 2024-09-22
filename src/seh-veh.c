#include <ntddk.h>
#include <intrin.h>
#include "intelpt.h"
#include "utils.h"

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD* Next;
    PVOID Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef NTSTATUS (*PFN_HOOK_FUNCTION)(PDEVICE_OBJECT, PIRP);
static PFN_HOOK_FUNCTION OriginalFunction = NULL;

VOID __declspec(naked) ExceptionHandler() {
    __asm {
        pop eax
        mov eax, [esp]
        push eax
        ret
    }
}

NTSTATUS SetMemoryProtection(PVOID address, SIZE_T size, ULONG newProtect) {
    PMMPTE entry;
    MM_HANDLE handle;
    NTSTATUS status;

    entry = MiGetPteAddress(address);
    handle = MmCreateSection(NULL, PAGE_READWRITE, 0);

    status = MmMapViewOfSection(handle, address, newProtect, size, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS HookFunction(PVOID targetFunctionAddress, PVOID hookFunctionAddress) {
    EXCEPTION_REGISTRATION_RECORD registration;
    registration.Next = NULL;
    registration.Handler = ExceptionHandler;

    __asm {
        push registration
    }

    NTSTATUS status;
    try {
        PVOID alignedAddress = (PVOID)((uintptr_t)targetFunctionAddress & ~(0xFFF));
        ULONG_PTR offset = (ULONG_PTR)targetFunctionAddress - (ULONG_PTR)alignedAddress;

        SIZE_T patchSize = 0x10;
        uint8_t* patchBytes = (uint8_t*)allocate_memory(patchSize);
        if (patchBytes == NULL) {
            KdPrintError("Failed to allocate memory for hook patch.");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        memcpy(patchBytes, alignedAddress, patchSize);

        uint8_t jumpInstruction[] = {0xE9};
        *(int32_t*)(jumpInstruction + 1) = (int32_t)((uintptr_t)hookFunctionAddress - (uintptr_t)targetFunctionAddress - 5);

        status = SetMemoryProtection(alignedAddress, patchSize, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status)) {
            KdPrintError("Failed to set memory protection.");
            free_memory(patchBytes);
            return status;
        }

        memcpy(alignedAddress, jumpInstruction, sizeof(jumpInstruction));
        OriginalFunction = *(PFN_HOOK_FUNCTION*)targetFunctionAddress;

    } except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrintError("Exception occurred in HookFunction.");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS UnhookFunction(PVOID targetFunctionAddress) {
    EXCEPTION_REGISTRATION_RECORD registration;
    registration.Next = NULL;
    registration.Handler = ExceptionHandler;

    __asm {
        push registration
    }

    NTSTATUS status;
    try {
        if (OriginalFunction) {
            memcpy((void*)((uintptr_t)targetFunctionAddress & ~(0xFFF)), patchMemory, sizeof(patchMemory));
        }

        if (patchMemory) {
            free_memory(patchMemory);
            patchMemory = NULL;
        }

    } except(EXCEPTION_EXECUTE_HANDLER) {
        KdPrintError("Exception occurred in UnhookFunction.");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS HookedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    return OriginalFunction(DeviceObject, Irp);
}