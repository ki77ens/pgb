#include <ntddk.h>
#include "hook.h"
#include "intelpt.h"  
#include "utils.h"

#define DEVICE_NAME L"\\Device\\MyDriverDevice"
#define SYMBOLIC_NAME L"\\DosDevices\\MyDriverSymbolicLink"

#define TARGET_FUNCTION_ADDRESS 0x123 

static PDEVICE_OBJECT DeviceObject = NULL;
static UNICODE_STRING DeviceName;
static UNICODE_STRING SymbolicLinkName;

typedef NTSTATUS(*PFN_TARGET_FUNCTION)(PDEVICE_OBJECT, PIRP);
static PFN_TARGET_FUNCTION OriginalFunction = NULL;
static PVOID patchMemory = NULL;

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
    PVOID alignedAddress = (PVOID)((uintptr_t)targetFunctionAddress & ~(0xFFF));
    ULONG_PTR offset = (ULONG_PTR)targetFunctionAddress - (ULONG_PTR)alignedAddress;

    SIZE_T patchSize = 0x10;
    patchMemory = allocate_memory(patchSize);
    if (patchMemory == NULL) {
        KdPrintError("Failed to allocate memory for hook patch.");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    uint8_t* patchBytes = (uint8_t*)patchMemory;
    memcpy(patchBytes, alignedAddress, patchSize);

    uint8_t jumpInstruction[] = {0xE9};
    *(int32_t*)(jumpInstruction + 1) = (int32_t)((uintptr_t)hookFunctionAddress - (uintptr_t)targetFunctionAddress - 5);

    NTSTATUS status = SetMemoryProtection(alignedAddress, patchSize, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        KdPrintError("Failed to set memory protection.");
        free_memory(patchMemory);
        return status;
    }

    memcpy(alignedAddress, jumpInstruction, sizeof(jumpInstruction));

    OriginalFunction = *(PFN_TARGET_FUNCTION*)targetFunctionAddress;

    return STATUS_SUCCESS;
}

NTSTATUS UnhookFunction(PVOID targetFunctionAddress) {
    if (OriginalFunction) {
        memcpy((void*)((uintptr_t)targetFunctionAddress & ~(0xFFF)), patchMemory, sizeof(patchMemory));
    }

    if (patchMemory) {
        free_memory(patchMemory);
        patchMemory = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS HookedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    return OriginalFunction(DeviceObject, Irp);
}

NTSTATUS SetHook(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    NTSTATUS status = EnableIntelPT();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = HookFunction((PVOID)TARGET_FUNCTION_ADDRESS, (PVOID)HookedFunction);
    if (!NT_SUCCESS(status)) {
        DisableIntelPT(); 
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS RemoveHook(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    NTSTATUS status = UnhookFunction((PVOID)TARGET_FUNCTION_ADDRESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = DisableIntelPT();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    IoDeleteSymbolicLink(&SymbolicLinkName);
    if (DeviceObject) {
        IoDeleteDevice(DeviceObject);
    }

    DisableIntelPT();
}

NTSTATUS DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpStack;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_SET_HOOK:
            status = SetHook(DeviceObject, Irp);
            break;

        case IOCTL_REMOVE_HOOK:
            status = RemoveHook(DeviceObject, Irp);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&SymbolicLinkName, SYMBOLIC_NAME);

    status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    DeviceObject = deviceObject;

    status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IoCompleteRequest;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoCompleteRequest;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;

    return STATUS_SUCCESS;
}