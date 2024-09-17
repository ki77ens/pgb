#ifndef DRIVER_H
#define DRIVER_H

#include <ntddk.h>
#include "hook.h"

#define DEVICE_NAME L"\\Device\\MyDriverDevice"
#define SYMBOLIC_NAME L"\\DosDevices\\MyDriverSymbolicLink"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif 