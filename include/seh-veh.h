#ifndef SEH_VEH_H
#define SEH_VEH_H

#include <ntddk.h>

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD* Next;
    PVOID Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef VOID (*PFN_EXCEPTION_HANDLER)(EXCEPTION_RECORD*, PVOID);

NTSTATUS RegisterExceptionHandler(PFN_EXCEPTION_HANDLER Handler);
VOID UnregisterExceptionHandler(PFN_EXCEPTION_HANDLER Handler);

NTSTATUS RegisterExceptionHandler(PFN_EXCEPTION_HANDLER Handler) {
    EXCEPTION_REGISTRATION_RECORD* newRecord;

    newRecord = (EXCEPTION_REGISTRATION_RECORD*)ExAllocatePool(NonPagedPool, sizeof(EXCEPTION_REGISTRATION_RECORD));
    if (!newRecord) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    newRecord->Next = (EXCEPTION_REGISTRATION_RECORD*)__readfsdword(0x0); 
    newRecord->Handler = Handler;
    __writefsdword(0x0, (DWORD)newRecord); 

    return STATUS_SUCCESS;
}

VOID UnregisterExceptionHandler(PFN_EXCEPTION_HANDLER Handler) {
    EXCEPTION_REGISTRATION_RECORD* currentRecord = (EXCEPTION_REGISTRATION_RECORD*)__readfsdword(0x0);
    EXCEPTION_REGISTRATION_RECORD* prevRecord = NULL;

    while (currentRecord) {
        if (currentRecord->Handler == Handler) {
            if (prevRecord) {
                prevRecord->Next = currentRecord->Next;
            } else {
                __writefsdword(0x0, (DWORD)currentRecord->Next);
            }
            ExFreePool(currentRecord);
            return;
        }
        prevRecord = currentRecord;
        currentRecord = currentRecord->Next;
    }
}

#endif 
