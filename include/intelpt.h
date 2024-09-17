#ifndef _INTELPT_H_
#define _INTELPT_H_

#include <ntddk.h>

NTSTATUS EnableIntelPT();
NTSTATUS DisableIntelPT();
void DumpTraceBuffer();
void ReadIntelPTStatus();

#endif 
