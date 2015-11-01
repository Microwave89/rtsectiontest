#pragma once
extern BYTE bootstrapCodeBegin;
extern BYTE bootstrapCodeEnd;

extern ULONGLONG g_originalSyscallCode;
extern ULONG_PTR g_ldrGetProcedureAddress;
ULONG_PTR g_bootstrapCodeBegin = (ULONG_PTR)&bootstrapCodeBegin;
ULONG_PTR g_bootstrapCodeEnd = (ULONG_PTR)&bootstrapCodeEnd;