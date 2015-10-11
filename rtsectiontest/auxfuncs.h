#pragma once
//extern NTSTATUS syscallStub(ULONG syscallNum, ...);
//__forceinline extern void myTerminate(void);
extern BOOLEAN mymemcmp(PVOID src1, PVOID src2, SIZE_T length);
extern ULONG injectionCode;
extern ULONG_PTR originalSyscallCode;
extern void fpCreatePayloadThread(ULONG_PTR payloadCodeAddress);
//extern void fpBootstrapRoutine(void);
extern PVOID createPayloadThreadBegin;
extern PVOID createPayloadThreadEnd;
extern UCHAR bootstrapRoutineBegin;
extern UCHAR bootstrapRoutineEnd;
extern SIZE_T protSize;
extern ULONG ntCreateThreadExNumber;
extern ULONG ntProtectVirtMemNumber;
extern ULONG origProt;
extern ULONG_PTR ldrInitializeThunkAddr;
extern ULONG_PTR ntdllRxBaseAddr;
