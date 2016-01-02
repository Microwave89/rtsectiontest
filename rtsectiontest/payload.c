#include "global.h"


//#define ONEPARAM_ROUTINE_RELEASEDC 0x39UL
//#define IOCTL_BEEP_SET 0x10000

typedef NTSTATUS(*PSYSCALL_STUB)(ULONG, ...);

//typedef struct _BEEPINFO {
//	ULONG frequency;
//	ULONG duration;
//}BEEP_INFO, *PBEEP_INFO;
#pragma pack(push, 1)   // n = 16, pushed to stack
typedef struct _INJECT_RUNTIME {
	BYTE padding;
	BYTE syscallCode[0x1B];
	BYTE returnInstruction[4];
	HANDLE hRemoteEvent;
	ULONG ntWaitForSingleObject;
	ULONG ntSetEvent;
	ULONG otherSyscalls[8];
	//ULONG syscallArray[10];
	BYTE additionalData[0x30];
}INJECT_RUNTIME, *PINJECT_RUNTIME;
#pragma pack(pop)   // n = 2 , stack popped

//void debugMessage(PULONGLONG pDebugNum, ULONGLONG message1, ULONGLONG message2);
//#pragma code_seg(".text")
//__declspec(allocate(".text")) BYTE payloadRoutineBegin[] = { 0x48, 0x83, 0xEC, 0x48, 0x48, 0x8D, 0x05, 0x65, 0x01, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x20, 0x1A, 0x00, 0x1C, 0x00, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8D, 0x05, 0x71, 0x01, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0xC7, 0x44, 0x24, 0x30, 0x36, 0x00, 0x38, 0x00, 0x41, 0xB8, 0x18, 0x00, 0x00, 0x40, 0x48, 0x8D, 0x54, 0x24, 0x30, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xE8, 0x27, 0x00, 0x00, 0x00, 0x41, 0xB8, 0x18, 0x00, 0x00, 0x40, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xE8, 0x12, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x41, 0xB8, 0x05, 0x00, 0x00, 0xC0, 0x33, 0xC9, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xEB, 0xC5, 0xCC, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8B, 0xEC, 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x45, 0x8B, 0xF0, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0x44, 0x8D, 0x7B, 0x04, 0x83, 0xFB, 0x4A, 0x0F, 0x84, 0x84, 0x00, 0x00, 0x00, 0x48, 0x85, 0xF6, 0xC7, 0x45, 0xC8, 0x02, 0x00, 0x04, 0x00, 0x48, 0xB8, 0x43, 0x65, 0x28, 0x97, 0x24, 0x68, 0x79, 0x13, 0xC7, 0x45, 0x38, 0x3F, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xC0, 0x4C, 0x8D, 0x15, 0x8C, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x45, 0x38, 0x48, 0xC7, 0x45, 0xE8, 0x40, 0x10, 0x00, 0x00, 0x48, 0x89, 0x45, 0xD0, 0x41, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x45, 0xC8, 0x48, 0xC7, 0x45, 0xF0, 0xD0, 0x07, 0x00, 0x00, 0x48, 0x0F, 0x45, 0xC6, 0x45, 0x8B, 0xC7, 0x48, 0x89, 0x45, 0xD8, 0x48, 0x85, 0xFF, 0x48, 0x8D, 0x45, 0xC8, 0x41, 0x8B, 0xD6, 0x48, 0x0F, 0x45, 0xC7, 0x8B, 0xCB, 0x48, 0x89, 0x45, 0xE0, 0x48, 0x8D, 0x45, 0xC0, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8D, 0x45, 0xD8, 0xC7, 0x44, 0x24, 0x28, 0x05, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x41, 0xFF, 0xD2, 0xFF, 0xC3, 0x81, 0xFB, 0x00, 0x10, 0x00, 0x00, 0x0F, 0x82, 0x65, 0xFF, 0xFF, 0xFF, 0x4C, 0x8D, 0x9C, 0x24, 0x80, 0x00, 0x00, 0x00, 0x49, 0x8B, 0x5B, 0x20, 0x49, 0x8B, 0x73, 0x28, 0x49, 0x8B, 0x7B, 0x30, 0x49, 0x8B, 0xE3, 0x41, 0x5F, 0x41, 0x5E, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0x89, 0xC8, 0x49, 0x89, 0xD2, 0x4C, 0x89, 0xC2, 0x4D, 0x89, 0xC8, 0x4C, 0x8B, 0x4C, 0x24, 0x28, 0x48, 0x83, 0xC4, 0x08, 0x90, 0x0F, 0x05, 0x48, 0x83, 0xEC, 0x08, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x53, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x63, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x65, 0x00, 0x20, 0x00, 0x3D, 0x00, 0x29, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x69, 0x00, 0x20, 0x00, 0x66, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x20, 0x00, 0x6E, 0x00, 0x6F, 0x00, 0x2D, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x20, 0x00, 0x73, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x63, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x65, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
void payloadRoutineBegin(void) {
	ULONG_PTR retAddr;
	LONG prevState;
	PINJECT_RUNTIME pInjectRuntime = (PINJECT_RUNTIME)((ULONG_PTR)&payloadRoutineBegin - 0x80);
	PSYSCALL_STUB fpSyscallStub = (PSYSCALL_STUB)&pInjectRuntime->syscallCode;
	
	retAddr = ((ULONG_PTR)_ReturnAddress() - 5);
	*(PBYTE)retAddr = 0xC3;
	//_InterlockedExchange((PLONG)retAddr, *(LONG*)pInjectRuntime->returnInstruction);

	if (_InterlockedCompareExchange16((short*)((ULONG_PTR)NtCurrentPeb() + 0x978), 1, 0x0))
		fpSyscallStub(pInjectRuntime->ntWaitForSingleObject, NtCurrentThread(), FALSE, NULL);

	fpSyscallStub(pInjectRuntime->ntSetEvent, pInjectRuntime->hRemoteEvent, &prevState);



	//__nop();
	//((PBYTE)retAddr)[0] = pInjectRuntime->returnInstruction[0];
	//((PBYTE)retAddr)[1] = pInjectRuntime->returnInstruction[1];
	//((PBYTE)retAddr)[2] = pInjectRuntime->returnInstruction[2];
	//((PBYTE)retAddr)[3] = pInjectRuntime->returnInstruction[3];
	//((PBYTE)retAddr)[4] = pInjectRuntime->returnInstruction[4];
	//HANDLE hRemoteHandle = NULL;
	//PULONG pSyscallArray;
	//PSYSCALL_STUB fpSyscallStub;


	//pSyscallArray = (PULONG)((ULONG_PTR)payloadRoutineBegin - 0x58);


	//((PBYTE)retAddr)[1] = ((PBYTE)(pSyscallArray - 3))[1];
	//((PBYTE)retAddr)[2] = ((PBYTE)(pSyscallArray - 3))[2];


	//fpSyscallStub = (PSYSCALL_STUB)((ULONG_PTR)payloadRoutineBegin - 0x7F);

	//hRemoteHandle = *(PHANDLE)(pSyscallArray - 1);
	//((PULONG)&hRemoteHandle)[1] = 0x0;

	
	//NtResumeProcess()
	//NtCreateMutant()
	//LARGE_INTEGER interval;
	//ULONGLONG debugNum = 1;
	//NTSTATUS status = STATUS_UNSUCCESSFUL;
	//PULONG pSyscallArray = (PULONG)((ULONG_PTR)payloadRoutineBegin - 0xA0);
	//PSYSCALL_STUB fpSyscallStub = (PSYSCALL_STUB)((ULONG_PTR)payloadRoutineBegin - 0xE0);
	//OBJECT_ATTRIBUTES procAttr;
	//HANDLE hProc = NULL;
	//InitializeObjectAttributes(&procAttr, NULL, 0, NULL, NULL);
	////debugMessage(&hBeepDevice, 0, 0);
	//ULONG_PTR currPid = 0;
	//interval.QuadPart = -500000;
	//CLIENT_ID cid;
	//cid.UniqueThread = NULL;
	//cid.UniqueProcess = NULL;
	//ULONG suspCount;
	//short alreadyExecuted = 0x0;

	//NtCurrentTeb()
	//alreadyExecuted = _InterlockedCompareExchange16((SHORT*)((ULONG_PTR)NtCurrentTeb() + 0x2D0), 0x1, 0x0);
	////alreadyExecuted = __readgsbyte(0x2D0);
	//if (alreadyExecuted) {
	//	go1:
	//	__nop();
	//	goto go1;
	//}
	//	//fpSyscallStub(pSyscallArray[0], NtCurrentThread(), &suspCount);

	////__writegsbyte(0x2D0, 0x1);

	//currPid += 4;
	//cid.UniqueProcess = (HANDLE)currPid;
	//fpSyscallStub(pSyscallArray[5], &hProc, MAXIMUM_ALLOWED, &procAttr, &cid);
	////if (alreadyExecuted) {
	////go1:
	////	__nop();
	////	goto go1;
	////}
payloadLoop:
	//fpSyscallStub(0x657, FALSE, NtCurrentThread());
	//status = fpSyscallStub(pSyscallArray[0], FALSE, &interval);
	//debugMessage(&debugNum, 25843, 253423);
	__nop();
	__writegsqword(0x2D0, 0x126783E789A);
	//__readeflags();
	__nop();
	__nop();

	////debugMessage(&hBeepDevice, STATUS_SUCCESS, status);
	//status = fpSyscallStub(pSyscallArray[0], FALSE, NULL);
	//debugMessage(&debugNum, 2543, 253423);
	//debugMessage(&hBeepDevice, STATUS_SUCCESS, status);
	goto payloadLoop;
}
//void debugMessage(PULONGLONG pDebugNum, ULONGLONG message1, ULONGLONG message2) {
//	UNICODE_STRING uSemName;
//	OBJECT_ATTRIBUTES semAttr;
//	LARGE_INTEGER interval;
//	HANDLE hSem = NULL;
//	NTSTATUS status = STATUS_UNSUCCESSFUL;
//	PULONG pSyscallArray = (PULONG)((ULONG_PTR)payloadRoutineBegin - 0xA0);
//	ULONGLONG debugNum = (ULONGLONG)*pDebugNum;
//	//PWSTR pBeepDeviceName = (PWSTR)((ULONG_PTR)pSyscallArray + 0x40);
//	PSYSCALL_STUB fpSyscallStub = (PSYSCALL_STUB)((ULONG_PTR)payloadRoutineBegin - 0xE0);
//	WCHAR puffer[] = { '\\','B','a','s','e','N','a','m','e','d','O','b','j','e','c','t','s','\\','B','l','a','h','q', 0x0 };
//	//puffer
//	//L"\\BaseNamedObjects\\Blahh"
//
//	uSemName.Buffer = puffer;
//	uSemName.Length = sizeof(puffer) - sizeof(UNICODE_NULL);
//	uSemName.MaximumLength = sizeof(puffer);
//	*pDebugNum = (*pDebugNum) + 1;
//	if (((WCHAR*)pDebugNum)[0] == 0) {
//		((WCHAR*)pDebugNum)[0] = 1;
//		*pDebugNum = (*pDebugNum) + 1;
//	}
//	if (((WCHAR*)pDebugNum)[1] == 0) {
//		((WCHAR*)pDebugNum)[1] = 1;
//		*pDebugNum = (*pDebugNum) + 1;
//	}
//	if (((WCHAR*)pDebugNum)[2] == 0) {
//		((WCHAR*)pDebugNum)[2] = 1;
//		*pDebugNum = (*pDebugNum) + 1;
//	}
//	if (((WCHAR*)pDebugNum)[3] == 0) {
//		((WCHAR*)pDebugNum)[3] = 1;
//		*pDebugNum = (*pDebugNum) + 1;
//	}
//
//
//
//	//for (ULONG i = 0; i < 4; i++) {
//	//	if ((((WCHAR*)pDebugNum)[i] == 0) || (((WCHAR*)pDebugNum)[i] == 0xFFFE) || (((WCHAR*)pDebugNum)[i] == 0xFFFF)) {
//	//		*pDebugNum = (*pDebugNum) + 1;
//	//		i--;
//	//	}
//	//}
//	debugNum = (ULONGLONG)*pDebugNum;	
//	*(PULONGLONG)&puffer[sizeof(puffer) / sizeof(WCHAR) - 6] = debugNum;
//	//if (puffer[sizeof(puffer) / sizeof(WCHAR) - 6] == 0) {
//	//	puffer[sizeof(puffer) / sizeof(WCHAR) - 6] = 1;
//	//}
//
//	//if (50 < *pDebugNum) {
//	//	*pDebugNum = 1;
//	//}
//
//	//puffer[sizeof(puffer) / sizeof(WCHAR) - 4] = 0x41 + ((WCHAR*)&message1)[0] / 26;
//	//puffer[sizeof(puffer) / sizeof(WCHAR) - 3] = 0x41 + ((WCHAR*)&message1)[1] / 26;
//	//(*pBeepDevice)++;
//	interval.QuadPart = -15000000;
//	//CLIENT_ID cid;
//	//cid.UniqueProcess = (HANDLE)0x58934020;
//	//if (!pBeepDevice)
//	//break;
//	InitializeObjectAttributes(&semAttr, &uSemName, OBJ_CASE_INSENSITIVE, NULL, NULL);
//	//fpSyscallStub(pSyscallArray[5], pBeepDevice, &semAttr, &cid);
//	////InitializeObjectAttributes(&semAttr, &uSemName, OBJ_CASE_INSENSITIVE, NULL, NULL);
//	fpSyscallStub(pSyscallArray[6],&hSem, MUTANT_ALL_ACCESS, &semAttr, TRUE);
////	status = fpSyscallStub(pSyscallArray[4], &hSem, SEMAPHORE_ALL_ACCESS, &semAttr, 0x3FFFFFFF, 0x7FFFFFFF);
//	fpSyscallStub(pSyscallArray[0], FALSE, &interval);
//	//if (!status)
//	//	fpSyscallStub(pSyscallArray[3], hSem);
//			
//	//myWPrintf();
//	//do {
//
//
//
//
//	//		
//
//	//	if(status)
//	//		fpSyscallStub
//	//	//
//	//	status = fpSyscallStub(pSyscallArray[4], pBeepDevice, SEMAPHORE_ALL_ACCESS, &semAttr, 0, 0x7FFFFFFF);
//	//	if (status) {
//
//	//	//status = fpSyscallStub(pSyscallArray[1], pBeepDevice, FILE_READ_ACCESS | FILE_WRITE_ACCESS | SYNCHRONIZE, &beepDevAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
//	//		if (status)
//	//			break;
//
//
//	//	//				break;
//	//	//
//	//	//			beepInfo.frequency = 3000;
//	//	}
//	//		
//	//	//		else {
//	//	//			if (message1 == message2)
//	//	//				beepInfo.frequency = 300;
//	//	//			else
//	//	//				beepInfo.frequency = 1000;
//	//	//		}
//	//	//
//	//	//		beepInfo.duration = 500;
//	//	//		status = fpSyscallStub(pSyscallArray[2], *pBeepDevice, NULL, NULL, NULL, &ioSb, IOCTL_BEEP_SET, &beepInfo, sizeof(BEEP_INFO), NULL, 0);
//	//	//		if (status)
//	//	//			break;
//	//	//
//	//	//		fpSyscallStub(pSyscallArray[0], FALSE, &interval);
//		//	} while (status);
//}
////void debugMessage(PHANDLE pBeepDevice, ULONGLONG message1, ULONGLONG message2) {
////	UNICODE_STRING uBeepDevName;
////	OBJECT_ATTRIBUTES beepDevAttr;
////	IO_STATUS_BLOCK ioSb;
////	BEEP_INFO beepInfo;
////	LARGE_INTEGER interval;
////	PULONG pSyscallArray = (PULONG)((ULONG_PTR)payloadRoutineBegin - 0xA0);
////	PWSTR pBeepDeviceName = (PWSTR)((ULONG_PTR)pSyscallArray + 0x40);
////	PSYSCALL_STUB fpSyscallStub = (PSYSCALL_STUB)((ULONG_PTR)payloadRoutineBegin - 0xE0);
////	NTSTATUS status = 0xFFFFFFFF;
////	UINT messageBeepSound = 0xFFFFFFFF;
////
////	interval.QuadPart = -6000000;
////
////	uBeepDevName.Buffer = pBeepDeviceName;
////	uBeepDevName.MaximumLength = 26;
////	uBeepDevName.Length = 24;
////
////	InitializeObjectAttributes(&beepDevAttr, &uBeepDevName, OBJ_CASE_INSENSITIVE, NULL, NULL);
////
////	do {
////		if (!pBeepDevice)
////			break;
////
////		if (!*pBeepDevice) {
////			status = fpSyscallStub(pSyscallArray[1], pBeepDevice, FILE_READ_ACCESS | FILE_WRITE_ACCESS | SYNCHRONIZE, &beepDevAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
////			if (status)
////				break;
////
////			beepInfo.frequency = 3000;
////		}
////		else {
////			if (message1 == message2)
////				beepInfo.frequency = 300;
////			else
////				beepInfo.frequency = 1000;
////		}
////
////		beepInfo.duration = 500;
////		status = fpSyscallStub(pSyscallArray[2], *pBeepDevice, NULL, NULL, NULL, &ioSb, IOCTL_BEEP_SET, &beepInfo, sizeof(BEEP_INFO), NULL, 0);
////		if (status)
////			break;
////
////		fpSyscallStub(pSyscallArray[0], FALSE, &interval);
////	} while (status);
////
////	if (status) {
////		if (NT_ERROR(status))
////			messageBeepSound = MB_ICONERROR;
////		else if (NT_WARNING(status))
////			messageBeepSound = MB_ICONEXCLAMATION;
////		else if (NT_INFORMATION(status))
////			messageBeepSound = MB_ICONINFORMATION;
////
////		fpSyscallStub(0x1005, messageBeepSound, ONEPARAM_ROUTINE_RELEASEDC);
////	}
////}
ULONG_PTR payloadRoutineEnd(void) {
	return (ULONG_PTR)payloadRoutineEnd;
}