#include "global.h"

#define ONEPARAM_ROUTINE_RELEASEDC 0x39UL
#define IOCTL_BEEP_SET 0x10000

typedef NTSTATUS(*PSYSCALL_STUB)(ULONG, ...);

typedef struct _BEEPINFO {
	ULONG frequency;
	ULONG duration;
}BEEP_INFO, *PBEEP_INFO;

void debugMessage(PULONGLONG pDebugNum, ULONGLONG message1, ULONGLONG message2);
void payloadRoutineBegin(void) {
	LARGE_INTEGER interval;
	ULONGLONG debugNum = 1;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PULONG pSyscallArray = (PULONG)((ULONG_PTR)payloadRoutineBegin - 0xA0);
	PSYSCALL_STUB fpSyscallStub = (PSYSCALL_STUB)((ULONG_PTR)payloadRoutineBegin - 0xE0);

	//debugMessage(&hBeepDevice, 0, 0);
	interval.QuadPart = -10000000;

payloadLoop:
	status = fpSyscallStub(pSyscallArray[0], FALSE, &interval);
	debugMessage(&debugNum, 25843, 253423);
	//debugMessage(&hBeepDevice, STATUS_SUCCESS, status);
	status = fpSyscallStub(pSyscallArray[0], FALSE, NULL);
	debugMessage(&debugNum, 2543, 253423);
	//debugMessage(&hBeepDevice, STATUS_SUCCESS, status);
	goto payloadLoop;
}
void debugMessage(PULONGLONG pDebugNum, ULONGLONG message1, ULONGLONG message2) {
	UNICODE_STRING uSemName;
	OBJECT_ATTRIBUTES semAttr;
	LARGE_INTEGER interval;
	HANDLE hSem = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PULONG pSyscallArray = (PULONG)((ULONG_PTR)payloadRoutineBegin - 0xA0);
	ULONGLONG debugNum = (ULONGLONG)*pDebugNum;
	//PWSTR pBeepDeviceName = (PWSTR)((ULONG_PTR)pSyscallArray + 0x40);
	PSYSCALL_STUB fpSyscallStub = (PSYSCALL_STUB)((ULONG_PTR)payloadRoutineBegin - 0xE0);
	WCHAR puffer[] = { '\\','B','a','s','e','N','a','m','e','d','O','b','j','e','c','t','s','\\','B','l','a','h','q', 0x0 };
	//puffer
	//L"\\BaseNamedObjects\\Blahh"

	uSemName.Buffer = puffer;
	uSemName.Length = sizeof(puffer) - sizeof(UNICODE_NULL);
	uSemName.MaximumLength = sizeof(puffer);
	*pDebugNum = (*pDebugNum) + 1;
	if (((WCHAR*)pDebugNum)[0] == 0) {
		((WCHAR*)pDebugNum)[0] = 1;
		*pDebugNum = (*pDebugNum) + 1;
	}
	if (((WCHAR*)pDebugNum)[1] == 0) {
		((WCHAR*)pDebugNum)[1] = 1;
		*pDebugNum = (*pDebugNum) + 1;
	}
	if (((WCHAR*)pDebugNum)[2] == 0) {
		((WCHAR*)pDebugNum)[2] = 1;
		*pDebugNum = (*pDebugNum) + 1;
	}
	if (((WCHAR*)pDebugNum)[3] == 0) {
		((WCHAR*)pDebugNum)[3] = 1;
		*pDebugNum = (*pDebugNum) + 1;
	}



	//for (ULONG i = 0; i < 4; i++) {
	//	if ((((WCHAR*)pDebugNum)[i] == 0) || (((WCHAR*)pDebugNum)[i] == 0xFFFE) || (((WCHAR*)pDebugNum)[i] == 0xFFFF)) {
	//		*pDebugNum = (*pDebugNum) + 1;
	//		i--;
	//	}
	//}
	debugNum = (ULONGLONG)*pDebugNum;	
	*(PULONGLONG)&puffer[sizeof(puffer) / sizeof(WCHAR) - 6] = debugNum;
	//if (puffer[sizeof(puffer) / sizeof(WCHAR) - 6] == 0) {
	//	puffer[sizeof(puffer) / sizeof(WCHAR) - 6] = 1;
	//}

	//if (50 < *pDebugNum) {
	//	*pDebugNum = 1;
	//}

	//puffer[sizeof(puffer) / sizeof(WCHAR) - 4] = 0x41 + ((WCHAR*)&message1)[0] / 26;
	//puffer[sizeof(puffer) / sizeof(WCHAR) - 3] = 0x41 + ((WCHAR*)&message1)[1] / 26;
	//(*pBeepDevice)++;
	interval.QuadPart = -15000000;
	//CLIENT_ID cid;
	//cid.UniqueProcess = (HANDLE)0x58934020;
	//if (!pBeepDevice)
	//break;
	InitializeObjectAttributes(&semAttr, &uSemName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	//fpSyscallStub(pSyscallArray[5], pBeepDevice, &semAttr, &cid);
	////InitializeObjectAttributes(&semAttr, &uSemName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	fpSyscallStub(pSyscallArray[6],&hSem, MUTANT_ALL_ACCESS, &semAttr, TRUE);
//	status = fpSyscallStub(pSyscallArray[4], &hSem, SEMAPHORE_ALL_ACCESS, &semAttr, 0x3FFFFFFF, 0x7FFFFFFF);
	fpSyscallStub(pSyscallArray[0], FALSE, &interval);
	//if (!status)
	//	fpSyscallStub(pSyscallArray[3], hSem);
			
	//myWPrintf();
	//do {




	//		

	//	if(status)
	//		fpSyscallStub
	//	//
	//	status = fpSyscallStub(pSyscallArray[4], pBeepDevice, SEMAPHORE_ALL_ACCESS, &semAttr, 0, 0x7FFFFFFF);
	//	if (status) {

	//	//status = fpSyscallStub(pSyscallArray[1], pBeepDevice, FILE_READ_ACCESS | FILE_WRITE_ACCESS | SYNCHRONIZE, &beepDevAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
	//		if (status)
	//			break;


	//	//				break;
	//	//
	//	//			beepInfo.frequency = 3000;
	//	}
	//		
	//	//		else {
	//	//			if (message1 == message2)
	//	//				beepInfo.frequency = 300;
	//	//			else
	//	//				beepInfo.frequency = 1000;
	//	//		}
	//	//
	//	//		beepInfo.duration = 500;
	//	//		status = fpSyscallStub(pSyscallArray[2], *pBeepDevice, NULL, NULL, NULL, &ioSb, IOCTL_BEEP_SET, &beepInfo, sizeof(BEEP_INFO), NULL, 0);
	//	//		if (status)
	//	//			break;
	//	//
	//	//		fpSyscallStub(pSyscallArray[0], FALSE, &interval);
		//	} while (status);
}
//void debugMessage(PHANDLE pBeepDevice, ULONGLONG message1, ULONGLONG message2) {
//	UNICODE_STRING uBeepDevName;
//	OBJECT_ATTRIBUTES beepDevAttr;
//	IO_STATUS_BLOCK ioSb;
//	BEEP_INFO beepInfo;
//	LARGE_INTEGER interval;
//	PULONG pSyscallArray = (PULONG)((ULONG_PTR)payloadRoutineBegin - 0xA0);
//	PWSTR pBeepDeviceName = (PWSTR)((ULONG_PTR)pSyscallArray + 0x40);
//	PSYSCALL_STUB fpSyscallStub = (PSYSCALL_STUB)((ULONG_PTR)payloadRoutineBegin - 0xE0);
//	NTSTATUS status = 0xFFFFFFFF;
//	UINT messageBeepSound = 0xFFFFFFFF;
//
//	interval.QuadPart = -6000000;
//
//	uBeepDevName.Buffer = pBeepDeviceName;
//	uBeepDevName.MaximumLength = 26;
//	uBeepDevName.Length = 24;
//
//	InitializeObjectAttributes(&beepDevAttr, &uBeepDevName, OBJ_CASE_INSENSITIVE, NULL, NULL);
//
//	do {
//		if (!pBeepDevice)
//			break;
//
//		if (!*pBeepDevice) {
//			status = fpSyscallStub(pSyscallArray[1], pBeepDevice, FILE_READ_ACCESS | FILE_WRITE_ACCESS | SYNCHRONIZE, &beepDevAttr, &ioSb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
//			if (status)
//				break;
//
//			beepInfo.frequency = 3000;
//		}
//		else {
//			if (message1 == message2)
//				beepInfo.frequency = 300;
//			else
//				beepInfo.frequency = 1000;
//		}
//
//		beepInfo.duration = 500;
//		status = fpSyscallStub(pSyscallArray[2], *pBeepDevice, NULL, NULL, NULL, &ioSb, IOCTL_BEEP_SET, &beepInfo, sizeof(BEEP_INFO), NULL, 0);
//		if (status)
//			break;
//
//		fpSyscallStub(pSyscallArray[0], FALSE, &interval);
//	} while (status);
//
//	if (status) {
//		if (NT_ERROR(status))
//			messageBeepSound = MB_ICONERROR;
//		else if (NT_WARNING(status))
//			messageBeepSound = MB_ICONEXCLAMATION;
//		else if (NT_INFORMATION(status))
//			messageBeepSound = MB_ICONINFORMATION;
//
//		fpSyscallStub(0x1005, messageBeepSound, ONEPARAM_ROUTINE_RELEASEDC);
//	}
//}
ULONG_PTR payloadRoutineEnd(void) {
	return (ULONG_PTR)payloadRoutineEnd;
}