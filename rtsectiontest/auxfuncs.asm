.data
getReturnAddress PROC
	
	mov eax, ecx
	mov r10, rdx
	mov rdx, r8
	mov r8, r9
	mov r9, qword ptr [rsp+28h]
	add rsp, 8
	syscall
	sub rsp, 8
	ret
getReturnAddress ENDP
	int 3
	int 3
	int 3
	int 3
	int 3
bootstrapCodeBegin PROC
bootstrapCodeBegin ENDP
	int 3
syscallStub PROC
	mov eax, ecx
	mov r10, rdx
	mov rdx, r8
	mov r8, r9
	mov r9, qword ptr [rsp+28h]
	add rsp, 8
	syscall
	sub rsp, 8
	ret
syscallStub ENDP
g_returnInstruction PROC
	num0 db 0CCh, 0CCh, 0CCh, 0CCh
g_returnInstruction ENDP
g_resumationHandle PROC
	dd 0CCCCCCCCh
		num1 dd 0CCCCCCCCh	
g_resumationHandle ENDP
syscallNumberArray PROC	;0x20
	num2 dd 0CCCCCCCCh	
	num3 dd 0CCCCCCCCh
	num4 dd 0CCCCCCCCh
	num5 dd 0CCCCCCCCh	;0x30
	num6 dd 0CCCCCCCCh
	num7 dd 0CCCCCCCCh
	num8 dd 0CCCCCCCCh
	num9 dd 0CCCCCCCCh	;0x40
	num10 dd 0CCCCCCCCh
	num11 dd 0CCCCCCCCh
syscallNumberArray ENDP
additionalData PROC
	dq 0CCCCCCCCCCCCCCCCh
	dq 0CCCCCCCCCCCCCCCCh
	dq 0CCCCCCCCCCCCCCCCh
	dq 0CCCCCCCCCCCCCCCCh
	dq 0CCCCCCCCCCCCCCCCh
	dq 0CCCCCCCCCCCCCCCCh
additionalData ENDP	;0x7F

bootstrapCodeEnd PROC
bootstrapCodeEnd ENDP
END
