.data

bootstrapCodeBegin PROC
bootstrapCodeBegin ENDP
	mov rax, [rsp]							;Retrieve return address saved by caller (injectionHookAddress + 8)
	dw 0BB48h								;rbx = *g_originalSyscallCode	
g_originalSyscallCode PROC
		dq 0CCCCCCCCCCCCCCCCh				;Original code of syscall stub
g_originalSyscallCode ENDP
	lock xchg qword ptr [rax - 8], rbx		;Restore original syscall stub code as soon as possible!
	;nop qword ptr [rax+40000000h]
	nop
	nop
	nop
	nop
	;int 3
	;dw 0FEEBh
;int  3
	sub rsp, 28h							;Correct the stack so we don't get into trouble if we call high level functions later on 
	db 0E9h									;jmp to our true C code payload routine. If we used the external address of our C payload routine
											;by doing something with "EXTRN" keyword in masm the jmp would have a (indirect) connection to the
											;injector base address which is bad for PIC code that runs within a completely other process.
	dd 000000E0h							;Therefore, the jmp width needs to be hardcoded. The injector itself copies the payload
											;code at the expected address.
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
	dd 0CCCCCCCCh	;Alignment
	;0x40h:
;g_ldrGetProcedureAddress PROC
	dq 1111111111111111h
;g_ldrGetProcedureAddress ENDP
	nonNtAddresses QWORD 3 dup (?)
	syscallArray QWORD 8 dup (?)
	;beepDevice dw '\','D','e','v','!','c','e','_','B','e','e','p',0
	beepDevice dw '\','B','a','s','e','N','a','m','e','d','O','b','j','e','c','t','s','\','B','l','a','h','h',0
bootstrapCodeEnd PROC
bootstrapCodeEnd ENDP
END
