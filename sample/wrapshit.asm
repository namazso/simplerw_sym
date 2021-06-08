.code

PUBLIC wrapperNtOpenEvent

; the syscall handler only saves these registers explicitly: rbx, rdi, rsi, rbp
; the rest are saved like normal nonvolatile registers are by subsequent functions
; thus we use rbx and rdi: rbx for magic, rdi for the commands

wrapperNtOpenEvent PROC
	mov r10, rcx
	mov eax, r9d
	xchg QWORD PTR [rsp + 28h], rbx
	xchg QWORD PTR [rsp + 30h], rdi
	syscall
	mov rbx, QWORD PTR [rsp + 28h]
	mov rdi, QWORD PTR [rsp + 30h]
	ret
wrapperNtOpenEvent ENDP

end