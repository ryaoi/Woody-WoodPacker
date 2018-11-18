  global rc4

	segment .data

rc4:
	push rbp
	mov rbp, rsp
	sub rsp, 0x188
	mov r9, rdx
	mov r8d, 0x0
j1:
	mov byte [rsp+r8*1+0x88], r8b
	mov eax, r8d
	cdq
	idiv esi
	movsxd rdx, edx
	movzx eax, byte [rdi+rdx*1]
	mov byte [rsp+r8*1-0x78],al
	add r8, 0x1
	cmp r8,0x100
	jne j1
	mov edx, 0x0
	mov esi, 0x0
	lea r8, [rsp-0x78]
j2:
	movzx edi, byte [rsp+rdx*1+0x88]
	movzx eax, dil
	add eax, esi
	movzx esi, byte [rdx+r8*1]
	add eax, esi
	mov esi, eax
	sar esi, 0x1f
	shr esi, 0x18
	add eax, esi
	movzx eax,al
	sub eax,esi
	mov esi, eax
	cdqe
	movzx r10d, byte [rsp+rax*1+0x88]
	mov [rsp+rdx*1+0x88], r10b
	mov [rsp+rax*1+0x88], dil
	add rdx,0x1
	cmp rdx,0x100
	jne j2
	test ecx,ecx
	jle j3
	lea eax, [rcx-0x1]
	lea rdi, [r9+rax*1+0x1]
	xor edx, edx
	xor eax, eax
j4:
	add rax, 0x1
	movzx eax,al
	movzx ecx, byte [rsp+rax*1+0x88]
	add edx, ecx
	movzx edx,dl
	movzx esi, byte [rsp+rdx*1+0x88]
	mov [rsp+rax*1+0x88], sil
	mov [rsp+rdx*1+0x88], cl
	add cl, [rsp+rax*1+0x88]
	xor [r9],cl
	add r9, 1
	cmp rdi,r9
	jne j4
j3:
	add rsp,0x188
	leave
	ret
