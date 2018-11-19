# WoodyWoodpacker
This packer encrypt the .text section and print a message "....WOODY.....". p.s. It doesn't pack!!!!
Useful? Not really...
But this project will help you discover the world of ELF.

## Some explanation

Their is multiple way of patching binary:
- .NOTE Section Overwriting
- Section Adding
- Segment Padding
- Section Padding
- Code cave

We will do section adding to be able to handle all kind of binary.
Others depends on the size / padding etc etc.. so some binary wont let us patch.

### Elf description

[Elf Header][Program header * n times][Sections][Section header * m times]

Elf Header describe about the type of file, if its 32, 64bit, where is the entrypoint etc...
Program header describe about how to map files to memory, their rights their size etc...
Sections headers describe abour each section, for example section header for text will describe about the offset of .text,
size etc...

Important tips: section headers are useless for execution so u cant delete it when u create a malware, it will be hard to reverse engineer if section headers are missing :)

### Patch a binary?

You might wonder "how do you patch a binary ?"

Well, u stick a bytecode which contain instruction to execute.

for example `ret` instruction got a value which is `c3` so u stick  the hex value `c3` to the binary.
That's all.

## Let's go!

Let's talk about the exection flow.

We will encrypt the text section so if we let our program execute, then it will probrably crash.
We need to first execute the decoder then execute the normal execution.
But How?
Well, elf header contain the entrypoint and entrypoint is a virtual address which the program should start.
It is often at text section.
If we modify the entrypoint to 0xAAAA then it will go to the address 0xAAAA and execute.

Now we can see what we can do.
Let's modify this entrypoint so that it will first go to our decrypter then continue with the normal execution!


First thing to do is add new section which will describe about our new section aka decrypter!
Where shall we put?

Why not put at before `.bss` ? So that we won't need to modify other offset!
```
[text][data][bss][shstrtab]
[text][data][bss][OUR_NEW_SECTION][shstrtab]
```

Our new section should:
- save registers
- print("....WOODY.....")
- decrypt the text section (in our case we will sue rc4, easy to code :P)
- jmp to the text section to continue the execution flow

```
  global _start

  segment .text

_test:
	ret

_start:
	pushfq
	push rax
	push rdi
	push rsi
	push rsp
	push rdx
	push rcx
	push r8
	push r9
	push r10
	mov edi, 1
	jmp woody
back:
	pop rsi
	mov edx, 0x10
	mov rax, rdi
	syscall
	jmp key
get_key:
	pop rdi
	mov rsi, 0x0000000000000001
	lea rdx, [rel _test]
	mov rcx, 0x0000000000000001

	; start rc4

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

	;end rc4

	pop r10
	pop r9
	pop r8
	pop rcx
	pop rdx
	pop rsp
	pop rsi
	pop rdi
	pop rax
	popfq
	jmp    0x4003e0
woody:
	call back
	.string db "....WOODY.....", 10, 00

key:
	call get_key
	.string db "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 00
```



```
root@debian-ryaoi:~/woody-woodpacker# nasm -felf64 test.asm
root@debian-ryaoi:~/woody-woodpacker# ld -melf_x86_64 test.o
root@debian-ryaoi:~/woody-woodpacker# radare2 -A a.out
Warning: Cannot initialize dynamic strings
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[x] Use -AA or aaaa to perform additional experimental analysis.
 -- Try pressing the pigeon-shaped button
[0x00400081]> afl
0x00400081    1 23   -> 44   entry0
0x00400098    1 16   -> 21   loc.back
0x004000a8    8 269          loc.get_key
0x004001b5    1 21           loc.woody
0x004001ca    1 5            loc.key
[0x00400081]> s entry0
[0x00400081]> pdf
            ;-- _start:
            ;-- rip:
/ (fcn) entry0 44
|   entry0 ();
|           0x00400081      9c             pushfq
|           0x00400082      50             push rax
|           0x00400083      57             push rdi
|           0x00400084      56             push rsi
|           0x00400085      54             push rsp
|           0x00400086      52             push rdx
|           0x00400087      51             push rcx
|           0x00400088      4150           push r8
|           0x0040008a      4151           push r9
|           0x0040008c      4152           push r10
|           0x0040008e      bf01000000     mov edi, 1
\       ,=< 0x00400093      e91d010000     jmp loc.woody
..
[0x00400081]> pc 387
#define _BUFFER_SIZE 387
const uint8_t buffer[387] = {
  0x9c, 0x50, 0x57, 0x56, 0x54, 0x52, 0x51, 0x41, 0x50, 0x41,
  0x51, 0x41, 0x52, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x1d,
  0x01, 0x00, 0x00, 0x5e, 0xba, 0x10, 0x00, 0x00, 0x00, 0x48,
  0x89, 0xf8, 0x0f, 0x05, 0xe9, 0x22, 0x01, 0x00, 0x00, 0x5f,
  0xbe, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, 0xcb, 0xff,
  0xff, 0xff, 0xb9, 0x01, 0x00, 0x00, 0x00, 0x48, 0x81, 0xec,
  0x88, 0x01, 0x00, 0x00, 0x49, 0x89, 0xd1, 0x41, 0xb8, 0x00,
  0x00, 0x00, 0x00, 0x46, 0x88, 0x84, 0x04, 0x88, 0x00, 0x00,
  0x00, 0x44, 0x89, 0xc0, 0x99, 0xf7, 0xfe, 0x48, 0x63, 0xd2,
  0x0f, 0xb6, 0x04, 0x17, 0x42, 0x88, 0x44, 0x04, 0x88, 0x49,
  0x83, 0xc0, 0x01, 0x49, 0x81, 0xf8, 0x00, 0x01, 0x00, 0x00,
  0x75, 0xd9, 0xba, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x00, 0x00,
  0x00, 0x00, 0x4c, 0x8d, 0x44, 0x24, 0x88, 0x0f, 0xb6, 0xbc,
  0x14, 0x88, 0x00, 0x00, 0x00, 0x40, 0x0f, 0xb6, 0xc7, 0x01,
  0xf0, 0x42, 0x0f, 0xb6, 0x34, 0x02, 0x01, 0xf0, 0x89, 0xc6,
  0xc1, 0xfe, 0x1f, 0xc1, 0xee, 0x18, 0x01, 0xf0, 0x0f, 0xb6,
  0xc0, 0x29, 0xf0, 0x89, 0xc6, 0x48, 0x98, 0x44, 0x0f, 0xb6,
  0x94, 0x04, 0x88, 0x00, 0x00, 0x00, 0x44, 0x88, 0x94, 0x14,
  0x88, 0x00, 0x00, 0x00, 0x40, 0x88, 0xbc, 0x04, 0x88, 0x00,
  0x00, 0x00, 0x48, 0x83, 0xc2, 0x01, 0x48, 0x81, 0xfa, 0x00,
  0x01, 0x00, 0x00, 0x75, 0xb2, 0x85, 0xc9, 0x7e, 0x4a, 0x8d,
  0x41, 0xff, 0x49, 0x8d, 0x7c, 0x01, 0x01, 0x31, 0xd2, 0x31,
  0xc0, 0x48, 0x83, 0xc0, 0x01, 0x0f, 0xb6, 0xc0, 0x0f, 0xb6,
  0x8c, 0x04, 0x88, 0x00, 0x00, 0x00, 0x01, 0xca, 0x0f, 0xb6,
  0xd2, 0x0f, 0xb6, 0xb4, 0x14, 0x88, 0x00, 0x00, 0x00, 0x40,
  0x88, 0xb4, 0x04, 0x88, 0x00, 0x00, 0x00, 0x88, 0x8c, 0x14,
  0x88, 0x00, 0x00, 0x00, 0x02, 0x8c, 0x04, 0x88, 0x00, 0x00,
  0x00, 0x41, 0x30, 0x09, 0x49, 0x83, 0xc1, 0x01, 0x4c, 0x39,
  0xcf, 0x75, 0xc2, 0x48, 0x81, 0xc4, 0x88, 0x01, 0x00, 0x00,
  0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x59, 0x5a, 0x5c, 0x5e,
  0x5f, 0x58, 0x9d, 0xe9, 0xdc, 0x03, 0x40, 0x00, 0xe8, 0xde,
  0xfe, 0xff, 0xff, 0x2e, 0x2e, 0x2e, 0x2e, 0x57, 0x4f, 0x4f,
  0x44, 0x59, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x0a, 0x00, 0xe8,
  0xd9, 0xfe, 0xff, 0xff, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
  0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
  0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
  0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
  0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x00
};
[0x00400081]>
```

So this will be our new section!
We just need to modify some values so that 

```
	mov rsi, 0x0000000000000001
	lea rdx, [rel _test]
	mov rcx, 0x0000000000000001
```

rsi contain the key length, rdx contain the address of text section because we need to decrypt text section after encryption and rcx which will contain the size of text section.

Ah and also the jmp offset
```
	jmp    0x4003e0
```

This should jump to the entrypoint of the program. So we will modify this value.

Ok so we know the size of this bytecode so let's add our new section header which describe about this section.

```
  [26] .data             PROGBITS         000000000021f380  0001f380
       0000000000000268  0000000000000000  WA       0     0     32
  [27] .bss              PROGBITS         000000000021f600  0001f600
       00000000000011c8  0000000000000000  WA       0     0     32
  [28]                   PROGBITS         00000000002207c8  000207c8
       000000000000015e  0000000000000000  AX       0     0     1
  [29] .gnu_debuglink    PROGBITS         0000000000000000  00020926
       0000000000000034  0000000000000000           0     0     1
  [30] .shstrtab         STRTAB           0000000000000000  0002095a
       000000000000010f  0000000000000000           0     0     1
```

Perfect. (don't forget to shift the sh_offset and sh_vaddr when adding a new section) 

when adding a new section and a new section header, You need to be aware of 2 stuff on the Elf header:
- e_shoff
- e_shnum
- e_shstrndx
- e_entry
__e_shoff__ describe where the section headers start from. We need to add sizeof(decrypter) to the e_shoff
__e_shnum__ describe how many section headers are on the file, we added a new section header so increment this value by 1
__e_shstrndx__ got the index of shstr(section header string) and we added our new section header before `.shstrtab` so don't forget to increment this value.
__e_entry__ describe where the program starts from. Modify this to the our new sections vaddr.


Recap:

- create the decrypter
- add new section
- add new section header
- modify Elf header

So here is going to be the tricky part.
Program header.

```
root@debian-ryaoi:~/woody-woodpacker# readelf -l /bin/ls

Elf file type is DYN (Shared object file)
Entry point 0x5430
There are 9 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                 0x00000000000001f8 0x00000000000001f8  R E    0x8
  INTERP         0x0000000000000238 0x0000000000000238 0x0000000000000238
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x000000000001e184 0x000000000001e184  R E    0x200000
  LOAD           0x000000000001e388 0x000000000021e388 0x000000000021e388
                 0x0000000000001260 0x0000000000002440  RW     0x200000
  DYNAMIC        0x000000000001edb8 0x000000000021edb8 0x000000000021edb8
                 0x00000000000001f0 0x00000000000001f0  RW     0x8
  NOTE           0x0000000000000254 0x0000000000000254 0x0000000000000254
                 0x0000000000000044 0x0000000000000044  R      0x4
  GNU_EH_FRAME   0x000000000001ab74 0x000000000001ab74 0x000000000001ab74
                 0x000000000000082c 0x000000000000082c  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
  GNU_RELRO      0x000000000001e388 0x000000000021e388 0x000000000021e388
                 0x0000000000000c78 0x0000000000000c78  R      0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .jcr .data.rel.ro .dynamic .got .got.plt .data .bss
   04     .dynamic
   05     .note.ABI-tag .note.gnu.build-id
   06     .eh_frame_hdr
   07
   08     .init_array .fini_array .jcr .data.rel.ro .dynamic .got
root@debian-ryaoi:~/woody-woodpacker#
```

This is what program header describe about the binary `/bin/ls`

I want you to look closely to this part
```
  LOAD           0x000000000001e388 0x000000000021e388 0x000000000021e388
                 0x0000000000001260 0x0000000000002440  RW     0x200000
```

Why does the filesz and memsz are diffrent??

Well, because bss doesn't need to be on the file. bss only contains 0 and when u map a page to execute its 0'd so this mean you only need `.init_array .fini_array .jcr .data.rel.ro .dynamic .got .got.plt .data` from the file to be mapped. it's a clever way to reduce the size of file. but wait... our new sections is after bss so that means that it won't get mapped!??
it won't get mapped if u dont increase the size of filesz and memsz. And to reach our decrypter, we need to add the 0'd section to our file so that while executing the program bss wont point over the decrypter. 
```
filesz += bss size + sizeof(decypter)
memsz += sizeof(decrypter)
```

Well... Time to pad some 0's inside the file manually before our decryptor.

Good job if u did it pew...

There is another stuff to modify on the program header.
Default permission for data segment are:

```
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x000000000001e184 0x000000000001e184  R E    0x200000
```

text segment should only be read and executed for protection but we need to decrypt the text section during the execution so we will add write permission to this text segment.


Our decyptor is in the data segment so we will need to add Exection permission!

And that's it!

now u got ur woody ready!


let's try out
```
root@debian-ryaoi:~/woody-woodpacker# readelf -S test_files/small
There are 7 section headers, starting at offset 0x2e8:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .text             PROGBITS         00000000004000b0  000000b0
       000000000000004d  0000000000000000  AX       0     0     16
  [ 2] .data             PROGBITS         0000000000600100  00000100
       0000000000000018  0000000000000000  WA       0     0     4
  [ 3] .bss              NOBITS           0000000000600118  00000118
       0000000000000008  0000000000000000  WA       0     0     4
  [ 4] .symtab           SYMTAB           0000000000000000  00000118
       0000000000000150  0000000000000018           5    10     8
  [ 5] .strtab           STRTAB           0000000000000000  00000268
       000000000000004f  0000000000000000           0     0     1
  [ 6] .shstrtab         STRTAB           0000000000000000  000002b7
       000000000000002c  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
root@debian-ryaoi:~/woody-woodpacker# readelf -l test_files/small

Elf file type is EXEC (Executable file)
Entry point 0x4000b0
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000000fd 0x00000000000000fd  R E    0x200000
  LOAD           0x0000000000000100 0x0000000000600100 0x0000000000600100
                 0x0000000000000018 0x0000000000000020  RW     0x200000

 Section to Segment mapping:
  Segment Sections...
   00     .text
   01     .data .bss
root@debian-ryaoi:~/woody-woodpacker# ./test_files/small
....WOODY.....
root@debian-ryaoi:~/woody-woodpacker#
```

We got a small program which will just printf("....WOODY.....").
Now let's pack it.


```
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker ./test_files/small
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# readelf -S woody
There are 8 section headers, starting at offset 0x44e:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .text             PROGBITS         00000000004000b0  000000b0
       000000000000004d  0000000000000000  AX       0     0     16
  [ 2] .data             PROGBITS         0000000000600100  00000100
       0000000000000018  0000000000000000  WA       0     0     4
  [ 3] .bss              PROGBITS         0000000000600118  00000118
       0000000000000008  0000000000000000  WA       0     0     4
readelf: Warning: [ 4]: Unexpected value (10) in info field.
  [ 4]                   PROGBITS         0000000000600120  00000120
       000000000000015e  0000000000000000  AX       0    10     1
readelf: Warning: [ 5]: Link field (5) should index a string section.
  [ 5] .symtab           SYMTAB           0000000000000000  0000027e
       0000000000000150  0000000000000018           5    10     8
  [ 6] .strtab           STRTAB           0000000000000000  000003ce
       000000000000004f  0000000000000000           0     0     1
  [ 7] .shstrtab         STRTAB           0000000000000000  0000041d
       000000000000002c  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
root@debian-ryaoi:~/woody-woodpacker# readelf -l woody

Elf file type is EXEC (Executable file)
Entry point 0x600120
There are 2 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000000fd 0x00000000000000fd  RWE    0x200000
  LOAD           0x0000000000000100 0x0000000000600100 0x0000000000600100
                 0x000000000000017e 0x000000000000017e  RWE    0x200000

 Section to Segment mapping:
  Segment Sections...
   00     .text
   01     .data .bss
root@debian-ryaoi:~/woody-woodpacker# ./woody
....WOODY.....
....WOODY.....
root@debian-ryaoi:~/woody-woodpacker#
```


Great ! shall we check if the text section is encrypted?

```
root@debian-ryaoi:~/woody-woodpacker# objdump -d test_files/small

test_files/small:     file format elf64-x86-64


Disassembly of section .text:

00000000004000b0 <_start>:
  4000b0:	9c                   	pushfq
  4000b1:	50                   	push   %rax
  4000b2:	57                   	push   %rdi
  4000b3:	56                   	push   %rsi
  4000b4:	54                   	push   %rsp
  4000b5:	52                   	push   %rdx
  4000b6:	51                   	push   %rcx
  4000b7:	41 50                	push   %r8
  4000b9:	41 51                	push   %r9
  4000bb:	41 52                	push   %r10
  4000bd:	bf 01 00 00 00       	mov    $0x1,%edi
  4000c2:	eb 24                	jmp    4000e8 <woody>

00000000004000c4 <back>:
  4000c4:	5e                   	pop    %rsi
  4000c5:	ba 10 00 00 00       	mov    $0x10,%edx
  4000ca:	48 89 f8             	mov    %rdi,%rax
  4000cd:	0f 05                	syscall
  4000cf:	41 5a                	pop    %r10
  4000d1:	41 59                	pop    %r9
  4000d3:	41 58                	pop    %r8
  4000d5:	59                   	pop    %rcx
  4000d6:	5a                   	pop    %rdx
  4000d7:	5c                   	pop    %rsp
  4000d8:	5e                   	pop    %rsi
  4000d9:	5f                   	pop    %rdi
  4000da:	58                   	pop    %rax
  4000db:	9d                   	popfq
  4000dc:	bf 01 00 00 00       	mov    $0x1,%edi
  4000e1:	b8 3c 00 00 00       	mov    $0x3c,%eax
  4000e6:	0f 05                	syscall

00000000004000e8 <woody>:
  4000e8:	e8 d7 ff ff ff       	callq  4000c4 <back>

00000000004000ed <woody.string>:
  4000ed:	2e 2e 2e 2e 57       	cs cs cs cs push %rdi
  4000f2:	4f                   	rex.WRXB
  4000f3:	4f                   	rex.WRXB
  4000f4:	44 59                	rex.R pop %rcx
  4000f6:	2e 2e 2e 2e 2e 0a 00 	cs cs cs cs or %cs:(%rax),%al
```

```
root@debian-ryaoi:~/woody-woodpacker# objdump -d woody

woody:     file format elf64-x86-64

objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)
objdump: woody: attempt to load strings from a non-string section (number 5)

Disassembly of section .text:

00000000004000b0 <(null)>:
  4000b0:	c6                   	(bad)
  4000b1:	38 58 c1             	cmp    %bl,-0x3f(%rax)
  4000b4:	c3                   	retq
  4000b5:	bb 4b 10 2f 8b       	mov    $0x8b2f104b,%ebx
  4000ba:	1d c0 fc 73 30       	sbb    $0x3073fcc0,%eax
  4000bf:	a6                   	cmpsb  %es:(%rdi),%ds:(%rsi)
  4000c0:	93                   	xchg   %eax,%ebx
  4000c1:	f0 5b                	lock pop %rbx
  4000c3:	1c                   	.byte 0x1c

00000000004000c4 <(null)>:
  4000c4:	c8 ec 8b a7          	enterq $0x8bec,$0xa7
  4000c8:	2a 3a                	sub    (%rdx),%bh
  4000ca:	a4                   	movsb  %ds:(%rsi),%es:(%rdi)
  4000cb:	32 c7                	xor    %bh,%al
  4000cd:	1a 45 4b             	sbb    0x4b(%rbp),%al
  4000d0:	85 2e                	test   %ebp,(%rsi)
  4000d2:	9e                   	sahf
  4000d3:	d6                   	(bad)
  4000d4:	b5 88                	mov    $0x88,%ch
  4000d6:	4b 81 c9 cd ee fc 8a 	rex.WXB or $0xffffffff8afceecd,%r9
  4000dd:	e9 15 d3 c3 4e       	jmpq   4f03d3f7 <(null)+0x4ea3d2d7>
  4000e2:	7a 40                	jp     400124 <(null)+0x37>
  4000e4:	2c 58                	sub    $0x58,%al
  4000e6:	84 0a                	test   %cl,(%rdx)

00000000004000e8 <(null)>:
  4000e8:	41 2f                	rex.B (bad)
  4000ea:	bc                   	.byte 0xbc
  4000eb:	d4                   	(bad)
  4000ec:	f3                   	repz

00000000004000ed <(null)>:
  4000ed:	d9 55 fe             	fsts   -0x2(%rbp)
  4000f0:	50                   	push   %rax
  4000f1:	e2 8f                	loop   400082 <(null)-0x2e>
  4000f3:	ca d6 e4             	lret   $0xe4d6
  4000f6:	f6 c3 1b             	test   $0x1b,%bl
  4000f9:	ad                   	lods   %ds:(%rsi),%eax
  4000fa:	44                   	rex.R
  4000fb:	9b                   	fwait
  4000fc:	93                   	xchg   %eax,%ebx
```

The project is done.


Why not encrypt your woody?

```
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker /bin/ls
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody_woodpacker woody
key_value: 404142434445464748494A4B4C4D4E4F
root@debian-ryaoi:~/woody-woodpacker# ./woody
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
....WOODY.....
a.out		obj_c				      rc4.o	 test.asm
ft_memcpy.o	peda-session-a.out.txt		      small32	 test_files
ft_memmove.o	peda-session-small32.txt	      src_asm	 test.o
handle_elf64.o	peda-session-test.txt		      src_c	 test.sh
less		peda-session-woody.txt		      test	 woodpacker.h
main.o		peda-session-woody_woodpacker.txt     test1	 woody
Makefile	peda-session-x86_64-linux-gnu-nm.txt  test1.asm  woody_woodpacker
obj_asm		rc4.c				      test1.o
root@debian-ryaoi:~/woody-woodpacker#
```
