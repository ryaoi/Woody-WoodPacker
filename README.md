# WoodyWoodpacker
Projet dans la suite logique de nm/otools qui a pour principe de modifier les headers d'un fichier de type ELF64. Le but ici est de pouvoir ajouter un morceau de code et obfusquer une partie d'un fichier non strippé.

## Comment faire

On va creer un program qui s'appelle packer qui va modifier le binaire en sorte que:

[Execution] -> [Execute .text]

[Execution] -> [decode the .text] -> [Execute .text]

le packer doit encrypter la partie .text et ajouter la partie decoder qui va decrypter au niveau de runtime.

1. On va creer notre propre section header qui va etre utile pour s'addresser a notre decoder de text.
le meilleur endroit pour ajouter notre propre section est juste avant les sections qui contient des sh_addr = 0x0 car on a pas besoin de modifier chaque offsets.

Donc:

[.bss] [.comment] [.shstrtab] [.symtab] [.strtab]

va etre

[.bss] __[decoder!]__ [.comment] [.shstrtab] [.symtab] [.strtab]

notre section decoder va contenir

```
  shdr->sh_name = 0x0;
  shdr->sh_type = SHT_PROGBITS;
  shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  shdr->sh_addr = prev_shdr->sh_addr + prev_shdr->sh_size;
  shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
  shdr->sh_size = sizeof(decode_stub);
  shdr->sh_link = 0x0;
  shdr->sh_addralign = 0x10;
  shdr->sh_entsize = 0x0;
```

comme information. Ce qu'il faut faire gaffe est les autres parties de section header.
On a ajouteé notre section decoder donc il faut faire un decalage.
les autres section header doit avoir un nouveau sh_offset qui est `shdr->sh_offset += sizeof(decode_stub);`

2. On va integrer notre decoder dans la zone qu'on vient de creer.
On va copier en dure dans le binaire les instruction a executer pour decoder .text

3. On va modifier le Program header en sorte que la partie decoder peut etre executer et que la partie .text peut etre ecrit. Donc `RWE` pour les deux type LOAD.

Example:

```
root@debian-ryaoi:~/woody-woodpacker# readelf -l ../woody
Elf file type is EXEC (Executable file)
Entry point 0x600918
There are 8 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x00000000000001c0 0x00000000000001c0  R E    0x8
  INTERP         0x0000000000000200 0x0000000000400200 0x0000000000400200
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000006e4 0x00000000000006e4  RWE    0x200000
  LOAD           0x00000000000006e8 0x00000000006006e8 0x00000000006006e8
                 0x00000000000002a9 0x00000000000002a9  RWE    0x200000
  DYNAMIC        0x0000000000000700 0x0000000000600700 0x0000000000600700
                 0x00000000000001d0 0x00000000000001d0  RW     0x8
  NOTE           0x000000000000021c 0x000000000040021c 0x000000000040021c
                 0x0000000000000020 0x0000000000000020  R      0x4
  GNU_EH_FRAME   0x00000000000005a4 0x00000000004005a4 0x00000000004005a4
                 0x0000000000000034 0x0000000000000034  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.ABI-tag .hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss
   04     .dynamic
   05     .note.ABI-tag
   06     .eh_frame_hdr
   07
```

Il ne faut pas oublier de modifier FileSiz, MemSiz aussi car on a ajoute notre decoder dans le binaire.

4. On va crypter la partie .text (n'importe quel ecnryption)

5. On va modifier le Entry Header en sorte que le entrypoint est pointé vers notre decoder.
 on a d'autre point a modifier. `shnum` qui indique le nombre de section, `shstrndx` qui indique quel section a utilise pour symtab et `shoff` qui indique le offset de section header. 
 
 On est obligé de incrementer de 1 sur `shstrndx` car le symtab se trouve apres notre decode section.
 `shoff` vaut l'ancien valeur + la taille de notre section decoder.
 `shnum` on increment de 1.
 `entry` va etre pointe sur notre section.
 
 Et c'est fini.
 
 Example de executable apres avoir passer sur notre packer:
 ```
 root@debian-ryaoi:~/woody-woodpacker# readelf -S woody
There are 32 section headers, starting at offset 0x1a2c:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000000238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000000254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.build-i NOTE             0000000000000274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000000298  00000298
       000000000000001c  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000000002b8  000002b8
       00000000000000c0  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           0000000000000378  00000378
       0000000000000096  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000000040e  0000040e
       0000000000000010  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000000420  00000420
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000000440  00000440
       00000000000000d8  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             0000000000000518  00000518
       0000000000000018  0000000000000018  AI       5    24     8
  [11] .init             PROGBITS         0000000000000530  00000530
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000000550  00000550
       0000000000000020  0000000000000010  AX       0     0     16
  [13] .plt.got          PROGBITS         0000000000000570  00000570
       0000000000000008  0000000000000000  AX       0     0     8
  [14] .text             PROGBITS         0000000000000580  00000580
       00000000000001c2  0000000000000000  AX       0     0     16
  [15] .fini             PROGBITS         0000000000000744  00000744
       0000000000000009  0000000000000000  AX       0     0     4
  [16] .rodata           PROGBITS         0000000000000750  00000750
       0000000000000011  0000000000000000   A       0     0     4
  [17] .eh_frame_hdr     PROGBITS         0000000000000764  00000764
       000000000000003c  0000000000000000   A       0     0     4
  [18] .eh_frame         PROGBITS         00000000000007a0  000007a0
       000000000000010c  0000000000000000   A       0     0     8
  [19] .init_array       INIT_ARRAY       0000000000200dd8  00000dd8
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000200de0  00000de0
       0000000000000008  0000000000000008  WA       0     0     8
  [21] .jcr              PROGBITS         0000000000200de8  00000de8
       0000000000000008  0000000000000000  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000200df0  00000df0
       00000000000001e0  0000000000000010  WA       6     0     8
  [23] .got              PROGBITS         0000000000200fd0  00000fd0
       0000000000000030  0000000000000008  WA       0     0     8
  [24] .got.plt          PROGBITS         0000000000201000  00001000
       0000000000000020  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000201020  00001020
       0000000000000010  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000201030  00001030
       0000000000000008  0000000000000000  WA       0     0     1
  [27]                   PROGBITS         0000000000201038  00001038
       000000000000002c  0000000000000000  AX       0     0     16
  [28] .comment          PROGBITS         0000000000000000  0000105c
       000000000000002d  0000000000000001  MS       0     0     1
readelf: Warning: [29]: Link field (29) should index a string section.
  [29] .symtab           SYMTAB           0000000000000000  0000108c
       0000000000000660  0000000000000018          29    47     8
  [30] .strtab           STRTAB           0000000000000000  000016ec
       000000000000022f  0000000000000000           0     0     1
  [31] .shstrtab         STRTAB           0000000000000000  0000191b
       000000000000010c  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```

On remarque dans l'index 27, il y a une section qui a pas de nom et qui a un droit d'execution.
Son offset est de `0000000000201038`.
On va verifier si cela correspond a notre entrypoint.
```
root@debian-ryaoi:~/woody-woodpacker# readelf -h woody
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x201038
  Start of program headers:          64 (bytes into file)
  Start of section headers:          6700 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         32
  Section header string table index: 31
 ```
 

 La sortie:
 
 ```
 root@debian-ryaoi:~# cat test.c
#include <stdio.h>

int main(void)
{
	printf("Hello world...? Maybe not.\n");
	return (0);
}
root@debian-ryaoi:~# gcc test.c -o example
root@debian-ryaoi:~/woody-woodpacker# ./a.out ../example
[*] 3:ELF
ELF Executable!
64 bits!
[*] Start Xor Encode by '0xBB'
[+] Encode Done
oep_old        : 0X580
size           : 0X1C2
decoder        : 0XBB
oep_new        : 0X201038
rsi_oep_old    : 0XFFDFF528
jmp_to_oep_old : 0XFFDFF50C
[+] Modified stub!
[+] Modified program header!
[*] Previous Rntry point :580
[+] Current Entry point  :201038!
[+] Copied the decode_stub inside the binary!
[+] Finished writing to woody!
root@debian-ryaoi:~/woody-woodpacker# ./woody
....WOODY.....
Hello world...? Maybe not.
root@debian-ryaoi:~/woody-woodpacker#
 ```
 
 
 







