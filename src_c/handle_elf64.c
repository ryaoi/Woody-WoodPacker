#include "../woodpacker.h"

# define DECODE_SIZE 334

unsigned char		decode_stub[DECODE_SIZE + KEY_MAXLEN] = {
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
  0xd9, 0xfe, 0xff, 0xff
};

unsigned int 		key_addr_offset = DECODE_SIZE;
unsigned int 		key_size_offset = 41;
unsigned int 		decode_start_offset = 48;
unsigned int 		decode_size_offset  = 53;
unsigned int 		jmp_oep_addr_offset = 304;

Elf64_Shdr 		*search_oep_section_header64(Elf64_Shdr *shdr, \
			uint64_t oep, uint64_t shnum)
{
	Elf64_Shdr 	*oep_shdr;
	uint64_t 	section_addr;
	uint64_t 	section_size;
	unsigned int	index;

	oep_shdr = NULL;
	index = 0;
	while (index < shnum)
	{
		section_addr = shdr->sh_addr;
		section_size = shdr->sh_size;
		if (section_addr <= oep && oep < section_addr + section_size)
		{
			oep_shdr = shdr;
			break ;
		}
		index++;
		shdr++;
	}
	return oep_shdr;
}

unsigned int		align(unsigned int value, int base)
{
	return (value + (base - 1)) & -base;
}


Elf64_Shdr		*add_new_section_header64(void *map, Elf64_Shdr *shdr, \
						uint64_t shnum, size_t filesize)
{
	unsigned int 	index;
	int		added;
	uint64_t	prev_comment_offset;
	Elf64_Shdr	*prev_shdr;
	Elf64_Shdr	*new_shdr;
	uint64_t	data_addr;
	uint64_t 	data_offset;

	index = 0;
	added = 0;
	prev_comment_offset = 0;
	while (index < shnum + 1)
	{
		/* if the section is added then we need to shift the sh_offset of other consecutive section after our section */
		if (added)
		{
	    	if (shdr->sh_type == SHT_NOTE)
	    	{
	    	    prev_comment_offset = shdr->sh_offset;
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
	    	}
	    	else if (prev_comment_offset != 0 && prev_shdr->sh_type == SHT_NOTE)
	    	{
				shdr->sh_offset = prev_shdr->sh_offset + (shdr->sh_offset - prev_comment_offset);
				prev_comment_offset = 0;
	    	}
			/* Handle comment section alignement */
			else if (shdr->sh_type == SHT_PROGBITS && shdr->sh_flags == SHF_STRINGS + SHF_MERGE)
			{
				prev_comment_offset = shdr->sh_offset;
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
			}
			//else if (prev_comment_offset != 0 && !(shdr->sh_type == SHT_PROGBITS && shdr->sh_flags == SHF_STRINGS + SHF_MERGE))
			else if (prev_comment_offset != 0 && prev_shdr->sh_flags == SHF_STRINGS + SHF_MERGE)
			{
				shdr->sh_offset = prev_shdr->sh_offset + (shdr->sh_offset - prev_comment_offset);
				prev_comment_offset = 0;
			}
			else if (shdr->sh_type == SHT_PROGBITS && prev_shdr->sh_addralign != 1)
				shdr->sh_offset = prev_shdr->sh_offset + align(prev_shdr->sh_size, shdr->sh_addralign);
			else
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
		}

		if (index != 0 && shdr->sh_addr == 0 && added == 0 && shdr->sh_name != 0)
		{
			/* shift the memory to create a new space for our section hedaer */
			ft_memmove((void *)shdr + sizeof(Elf64_Shdr), (void *)shdr, filesize - ((size_t)shdr - (size_t)map));
			/* Initialize our section header */
			shdr->sh_name = 0x0;
			shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
			if (prev_shdr->sh_type == SHT_NOBITS)
			{
				prev_shdr--;
				data_addr = prev_shdr->sh_addr;
				data_offset = prev_shdr->sh_offset;
				prev_shdr++;
				// bss offset = data offset + (bss_addr - data_addr)
				prev_shdr->sh_offset = data_offset + (prev_shdr->sh_addr - data_addr);
				shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
				shdr->sh_addr = prev_shdr->sh_addr + prev_shdr->sh_size;
			}
			else
			{
				shdr->sh_offset = prev_shdr->sh_offset + align(prev_shdr->sh_size, prev_shdr->sh_addralign);
				shdr->sh_addr = prev_shdr->sh_addr + align(prev_shdr->sh_size, prev_shdr->sh_addralign);
			}
			shdr->sh_type = SHT_PROGBITS;
			shdr->sh_size = sizeof(decode_stub);
			shdr->sh_link = 0x0;
			shdr->sh_addralign = 0x1;
			shdr->sh_entsize = 0x0;
			added = 1;
			new_shdr = shdr;
		}
		prev_shdr = shdr;
		index++;
		shdr++;
	}
	return (new_shdr);
}

void			modify_program_header64(Elf64_Phdr *phdr, uint64_t phnum)
{
	unsigned int	index;

	index = 0;
	while (index < phnum)
	{
		if (phdr->p_type == PT_LOAD)
		{
			phdr->p_flags = PF_X + PF_W + PF_R;
			/* our new section is not added on the first LOAD so skip the first part */
			if (phdr->p_offset != 0 || phnum == 1)
			{
				phdr->p_memsz += sizeof(decode_stub);
				phdr->p_filesz = phdr->p_memsz;
			}
		}
		index++;
		phdr++;
	}
}


void			create_decode_stub(uint64_t oep_old, uint64_t oep_new, uint64_t oep_old_size, uint64_t text_entrypoint)
{
	int 		rsi_oep_old = text_entrypoint - (oep_new + decode_start_offset) - 4;
 	int 		jmp_to_oep_old = oep_old - (oep_new + jmp_oep_addr_offset) - 4;
	int 		key_maxlen = KEY_MAXLEN;

	// first address of oep_old      oep_old - ( oep_new + decode_start_offset)
	ft_memcpy(&decode_stub[decode_start_offset], &rsi_oep_old, sizeof(int));
	// size
	ft_memcpy(&decode_stub[decode_size_offset],  &oep_old_size, sizeof(int));
	// key size
	ft_memcpy(&decode_stub[key_size_offset],  &key_maxlen, sizeof(int));

	// the address of oep_old oep_old - ( oep_new + jmp_offset) 
	ft_memcpy(&decode_stub[jmp_oep_addr_offset], &jmp_to_oep_old, sizeof(int));
	
	// copy the key to stub
	ft_memcpy(&decode_stub[key_addr_offset],  &key, sizeof(key));
	return;

}

static uint64_t		calculate_filesize(Elf64_Shdr *shdr, Elf64_Phdr *phdr, uint64_t shnum, uint64_t phnum, int bss_index)
{

	uint64_t	load_offset;
	uint64_t	total;
	uint64_t	index;
	Elf64_Shdr	*ptr_shdr;

	total = 0;
	load_offset = 0;
	if (phdr->p_type != PT_PHDR && phnum == 7)
	    return (0);
	for (index = 0; index < phnum;index++)
	{
		if (phdr->p_type == PT_LOAD && phdr->p_offset != 0)
			break;
		else if (phdr->p_type == PT_LOAD)
			load_offset = phdr->p_paddr;
		phdr++;
	}
	if (phnum > 1)
		load_offset += phdr->p_align;
	ptr_shdr = &shdr[bss_index];
	total = (ptr_shdr->sh_addr - load_offset) + align(ptr_shdr->sh_size, ptr_shdr->sh_addralign);
	for (index = bss_index + 1; index < shnum; index++)
	{
		if (shdr[index].sh_type == SHT_PROGBITS && shdr[index].sh_flags == SHF_STRINGS + SHF_MERGE)
		{
			if (index + 1 == shnum)
				return (0);
			total = total + (shdr[index + 1].sh_offset - shdr[index].sh_offset);
		}
		else
		{
			if (shdr[index].sh_addralign != 1)
				total = total + align(shdr[index].sh_size, shdr[index].sh_addralign);
			else
				total = total + shdr[index].sh_size;

		}
	}
	return (total);
	
}

int			get_shdr_before_new_index(void *map, size_t size)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)map;
 	Elf64_Shdr *shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
	Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
 	const char *sh_strtab_p = map + sh_strtab->sh_offset;

    /* Protect against shstrndx which will decide the address of sh_strtab_p */
    if (((uint64_t)(map + size)) < (uint64_t)sh_strtab)
        return (-1);
    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if ((uint64_t)map + size < (uint64_t)(sh_strtab_p + shdr[i].sh_name))
            return (-1);
		if (ft_strcmp(sh_strtab_p + shdr[i].sh_name,"__libc_freeres_ptrs") == 0)
			return (i);
  	}

    for (int i = 0; i < ehdr->e_shnum; i++)
	{
        if (ft_strcmp(sh_strtab_p + shdr[i].sh_name, ".bss") == 0)
            return (i);
  	}
 	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		if (ft_strcmp(sh_strtab_p + shdr[i].sh_name, ".data") == 0)
			return (i);
  	}

 	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		if (ft_strcmp(sh_strtab_p + shdr[i].sh_name, ".text") == 0)
			return (i);
  	}
	munmap_and_handle_error(map, size, "Sections are missing.\n");
	return (-1);

}

int			get_shdr_data_index(void *map)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)map;
 	Elf64_Shdr *shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
	Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
 	const char *sh_strtab_p = map + sh_strtab->sh_offset;

 	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		if (ft_strcmp(sh_strtab_p + shdr[i].sh_name,".data") == 0)
			return (i);
  	}
	return (0);

}

int			get_shdr_bss_index(void *map)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)map;
 	Elf64_Shdr *shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
	Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
 	const char *sh_strtab_p = map + sh_strtab->sh_offset;

 	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		if (ft_strcmp(sh_strtab_p + shdr[i].sh_name,".bss") == 0)
		{
		    if (ft_strcmp(sh_strtab_p + shdr[i+1].sh_name,"__libc_freeres_ptrs") == 0)
                return (i+1);
			return (i);
		}
  	}
	return (0);

}

uint64_t		find_size_alloc_zero(Elf64_Shdr *shdr, int bss_index, int data_index)
{
	uint64_t	ret;
	Elf64_Shdr	*bss_shdr;
	Elf64_Shdr	*data_shdr;

	ret = 0;
	bss_shdr = &shdr[bss_index];
	if (data_index != 0)
	{
		data_shdr = bss_shdr - 1;
		ret = bss_shdr->sh_size + (bss_shdr->sh_addr - data_shdr->sh_addr) - data_shdr->sh_size;
	}
	else
	{
		ret = bss_shdr->sh_size;
	}
	return (ret);
}

void			handle_elf64(void *mmap_ptr, size_t original_filesize)
{
	Elf64_Ehdr 	*ehdr;
	Elf64_Shdr 	*shdr;
	Elf64_Phdr 	*phdr;
	Elf64_Shdr 	*oep_shdr;
	Elf64_Shdr 	*new_shdr;
	Elf64_Shdr	*before_new_shdr;
	void 		*map;
	size_t 		size;
	int		before_new_index;
	int		bss_index;
	int		data_index;
	size_t		filesize_mapped_all;
	size_t		size_alloc_zero;
	size_t		offset;
	size_t		offset_old;
	int		packed;


	ehdr = (Elf64_Ehdr *)mmap_ptr;
	shdr = (Elf64_Shdr *)((mmap_ptr + ehdr->e_shoff));
	phdr = (Elf64_Phdr *)((mmap_ptr + ehdr->e_phoff));

    /* Check if the filesize doesn't extend beyond sections */
	if ((signed long)(original_filesize - ehdr->e_shoff) < (signed long)(ehdr->e_shnum * sizeof(Elf64_Shdr)) ||
				(signed long)(original_filesize - ehdr->e_phoff) < (signed long)(ehdr->e_phnum * sizeof(Elf64_Shdr)))
		munmap_and_handle_error(mmap_ptr, original_filesize, "Filesize does not match with number of section header.\n");


	before_new_index = get_shdr_before_new_index(mmap_ptr, original_filesize);
	if (before_new_index == -1)
		munmap_and_handle_error(mmap_ptr, original_filesize, "The executable is malformed.\n");
	    
	bss_index = get_shdr_bss_index(mmap_ptr);
	data_index = get_shdr_data_index(mmap_ptr);
	/* calculate new size which contain bss section inside te file and align the filesize by 8 */
	if ((filesize_mapped_all = align(calculate_filesize(shdr, phdr, ehdr->e_shnum, ehdr->e_phnum, before_new_index), 8)) == 0)
		munmap_and_handle_error(mmap_ptr, original_filesize, "The executable is malformed.\n");

	/* mapped_size + all sections hedaer + decode_stub + new Shdr */
	size = filesize_mapped_all + (ehdr->e_shnum * sizeof(Elf64_Shdr)) + sizeof(decode_stub) + sizeof(Elf64_Shdr) + 0x40;

    if (size < original_filesize)
		munmap_and_handle_error(mmap_ptr, original_filesize, "The executable is malformed.\n");
	if ((map = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		print_default_error();
	ft_memcpy(map, mmap_ptr, original_filesize);

	if ((munmap(mmap_ptr, original_filesize)) < 0)
	{
		if ((munmap(map, size)) < 0)
			print_default_error();
		print_default_error();
	}

	ehdr = (Elf64_Ehdr *)map;
	shdr = (Elf64_Shdr *)((map + ehdr->e_shoff));
	phdr = (Elf64_Phdr *)((map + ehdr->e_phoff));


	before_new_shdr = &shdr[before_new_index];
	offset_old = before_new_shdr->sh_offset;

	/* CHeck if the binary is already packed */
	packed = 0;
	if (before_new_index + 1 < ehdr->e_shnum && (shdr[before_new_index + 1].sh_name) == 0)
		packed = 1;

	/* add section 'anonymous' */
	new_shdr = add_new_section_header64(map, shdr, ehdr->e_shnum, original_filesize);

	/* add 1 to the header  */
	ehdr->e_shnum += 1;
	/* add 1 to the e_shstrndx because we added our new section before the strtab */
	ehdr->e_shstrndx += 1;

	/* keep size of 0 we need to put with bss section or below bss section (.data) */
	size_alloc_zero = find_size_alloc_zero(shdr, before_new_index, data_index);

	/* Get section which contain entry point then Encrypt the section */
	if ((oep_shdr = search_oep_section_header64(shdr, ehdr->e_entry, ehdr->e_shnum)) == NULL)
		munmap_and_handle_error(map, size, "No entry point section found.\n");

	/* Check the size of the section */
	if (original_filesize < (oep_shdr->sh_offset + oep_shdr->sh_size))
		munmap_and_handle_error(map, size, "Filesize too small for entry point section to fit.\n");

	/* encrypt the entry point section */
	rc4(key, sizeof(key), (char *)(oep_shdr->sh_offset + map), oep_shdr->sh_size);

	/* create decoder  */
	create_decode_stub(ehdr->e_entry, new_shdr->sh_addr, oep_shdr->sh_size, oep_shdr->sh_addr);
	/* modify program header */
	modify_program_header64(phdr, ehdr->e_phnum);
	/* modify entry point */
	ehdr->e_entry = new_shdr->sh_addr;

	before_new_shdr = &shdr[before_new_index];
	offset = before_new_shdr->sh_offset + before_new_shdr->sh_size;
	if ((before_new_index + 1 < ehdr->e_shnum && packed) || bss_index == 0)
	{
		offset = new_shdr->sh_offset;
		offset_old = offset;
	}

	ft_memmove((void *)(map + (offset + sizeof(decode_stub))), (void *)(map + offset_old), (size_t)(original_filesize - offset_old + sizeof(Elf64_Shdr)));

	if (packed == 0 && bss_index != 0)
	{
		ehdr->e_shoff = (ehdr->e_shoff + (offset - offset_old) + sizeof(decode_stub));
		new_shdr = ((void *)new_shdr + (offset - offset_old) + sizeof(decode_stub));
	}
	else
	{
		ehdr->e_shoff = (ehdr->e_shoff + sizeof(decode_stub));
		new_shdr = ((void *)new_shdr + sizeof(decode_stub));
	}

	/* copy the stub */
	ft_memcpy((void *)(map + new_shdr->sh_offset), decode_stub, sizeof(decode_stub));

	if (packed == 0 && bss_index != 0)
	{
		/* initialize bss */
		ft_memset((void *)(map + (offset - size_alloc_zero)), 0, size_alloc_zero);
		shdr = (Elf64_Shdr *)((map + ehdr->e_shoff));
		shdr[before_new_index].sh_type = SHT_PROGBITS;
	}
	map_to_file(map, size);
	if ((munmap(map, size)) < 0)
		print_default_error();
}
