#include "../woodpacker.h"

unsigned char key[KEY_MAXLEN] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};

void	handle_error(char *msg)
{
	dprintf(2, "%s", msg);
	exit(EXIT_FAILURE);
}

void	print_default_error(void)
{
	perror("[-] Error");
	exit(EXIT_FAILURE);
}

void	munmap_and_handle_error(void *map, size_t size, char *msg)
{
	if ((munmap(map, size)) < 0)
		print_default_error();
	handle_error(msg);
}

static void	check_header(void *mmap_ptr, size_t filesize)
{
	Elf64_Ehdr *header;

	header = (Elf64_Ehdr *)mmap_ptr;
	if((header->e_type == ET_EXEC || header->e_type == ET_DYN) &&
			header->e_ident[1] == 'E' &&
			header->e_ident[2] == 'L' &&
			header->e_ident[3] == 'F') {
		if (header->e_ident[EI_CLASS] == 1)
			printf("32 bits!\n");
		else if (header->e_ident[EI_CLASS] == 2)
			handle_elf64(mmap_ptr, filesize);
		else
		{
			if ((munmap(mmap_ptr, filesize)) < 0)
				print_default_error();
			handle_error("Undefined EI_CLASS value.\n");
		}
	}
	else
	{
		if ((munmap(mmap_ptr, filesize)) < 0)
			print_default_error();
		handle_error("File architecture not suported. x86_64 only\n");
	}
}


int		main(int argc, char **argv)
{
	int	fd;
	void	*mmap_ptr;
	off_t 	filesize;

	if (argc != 2)
		handle_error("Usage : ./woody_woodpacker <file>\n");
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		print_default_error();
	if ((filesize = lseek(fd, (size_t)0, SEEK_END)) < 0)
		print_default_error();
	if ((size_t)filesize < sizeof(Elf64_Ehdr))
		handle_error("The size of the file is too small.\n");
	if ((mmap_ptr = mmap(0, filesize, PROT_READ, MAP_PRIVATE, fd, 0))\
			== MAP_FAILED)
		print_default_error();
	if ((close(fd)) < 0)
		print_default_error();
	check_header(mmap_ptr, filesize);
	printf("key_value: ");
	for (int i = 0; i < KEY_MAXLEN; i++)
		printf("%02X", key[i]);
	printf("\n");
	return (EXIT_SUCCESS);
}
