#include "../woodpacker.h"

void		map_to_file(void *map, size_t size)
{
	int	fd;

	if ((fd = open(FILENAME, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0755)) < 0)
	{
		if ((munmap(map, size)) < 0)
			print_default_error();	
		print_default_error();	
	}
	if ((write(fd, map, size)) < 0)
	{
		if ((close(fd)) < 0)
		{
			if ((munmap(map, size)) < 0)
				print_default_error();	
			print_default_error();
		}
		print_default_error();
	}
	if ((close(fd)) < 0)
	{
		print_default_error();
	}
}
