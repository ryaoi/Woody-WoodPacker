#ifndef WOODPACKER_H
#define WOOD_PACHER_H

#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define KEY_MAXLEN 16
#define FILENAME "woody"

void	handle_elf64(void *mmap_ptr, size_t original_filesize);
void	handle_error(char *str);
void	print_default_error(void);
void	munmap_and_handle_error(void *map, size_t size, char *msg);
void 	rc4(unsigned char *key,int key_len,char *buff,int len);
void	*ft_memmove(void *dst, const void *src, size_t len);
void	*ft_memcpy(void *dst, const void *src, size_t n);
void	*ft_memset(void *b, int c, size_t n);
int	ft_strcmp(const char *s1, const char *s2);
void	map_to_file(void *map, size_t size);

extern unsigned char		key[KEY_MAXLEN];

#endif
