
#include "../woodpacker.h"

void	*ft_memset(void *b, int c, size_t n)
{
	unsigned char *new;

	new = b;
	while (n > 0 && new != NULL)
	{
		*new = (unsigned char)c;
		new++;
		n--;
	}
	return (b);
}
