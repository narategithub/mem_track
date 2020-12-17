#include <stdio.h>
#include <stdlib.h>

int fn(const char *s)
{
	void *p = malloc(10);
	printf("FN! %s\n", s);
	printf("FN! p: %p\n", p);
	//free(p);
}
