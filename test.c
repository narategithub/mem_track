#include <stdio.h>
#include <malloc.h>

int fn(const char *s);

int main(int argc, char **argv)
{
	void *p;
	p = malloc(16);
	printf("p: %p\n", p);
	printf("main: %p\n", main);
	printf("fn: %p\n", fn);
	//free(p);
	fn("abcdefg\n");
	return 0;
}
