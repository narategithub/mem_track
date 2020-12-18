#include <stdio.h>
#include <malloc.h>

int fn(const char *s);

int main(int argc, char **argv)
{
	void *p, *q, *r;
	p = malloc(16);
	printf("p: %p\n", p);
	printf("main: %p\n", main);
	printf("fn: %p\n", fn);
	q = realloc(p, 20);
	r = calloc(1, 32);
	fn("abcdefg\n");
	return 0;
}
