OBJS = libmalloctrace.so libfn.so test

all: $(OBJS)

CFLAGS = -ggdb3 -O0

clean:
	rm -f $(OBJS)

test: test.c
	gcc $(CFLAGS) -o $@ -lfn -L. $<

libmalloctrace.so: malloctrace.c
	gcc $(CFLAGS) -o $@ -shared -fPIC -ldl $<
libfn.so: fn.c
	gcc $(CFLAGS) -o $@ -shared -fPIC -ldl $<
