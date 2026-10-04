CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

.PHONY: all clean hardened

all: hello

hello: hello.c
	$(CC) $(CFLAGS) hello.c -o hello

hardened: hello.c
	$(CC) $(CFLAGS) -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now hello.c -o hello-hardened

clean:
	rm -f hello hello-hardened
