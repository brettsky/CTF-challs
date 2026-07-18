sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 -on
```
Not shown: 65459 closed tcp ports (reset)                                                                                                                   
PORT      STATE    SERVICE        REASON         VERSION                      
22/tcp    open     ssh            syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)                                             
| ssh-hostkey:                                                                
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)                                                                                             
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9
/PM44=                                                                                                                                                      
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)             
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD                                                                          
80/tcp    open     http           syn-ack ttl 63 nginx 1.24.0 (Ubuntu)    
|_http-server-header: nginx/1.24.0 (Ubuntu)                                                                                                                 
|_http-title: Did not follow redirect to http://mail.outbound.htb/                                                                                          
| http-methods:                                                                                                                                             
|_  Supported Methods: GET HEAD POST OPTIONS        
```
We see port 22 and 80 open 

This is also an assumed breach box with creds for the following account tyler / LhKL1o9Nm3X2

adding mail.outbound.htb and using the given creds gets us into round cube ![[Pasted image 20251117211513.png]]
CVE Details shows a 9.9 CVE that is valid for Roundcube version 1.6.X  We are on roundcube 1.6.10 - Bingo

![[Pasted image 20251117211631.png]]