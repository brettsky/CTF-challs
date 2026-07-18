
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.9.20`

```
Host is up, received user-set (0.036s latency).
Scanned at 2025-12-19 11:11:39 EST for 16s
Not shown: 65535 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
```
This room taught us about using GoBuster and Flags to ensure we captured default PHP webpages 


`sudo gobuster dir -u http://10.129.9.20:80/ -w /home/kali/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php
`
This command output a 200 status code to admin.php 

navigating to 10.129.9.20/admin.php gave us a login console. Admin:Admin worked and gave us the flag