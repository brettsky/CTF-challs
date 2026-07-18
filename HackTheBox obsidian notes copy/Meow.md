```
nmap -sV -p- 10.129.27.228
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-19 08:34 EST
Nmap scan report for 10.129.27.228
Host is up (0.017s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.44 seconds 
```

We see telnet is open, We try to connect as root 
`telnet 10.129.27.228 23`

`Meow login: root
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)`


We now have access as root and to the root flag. 

