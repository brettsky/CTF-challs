
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.1.27`

```
Not shown: 65535 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://ignition.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST
```

`Gobuster dir -u http://ignition.htb  --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php`

```
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 25815]
/contact              (Status: 200) [Size: 28673]
/home                 (Status: 200) [Size: 25802]
/media                (Status: 301) [Size: 185] [--> http://ignition.htb/media/]
/0                    (Status: 200) [Size: 25803]
/catalog              (Status: 302) [Size: 0] [--> http://ignition.htb/]
/static               (Status: 301) [Size: 185] [--> http://ignition.htb/static/]
/admin                (Status: 200) [Size: 7092]
/Home                 (Status: 301) [Size: 0] [--> http://ignition.htb/home]
/cms                  (Status: 200) [Size: 25817]

```

admin is the login for the admin portal. We brute force around by searching for Magneto Password requirements and popular passwords for when this box was made. We find that `qwerty123` meets all the requirements and gives us a login