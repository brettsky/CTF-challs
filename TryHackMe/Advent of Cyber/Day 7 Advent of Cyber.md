## Discovering Exposed Services


**The Simplest Port Scan**

nmap 10.67.180.86

**Scanning Whole Range**

nmap -p- --script=banner 10.67.180.86
-p- argument to scan all ports, and --script=banner to see what's likely behind the port:
```
root@attackbox:~# nmap -p- --script=banner 10.67.180.86 Nmap scan report for 10.67.180.86 
Host is up (0.00036s latency). Not shown: 65531 filtered ports
 PORT STATE SERVICE 
 22/tcp open ssh |_banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14 
 80/tcp open http 
 21212/tcp open trinket-agent |_banner: 220 (vsFTPd 3.0.5) 
 25251/tcp open unknown |_banner: TBFC maintd v0.2\x0AType HELP for commands.
```

ftp 10.67.180.86 21212 -- ftp connection over non standard port 
get - transfer ftp files from ftp server to machine

**Port Scan Modes**

you can always use Netcat (`nc`), a universal tool to interact with network services:

nc -v 10.67.180.86 25251

**TCP and UDP Ports**
nmap -sU 10.67.180.86


**Listing Listening Ports**

Once you have access to the console, there is no need to scan the ports, as you can simply ask the OS to list its open ports, also called listening ports. You can do it by running ss -tunlp (or netstat on older systems) 
3306 - default mysql port

Since you are already inside the host, let's see the database content by using the `mysql` program:

```
mysql -D tbfcqa01 -e "show tables;"                                                                                          
+--------------------+                                                                                                                               
| Tables_in_tbfcqa01 |                                                                                                                               
+--------------------+                                                                                                                               
| flags              |                                                                                                                               
+--------------------+                                                                                                                               
```

```
mysql -D tbfcqa01 -e "select * from flags;"                                                                                  
+----+------------------------------+                                                                                                                
| id | flag                         |                                                                                                                
+----+------------------------------+                                                                                                                
|  1 | THM{4ll_s3rvice5_d1sc0vered} |                                                                                                                
+----+------------------------------+                                                                                                                
```