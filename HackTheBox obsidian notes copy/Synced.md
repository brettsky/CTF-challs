`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.228.37`


```
PORT    STATE SERVICE REASON         VERSION
873/tcp open  rsync   syn-ack ttl 63 (protocol version 31)
```

We interact with the public share via this rsync command 

`rsync -av rsync://None@10.129.228.37:/public  /home/kali/Synced`

```
Receiving incremental file list
./
flag.txt

sent 50 bytes  received 161 bytes  22.21 bytes/sec
total size is 33  speedup is 0.16

┌──(kali㉿kali)-[~/Synced]
└─$ cat flag.txt        
72eaf5344ebb84908ae543a719830519

```