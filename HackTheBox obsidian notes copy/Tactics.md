
`sudo nmap -vvv -sC --reason -T4 -sCV -p0-65535 10.129.20.153`


```
PORT    STATE SERVICE       REASON          VERSION
135/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds? syn-ack ttl 127
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -2s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 23304/tcp): CLEAN (Timeout)
|   Check 2 (port 64719/tcp): CLEAN (Timeout)
|   Check 3 (port 59672/udp): CLEAN (Timeout)
|   Check 4 (port 48914/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-01-06T18:43:27
|_  start_date: N/A
```

SMB enumeration 

`smbclient -U administrator -L //10.129.20.156/` with this we were able to see the open SMB shares 

we were also able to use SMBExec to get an interactive shell `python smbexec.py administrator@10.129.20.156`