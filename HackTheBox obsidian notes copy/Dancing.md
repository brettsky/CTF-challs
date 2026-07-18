

`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.27.245`

```
Not shown: 65486 closed tcp ports (reset)
PORT      STATE    SERVICE       REASON          VERSION
135/tcp   open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds? syn-ack ttl 127
1586/tcp  filtered ibm-abtact    no-response
4384/tcp  filtered unknown       no-response
5985/tcp  open     http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0  
| smb2-time: 
|   date: 2025-12-19T18:37:39
|_  start_date: N/A
|_clock-skew: 3h59m38s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61929/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 23929/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 22131/udp): CLEAN (Timeout)
|   Check 4 (port 34633/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
                                                   
```

We learned how to use SMBClient to list out file shares and connect to specific shares 
`smbclient -L 10.129.27.245 `

We discovered a share that allowed us to connect with no password, it contained the flag
`smbclient //10.129.27.245/WorkShares `

We used `get` to get the files in each directory of `WorkShares`

