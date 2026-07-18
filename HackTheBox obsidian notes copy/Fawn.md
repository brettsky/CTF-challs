
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.27.235`

```
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.17.217
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
Service Info: OS: Unix
```


Mhmm Ftp with anonymous login  and flag.txt.....

`ftp 10.129.27.235`
`Anonymous`
`get flag.txt`

`cat flag.txt: 035db21c881520061c53e0536e44f815 `