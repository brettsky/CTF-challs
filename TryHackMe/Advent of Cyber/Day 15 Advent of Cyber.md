## Web attack forensics

How to find a web attack went down. 


## Detect sus commands

```kql

index=windows_apache_access (cmd.exe OR powershell OR "powershell.exe" OR "Invoke-Expression") | table _time host clientip uri_path uri_query statu
```


This search will go through the window_apache_access logs and search for cmd or powershell executables. Invoke expression will invoke an http request

Then it will out put this data to a table

We see the Base64 encoded string

 uri_query = cmd=powershell.exe+-enc+VABoAGkAcwAgAGkAcwAgAG4AbwB3ACAATQBpAG4AZQAhACAATQBVAEEASABBAEEASABBAEEA 


and we see the text T�h�i�s� �i�s� �n�o�w� �M�i�n�e�!� �M�U�A�H�A�A�H�A�A� "this is now mine"

## Looking for Server-Side Errors or Command Execution in Apache Error Logs
`index=windows_apache_access (cmd.exe OR powershell OR "powershell.exe" OR "Internal Server Error")`


If a request like `/cgi-bin/hello.bat?cmd=powershell` triggers a 500 “Internal Server Error,” it often means the attacker’s input was processed by the server but failed during execution, a key sign of exploitation attempts.


## Trace Suspicious Process Creation From Apache

Typically, Apache should only spawn worker threads, not system processes like `cmd.exe` or `powershell.exe`.

If results show child processes such as:

`ParentImage = C:\Apache24\bin\httpd.exe`

`Image        = C:\Windows\System32\cmd.exe`

It indicates a successful **command injection** where Apache executed a system command.

![[Pasted image 20251216094502.png]]


## Confirm enumeration 

![[Pasted image 20251216094641.png]]

Apache running whoami :sob: 


## Identify Base64-Encoded PowerShell Payloads

In this final step, we will work to find all successfully encoded commands. To search for encoded strings, we can use the following Splunk query:

`index=windows_sysmon Image="*powershell.exe" (CommandLine="*enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*Base64*")`

This query detects PowerShell commands containing -EncodedCommand or Base64 text, a common technique attackers use to **hide their real commands**.

If your defenses are correctly configured, this query should return **no results**, meaning the encoded payload (such as the “Muahahaha” message) never ran.

If results appear, you can decode the Base64 command to inspect the attacker’s true intent.