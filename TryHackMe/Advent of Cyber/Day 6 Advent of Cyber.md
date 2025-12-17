### Malware Analysis - Egg-xecutable

Today's room will have you taking the place of Elf McBlue, a highly talented member of The Best Festival Company's malware investigation squad. You have been tasked with investigating a highly suspicious executable that is being shared within the company. In today's room, we will be covering the following:

- The principles of malware analysis
- An introduction to sandboxes
- Static vs. dynamic analysis
- Tools of the trade: PeStudio, ProcMon, Regshot

Malware analysis is the process of examining a malicious file to understand its functionality, operation, and methods for defence against it. By analysing a malicious file or application, we can see exactly how it operates, and therefore, know how to prevent it. For example, could the malicious file communicate with an attacker's server? We can block that server.

There are two main branches of malware analysis: **static** and **dynamic**. Static analysis focuses on inspecting a file without executing it, whereas dynamic analysis involves execution.

 sandboxes are used to execute potentially dangerous code.

Static analysis can be a quick and effective way to understand how the sample _may_ operate, as well as how it can be identified. Some of the information that can be gathered from static analysis has been included in the table below:

|   |   |   |
|---|---|---|
|**Information**|**Explanation**|**Example**|
|Checksums|These checksums are used within cyber security to track and catalogue files and executables. For example, you can Google the checksum to see if this has been identified before.|`a93f7e8c4d21b19f2e12f09a5c33e48a`|
|Strings|"Strings" are sequences of readable characters within an executable. This could be, for example, IP addresses, URLs, commands, or even passwords!|`138.62.51.186`|
|Imports|"Imports" are a list of libraries and functions that the application depends upon. For example, rather than building everything from scratch, applications will use operating system functions and libraries to interact with the OS.<br><br>These are useful, especially in Windows, as they allow you to see how the application interacts with the system.|`CreateFileW`<br><br>This library is used to create a file on a Windows system.|
|Resources|"Resources" contain data such as the icon that is displayed to the user. This is useful to examine, especially since malware might use a Word document icon to trick the user.  <br>  <br>Additionally, malware itself has been known to hide in this section!|N/A|


# Dynamic Analysis 

**Regshot**

Regshot is a widely used utility, especially when analysing malware on Windows. It works by creating two "snapshots" of the registry—one before the malware is run and another afterwards. The results are then compared to identify any changes.

Malware aims to establish persistence, meaning it seeks to run as soon as the device is switched on. A common technique for malware is to add a `Run` key into the registry, which is frequently used to specify which applications are automatically executed when the device is powered on.


**ProcMon**

Next, we will explore using ProcMon (Process Monitor) from the Sysinternals suite to investigate today's sample. Proccess Monitor is used to monitor and investigate how processes are interacting with the Windows operating system. It is a powerful tool that allows us to see exactly what a process is doing. For example, reading and writing registry keys, searching for files, or creating network connections.

Open **Process Monitor (ProcMon)**, the shortcut for this has been placed on the Desktop of the analyst machine. Process Monitor will automatically start capturing events of various processes on the system.