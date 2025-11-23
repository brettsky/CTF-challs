Want to hear some lo-fi beats, to relax or study to? We've got you covered! 



Access this challenge by deploying both the vulnerable machine by pressing the green "Start Machine" button located within this task, and the TryHackMe AttackBox by pressing the  "Start AttackBox" button located at the top-right of the page.

Navigate to the following URL using the AttackBox: http://MACHINE_IP and find the flag in the root of the filesystem.



Check out similar content on TryHackMe:

LFI Path Traversal
File Inclusion
Note: The web page does load some elements from external sources. However, they do not interfere with the completion of the room.

We try the standard LFI payload but it gets blocked 
/../../../etc/passwd

We navigate to ../../../../../flag.txt to print the flag 

```
?page=../../../../../flag.txt 
```