
We start with a ping to help to determine the OS of the box 
```
PING 10.129.32.75 (10.129.32.75) 56(84) bytes of data.
64 bytes from 10.129.32.75: icmp_seq=1 ttl=63 time=1538 ms
```
TTL = 63 signifies this is most likely a linux OS. If the ttl is below 65 it is most likely linux

>65 - Linux
>65 - 128 = Windows
>128+ = Network Appliance