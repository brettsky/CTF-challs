tcp [[nmap]] scan shows nothing, but a UDP scan shows an Ike service listening on UDP port 500

nmap -sU -p500 -sV  10.129.38.4


![[Pasted image 20251025143228.png]]


https://book.hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html Proved to be very helpful in providing information on how to tackle this challenge 

We can use [[Ike-scan]] to gather further information about the gateway

sudo ike-scan -P -M -A -n fakeid 10.129.38.4

![[Pasted image 20251025144557.png]]

This tells us that the Ike Gateway is configured in aggressive mode and will return a fake hash for a user that does not exist. So we cannot use IKE scan to enumerate a valid user. But once we do find a user we will find the hash associated with their password. 