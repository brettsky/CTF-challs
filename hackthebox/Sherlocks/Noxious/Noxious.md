# Noxious

The IDS device alerted us to a possible rogue device in the internal Active Directory network. The Intrusion Detection System also indicated signs of LLMNR traffic, which is unusual. It is suspected that an LLMNR poisoning attack occurred. The LLMNR traffic was directed towards Forela-WKstn002, which has the IP address 172.17.79.136. A limited packet capture from the surrounding time is provided to you, our Network Forensics expert. Since this occurred in the Active Directory VLAN, it is suggested that we perform network threat hunting with the Active Directory attack vector in mind, specifically focusing on LLMNR poisoning.



### Concept

* SOC Incident Investigation

### Method of solve


#### Question one : Its suspected by the security team that there was a rogue device in Forela's internal network running responder tool to perform an LLMNR Poisoning attack. Please find the malicious IP Address of the machine

We start this challenge with a PCAP file. I open the packet and based on the suspicions my first thought is to look for LLMNR traffic

* A google search tells me LLMNR operates on UDP port 5355. So I add the filter "udp.port eq 5355"  - Quick research about LLMNR poisoning attacks shows me that this attack 
is when a device on the network listens for LLMNR traffic and responds to the traffic with its own information. It can be used to get password hashes and other information 


* I see that the only IPV4 responses to all queries are 172.17.79.135 This is suspicious and is the correct potentially malicious ip


#### Question two: What is the hostname of the rogue machine?


DHCP Traffic can include host name information in the packet details so I apply a filter for DHCH Pakcets. There is a DHCP request packet from 172.17.79.135 with the host name kali in the packet details

### Question three: Now we need to confirm whether the attacker captured the user's hash and it is crackable!! What is the username whose hash was captured?

This led me to pivot to any NTLM authentications on the network. Adding a filter for ntlmssp shows auth attempts from that work station to the john.deacon user


User::Domain:ServerChallenge:NTProofStr:NTLMv2Response
john.deacon:FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:010100000000000080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100530035004c00310047005200570054002e004e004200460059002e004c004f00430041004c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e004c004f00430041004c000700080080e4d59406c6da0106000400020000000800300030000000000000000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c90a001000000000000000000000000000000000000900140063006900660073002f00440043004300300031000000000000000000