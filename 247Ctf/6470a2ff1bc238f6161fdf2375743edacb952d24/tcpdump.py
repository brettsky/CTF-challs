import dpkt

input=open("error_reporting.pcap", "rb")

# We are going to extract all ICMP payloads and concatenate them in one file,
# and see what happens:
output=open("output.jpg", "w")

pcap=dpkt.pcap.Reader(input)

for ts, buf in pcap:
    eth=dpkt.ethernet.Ethernet(buf)
    if (eth.type != 2048): # 2048 is the code for IPv4
        continue


    ip=eth.data
    icmp=ip.data    # type: dpkt.icmp.ICMP

# The parsed packets in the dpkt.pcap.Reader contains two members: "ts" and "buf".
# The member "ts" is just the timestamp which lived in the packet when captured
# by Wireshark; it is the clock when captured this packet. The member "buf" holds
# the real packet data captured by capture tool, it's the raw traffic data.
    if (ip.p==dpkt.ip.IP_PROTO_ICMP) and len(icmp.data.data)>0: # type: dpkt.icmp.ICMP
        try:
            print (icmp.data.data)
            output.write(icmp.data.data)
        except:
            print ('Error extracting ICMP payload data from this packet.')
        continue

input.close()
output.close()