from collections import Counter
from scapy.all import sniff

packet_cntr = Counter()

def custom_act(packet):
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_cntr.update([key])
    return f"Packet #{sum(packet_cntr.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"
    
#sniff(filter="dst port 1234", prn=custom_act, count=1)

#print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_cntr.items()))

a = sniff(filter="dst port 1236", count=1)
a.summary()
