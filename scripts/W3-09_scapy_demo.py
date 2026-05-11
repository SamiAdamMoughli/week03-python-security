"""
scapy_demo.py
Scapy packet crafting — localhost only (127.0.0.1)!
Run with: sudo python3 scapy_demo.py
Platform: Kali Linux
"""

from scapy.all import IP, TCP, ICMP, Raw, sr1, send, sniff


# Section 1: Basic IP/TCP structure
ip = IP(dst="127.0.0.1", ttl=64)
pkt = ip / TCP(dport=443, flags="S")
pkt.show()

if IP in pkt:
    print(f"dst: {pkt[IP].dst}, ttl: {pkt[IP].ttl}")
if TCP in pkt:
    print(f"dport: {pkt[TCP].dport}, flags: {pkt[TCP].flags}")


# Section 2: ICMP — send to loopback, read reply
resp = sr1(IP(dst="127.0.0.1")/ICMP(), timeout=2, verbose=0)
if resp:
    resp.show()


# Section 3: TCP SYN — inspect each layer
pkt = IP(dst="127.0.0.1", ttl=64) / TCP(dport=443, flags="S")
pkt.show()
print(f"dst: {pkt[IP].dst}, ttl: {pkt[IP].ttl}")
print(f"dport: {pkt[TCP].dport}, flags: {pkt[TCP].flags}")


# Section 4: Sniff 10 packets on loopback
pkts = sniff(iface="lo", count=10)
for pkt in pkts:
    pkt.show()
pkts.summary()


# Section 5: TCP packets only
pkts = sniff(iface="lo", count=10, filter="tcp")
for pkt in pkts:
    pkt.show()
pkts.summary()


# Section 6: Raw bytes → parsed packet
raw_data = bytes(IP(dst="127.0.0.1")/TCP(dport=80))
parsed_pkt = IP(raw_data)
parsed_pkt.show()