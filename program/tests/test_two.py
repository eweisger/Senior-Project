import collections

def test_two(packet):
    if packet.ipv4.protocol is 0:
        print('icmp')
        print(packet.icmp.data)

    if packet.ipv4.protocol is 1:
        print('tcp')
        print(packet.tcp.data)

    if packet.ipv4.protocol is 2:
        print('udp')
        print(packet.udp.data)

    if packet.ipv4.protocol is 3:
        print('other')
        print(packet.other)

