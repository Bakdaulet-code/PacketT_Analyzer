import os, sys
import socket
import binascii
import struct

socket_is_created = False
socket_sniffers = 0


def UDP_Header_Analyzer(data_received):
    udp_h = struct.unpack('!4H', data_received[:8])
    source_port = udp_h[0]
    destination_port = udp_h[1]
    v_length = udp_h[2]
    v_checksum = udp_h[3]
    data = data_received[8:]

    print('--------- UDP HEADER ---------')
    print('Source Port: %hu' % source_port)
    print('Destination Port: %hu' % destination_port)
    print('Length: %hu' % v_length)
    print('Checksum: %hu\n' % v_checksum)

    return data


def TCP_Header_Analyzer(data_received):
    tcp_h = struct.unpack('!2H2I4H', data_received[:20])
    source_port = tcp_h[0]
    destination_port = tcp_h[1]
    sequence_n = tcp_h[2]
    acknowledgement = tcp_h[3]
    offset = tcp_h[4] >> 12
    reserved = (tcp_h[5] >> 6) & 0x03ff
    any_flag = tcp_h[4] & 0x003f
    window = tcp_h[5]
    checksum = tcp_h[6]
    urgent_ptr = tcp_h[7]
    data = data_received[20:]

    urg = bool(any_flag & 0x0020)
    ack = bool(any_flag & 0x0010)
    psh = bool(any_flag & 0x0008)
    rst = bool(any_flag & 0x0004)
    syn = bool(any_flag & 0x0002)
    fin = bool(any_flag % 0x0001)

    print('--------- TCP HEADER ---------')
    print('Source Port: %hu' % source_port)
    print('Destination Port: %hu' % destination_port)
    print('Sequence Number: %u' % sequence_n)
    print('Acknowledgement: %u' % acknowledgement)
    print('Flags: ')
    print('    URG: %d | ACK: %d | PSH: %d | RST: %d | SYN: %d | FIN: %d' % (urg, ack, psh, rst, syn, fin))
    print('Window Size: %hu' % window)
    print('Checksum: %hu' % checksum)
    print('Urgent Pointer: %hu\n' % urgent_ptr)

    return data


def IP_Analyzer(data_received):
    ip_h = struct.unpack('!6H4s4s', data_received[:20])
    version = ip_h[0] >> 12
    sts_ihl = (ip_h[0] >> 8) & 0x0f
    sts_tos = ip_h[0] & 0x00ff
    total_length = ip_h[1]
    id = ip_h[2]
    any_flag = ip_h[3] >> 13
    offset = ip_h[3] & 0x1fff
    ttl = ip_h[4] >> 8
    prt = ip_h[4] & 0x00ff
    checksum = ip_h[5]
    source_addr = socket.inet_ntoa(ip_h[6])
    destination_addr = socket.inet_ntoa(ip_h[7])
    data = data_received[20:]

    print('---------- IP HEADER ----------')
    print('Version: %hu' % version)
    print('IHL: %hu' % sts_ihl)
    print('TOS: %hu' % sts_tos)
    print('Length: %hu' % total_length)
    print('ID: %hu' % id)
    print('Offset: %hu' % offset)
    print('TTL: %hu' % ttl)
    print('Protocol: %hu' % prt)
    print('Checksum: %hu' % checksum)
    print('Source IP: %s' % source_addr)
    print('Destination IP: %s\n' % destination_addr)

    if prt == 6:
        tcp_udp = "TCP"
    elif prt == 17:
        tcp_udp = "UDP"
    else:
        tcp_udp = "Other"

    return data, tcp_udp


def Ether_Header_Analyzer(data_received):
    ipEx = False
    ether_header = struct.unpack('!6s6sH', data_received[:14])
    destination_mac_addr = binascii.hexlify(ether_header[0]).decode()
    source_mac_addr = binascii.hexlify(ether_header[1]).decode()
    prt = ether_header[2] >> 8
    data = data_received[14:]

    print('--------- ETHERNET HEADER ----------')
    print('Destination MAC: %s:%s:%s:%s:%s:%s' % (
        destination_mac_addr[0:2], destination_mac_addr[2:4], destination_mac_addr[4:6], destination_mac_addr[6:8],
        destination_mac_addr[8:10], destination_mac_addr[10:12]))
    print('Source MAC: %s:%s:%s:%s:%s:%s' % (
        source_mac_addr[0:2], source_mac_addr[2:4], source_mac_addr[4:6], source_mac_addr[6:8], source_mac_addr[8:10],
        source_mac_addr[10:12]))
    print('Protocol: %hu\n' % prt)

    if prt == 0x08:
        ipEx = True

    return data, ipEx


def main():
    global socket_is_created
    global socket_sniffers

    if socket_is_created == False:
        socket_sniffers = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        socket_is_created = True

    data_received = socket_sniffers.recv(2048)
    os.system('clear')

    data_received, ipBool = Ether_Header_Analyzer(data_received)

    if ipBool:
        data_received, tcp_udp = IP_Analyzer(data_received)
    else:
        return

    if tcp_udp == "TCP":
        data_received = TCP_Header_Analyzer(data_received)
    elif tcp_udp == "UDP":
        data_received = UDP_Header_Analyzer(data_received)
    else:
        return


while True:
    main()
