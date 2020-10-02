from requestpacket import RequestPacket
from hdrs import IPHdr, ICMPHdr, UDPHdr
import socket
import time
import random
import argparse
import sys


DEFAULT_UDP_DST_PORT = 53
TRIES = 3


def do_traceroute(hop_count, dst_addr, timeout, packet, rand_port_flag=False):
    found = False
    count = 1
    packet_id = random.randint(1, 65535)
    packet.ip_layer.fid = packet_id

    if packet.protocol == socket.IPPROTO_ICMP:
        packet.sub_layer.id = packet_id
    elif packet.protocol == socket.IPPROTO_UDP and rand_port_flag:
        packet.sub_layer.dst_port = random.randint(49152, 65535)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as send_socket:
            for hop in range(1, hop_count+1):
                packet.ip_layer.ttl = hop
                print('{0}{1}'.format(hop, ' '*(5-len(str(hop)))), end='')

                messages = ['*' for _ in range(TRIES)]
                got_response = False

                for tries in range(TRIES):
                    if packet.protocol == socket.IPPROTO_ICMP:
                        packet.sub_layer.seq = count

                    elif packet.protocol == socket.IPPROTO_UDP:
                        packet.sub_layer.src_port = random.randint(49152, 65535)

                        if rand_port_flag:
                            packet.sub_layer.dst_port += 1

                    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as recv_socket:
                        recv_socket.settimeout(timeout)
                        try:
                            send_socket.sendto(p.packet, (dst_addr, 0))
                            send_time = time.clock()

                            recv_packet, addr = recv_socket.recvfrom(65535)
                            recv_time = time.clock()

                        except socket.timeout:
                            pass

                        else:
                            ip_hdr = IPHdr.disassemble(recv_packet)

                            if ip_hdr.proto != socket.IPPROTO_ICMP:
                                continue

                            icmp_hdr = ICMPHdr.disassemble(ip_hdr.data)

                            if icmp_hdr.type == 0 and icmp_hdr.code == 0:  # Echo reply
                                if icmp_hdr.id == packet_id and ip_hdr.src == packet.ip_layer.dst:
                                    found = True
                                else:
                                    continue
                            elif icmp_hdr.type == 11 and icmp_hdr.code == 0:  # Time exceeded in transit
                                ref_ip = IPHdr.disassemble(ip_hdr.data[8:])
                                if ref_ip.fid != packet.ip_layer.fid or ref_ip.dst != packet.ip_layer.dst:
                                    continue

                            elif icmp_hdr.type == 3 and icmp_hdr.code == 3:  # Destination unreachable(port)
                                ref_ip = IPHdr.disassemble(ip_hdr.data[8:])
                                if ref_ip.fid != packet.ip_layer.fid or ref_ip.dst != packet.ip_layer.dst:
                                    continue

                                ref_udp = UDPHdr.disassemble(ref_ip.data)

                                if ref_udp.src_port == packet.sub_layer.src_port and ref_udp.dst_port == packet.sub_layer.dst_port:
                                    found = True
                                else:
                                    continue
                            else:
                                continue

                            got_response = True
                            messages[tries] = '{0} ms'.format(round((recv_time - send_time) * 10000, 2))

                    count += 1

                if got_response:
                    try:
                        node = '[{0}, {1}]'.format(socket.gethostbyaddr(addr[0])[0], addr[0])
                    except:
                        node = '[{0}, {1}]'.format(addr[0], addr[0])
                else:
                    node = ''

                print('   '.join(messages) + ' ' + node)

                if found:
                    return

    except KeyboardInterrupt:
        print('\nQuit')
        sys.exit(0)

    except PermissionError:
        print('No permission for create raw socket, try superuser...')
        sys.exit(-1)

    except socket.error as e:
        print(e)
        sys.exit(-1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='simple traceroute by famous')
    parser.add_argument('host', type=str, metavar='DST_ADDR', help='destination address')
    parser.add_argument('size', type=int, nargs='?', default=60, metavar='PACKET_SIZE',
                        help='IP packet size, include header size')

    parser.add_argument('-I', type=int, nargs='?', metavar='ICMP_ECHO', help='using ICMP_ECHO_REQUEST', const=socket.IPPROTO_ICMP)
    parser.add_argument('-U', type=int, nargs='?', metavar='UDP', help='using UDP', const=socket.IPPROTO_UDP)
    parser.add_argument('-t', type=float, metavar='RECV_TIME_OUT', help='request timeout', default=1.5)
    parser.add_argument('-c', type=int, metavar='MAX_HOP', help='max hop count', default=30)
    parser.add_argument('-p', type=int, metavar='PORT_NUM', help='destination port number')
    args = parser.parse_args()

    host = args.host
    timeout = args.t
    packet_size = args.size
    max_hop = args.c
    port = args.p

    try:
        dst_addr = socket.gethostbyname(host)
        print('traceroute to {0} ({1}), {2} hops max, {3} byte packets'.format(host, dst_addr, max_hop, packet_size))
    except socket.gaierror:
        print('Can not resolve server address from {0}'.format(host))
        sys.exit(-1)

    random_port = False

    if args.U:
        p = RequestPacket(dst=dst_addr, packet_size=packet_size, protocol=socket.IPPROTO_UDP)
        p.sub_layer.dst_port = port
        if not port:
            random_port = True

    else:
        p = RequestPacket(dst=dst_addr, packet_size=packet_size, protocol=socket.IPPROTO_ICMP)

    do_traceroute(max_hop, dst_addr, timeout, p, random_port)






