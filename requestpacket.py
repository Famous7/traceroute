from hdrs import *
import socket


class RequestPacket:
    SUPPORTED_PROTOCOLS = [socket.IPPROTO_ICMP, socket.IPPROTO_UDP]

    def __init__(self, src='0.0.0.0', dst='127.0.0.1', protocol=socket.IPPROTO_ICMP, packet_size=60):
        if protocol not in RequestPacket.SUPPORTED_PROTOCOLS:
            raise ValueError

        self.ip_layer = IPHdr(src=src, dst=dst, proto=protocol)
        self.protocol = protocol

        min_size = IPHdr.IP_DEFAULT_SIZE

        if protocol == socket.IPPROTO_ICMP:
            min_size += ICMPHdr.ICMP_DEFAULT_SIZE
            self.sub_layer = ICMPHdr()

        # TODO : Add other protocols
        else:
            min_size += UDPHdr.UDP_DEFAULT_SIZE
            self.sub_layer = UDPHdr()

        data = self.__make_data(packet_size, min_size)
        self.packet_size = min_size + len(data) if min_size < packet_size else min_size
        self.sub_layer.data = data

        self.__packet = None

    @property
    def packet(self):
        self.ip_layer.data = self.sub_layer.assemble()
        self.__packet = self.ip_layer.assemble()
        return self.__packet

    def __make_data(self, data_size, default_size):
        if data_size <= default_size:
            data = ''
        else:
            data = 'A' * (data_size - default_size)

        return data.encode()