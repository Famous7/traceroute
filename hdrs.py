from protocolhdr import ProtocolHdl
import socket
import struct


class IPHdr(ProtocolHdl):
    IP_DEFAULT_SIZE = 20

    def __init__(self, proto=socket.IPPROTO_ICMP, src='0.0.0.0', dst='127.0.0.1', data=''):
        self.src = socket.inet_aton(src)
        self.dst = socket.inet_aton(dst)
        self.proto = proto
        self.ip_ver = 4
        self.ip_hl = 5
        self.tos = 0
        self.tol = 0
        self.fid = 0
        self.f_rsv = 0
        self.f_dtf = 0
        self.f_mrf = 0
        self.f_offset = 0
        self.ttl = 255
        self.checksum = 0
        self.data = data if isinstance(data, bytes) else data.encode()

    def assemble(self):
        ver_hl = (self.ip_ver << 4) + self.ip_hl
        flagment = (self.f_rsv << 15) + (self.f_dtf << 14) + (self.f_mrf << 13) + (self.f_offset & 0x1FFF)

        header = struct.pack('!BBHHHBBH4s4s', ver_hl, self.tos, self.tol, self.fid, flagment, self.ttl, self.proto,
                             self.checksum, self.src, self.dst)

        header += self.data

        return header

    @classmethod
    def disassemble(cls, raw_data):
        ip_hdr = IPHdr()

        if len(raw_data) > cls.IP_DEFAULT_SIZE:
            payload = raw_data[cls.IP_DEFAULT_SIZE:]
            raw_data = raw_data[:cls.IP_DEFAULT_SIZE]
        else:
            payload = ''.encode()

        ip = struct.unpack('!BBHHHBBH', raw_data[:-8])

        ip_hdr.ip_ver = ip[0] >> 4
        ip_hdr.ip_hl = ip[0] & 0x0F
        ip_hdr.tos = ip[1]
        ip_hdr.tol = ip[2]
        ip_hdr.fid = ip[3]
        flag = ip[4] >> 13
        ip_hdr.f_rsv = flag >> 2
        ip_hdr.f_dtf = (flag & 0x02) >> 1
        ip_hdr.f_mrf = flag & 0x01
        ip_hdr.f_offset = ip[4] & 0x1FFF
        ip_hdr.ttl = ip[5]
        ip_hdr.proto = ip[6]
        ip_hdr.checksum = ip[7]
        ip_hdr.src = raw_data[12:16]
        ip_hdr.dst = raw_data[16:20]
        ip_hdr.data = payload

        return ip_hdr


class UDPHdr(ProtocolHdl):
    UDP_DEFAULT_SIZE = 8

    def __init__(self, src_port=5555, dst_port=5555, data=''):
        self.src_port = src_port
        self.dst_port = dst_port
        self.packet_length = 0
        self.checksum = 0
        self.data = data if isinstance(data, bytes) else data.encode()

    @classmethod
    def make_udp_checksum(cls):
        # implement proper checksum
        return 0

    def assemble(self):
        self.packet_length = len(self.data) + UDPHdr.UDP_DEFAULT_SIZE
        sdl_part = struct.pack("!HHH", self.src_port, self.dst_port, self.packet_length)
        checksum = self.make_udp_checksum()
        checksum = struct.pack("!H", checksum)

        return sdl_part + checksum + self.data

    @classmethod
    def disassemble(cls, raw_data):
        udp_hdr = UDPHdr()

        if len(raw_data) > cls.UDP_DEFAULT_SIZE:
            payload = raw_data[cls.UDP_DEFAULT_SIZE:]
            raw_data = raw_data[:cls.UDP_DEFAULT_SIZE]
        else:
            payload = ''.encode()

        udp_hdr.src_port, udp_hdr.dst_port, udp_hdr.packet_length, udp_hdr.checksum = struct.unpack("!HHHH", raw_data)
        udp_hdr.data = payload

        return udp_hdr


class ICMPHdr(ProtocolHdl):
    ICMP_DEFAULT_SIZE = 8

    def __init__(self, data=''):
        self.type = 8
        self.code = 0
        self.checksum = 0
        self.id = 0
        self.seq = 0
        self.data = data if isinstance(data, bytes) else data.encode()

    def assemble(self):
        type_code_part = struct.pack('BB', self.type, self.code)
        id_seq_part = struct.pack('!HH', self.id, self.seq)
        checksum = ProtocolHdl.make_checksum(type_code_part + b'\x00\x00' + id_seq_part + self.data)
        self.checksum = checksum

        return type_code_part + struct.pack('!H', self.checksum) + id_seq_part + self.data

    @classmethod
    def disassemble(cls, raw_data):
        icmp_hdr = cls()
        if len(raw_data) > cls.ICMP_DEFAULT_SIZE:
            payload = raw_data[cls.ICMP_DEFAULT_SIZE:]
            raw_data = raw_data[:cls.ICMP_DEFAULT_SIZE]
        else:
            payload = ''.encode()

        icmp_hdr.type, icmp_hdr.code, icmp_hdr.checksum, icmp_hdr.id, icmp_hdr.seq = struct.unpack('!BBHHH', raw_data)
        icmp_hdr.data = payload

        return icmp_hdr