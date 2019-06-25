from abc import ABCMeta, abstractmethod
import struct
from functools import reduce


class ProtocolHdl:
    __metaclass__ = ABCMeta

    @abstractmethod
    def assemble(self):
        pass

    @abstractmethod
    def disassemble(cls, raw_data):
        pass

    @staticmethod
    def make_checksum(header):
        size = len(header)
        if (size % 2) == 1:
            header += b'\x00'
            size += 1
        size = size // 2
        header = struct.unpack('!' + str(size) + 'H', header)
        sum = reduce(lambda x, y: x+y, header)
        chksum = (sum >> 16) + (sum & 0xffff)
        chksum += chksum >> 16
        chksum = (chksum ^ 0xffff)

        return chksum


