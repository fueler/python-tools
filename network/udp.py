import struct

__author__ = 'wmoorefi'


class UdpHeader(object):
    """
    RFC768
          0      7 8     15 16    23 24    31
         +--------+--------+--------+--------+
         |     Source      |   Destination   |
         |      Port       |      Port       |
         +--------+--------+--------+--------+
         |                 |                 |
         |     Length      |    Checksum     |
         +--------+--------+--------+--------+
    """
    __slots__ = ['source_port', 'destination_port', 'length', 'checksum']

    def __init__(self, source_port, destination_port, length, checksum):
        self.source_port = source_port
        self.destination_port = destination_port
        self.length = length
        self.checksum = checksum

    def __len__(self):
        return 8

def read_udp_header(input_stream, byte_swap):
    chunk = input_stream.read(8)
    if chunk == '':
        return

    if byte_swap:
        raw_unpacked = struct.unpack('<HHHH', chunk)
    else:
        raw_unpacked = struct.unpack('>HHHH', chunk)

    source_port = raw_unpacked[0]
    destination_port = raw_unpacked[1]
    length = raw_unpacked[2]
    checksum = raw_unpacked[3]

    # FIXME read ipv4 options
    # FIXME store flags as namedtuple

    return UdpHeader(source_port, destination_port, length, checksum)
