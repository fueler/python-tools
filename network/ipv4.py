import struct

__author__ = 'wmoorefi'


class Ipv4Header(object):
    """
    RFC791, RFC2474, RFC3168
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  | DSCP      |ECN|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    __slots__ = ['version', 'internet_hdr_length', 'dscp', 'explicit_congestion_notification',
                 'total_length', 'identification', 'flags', 'fragment_offset',
                 'time_to_live', 'protocol', 'header_checksum', 'source_ip',
                 'destination_ip', 'options']

    def __init__(self,
                 version, internet_hdr_length, dscp, explicit_congestion_notification,
                 total_length, identification, flags, fragment_offset,
                 time_to_live, protocol, header_checksum, source_ip,
                 destination_ip, options=[]):
        self.version = version
        self.internet_hdr_length = internet_hdr_length
        self.dscp = dscp
        self.explicit_congestion_notification = explicit_congestion_notification
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.time_to_live = time_to_live
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.options = options


def read_ipv4_header(input_stream, byte_swap):
    chunk = input_stream.read(20)
    if chunk == '':
        return

    if byte_swap:
        raw_unpacked = struct.unpack('<BBHHBBBBHBBBBBBBB', chunk)
    else:
        raw_unpacked = struct.unpack('>BBHHBBBBHBBBBBBBB', chunk)

    version = raw_unpacked[0] >> 4
    internet_hdr_length = (raw_unpacked[0] & 0x0F) * 4
    dscp = raw_unpacked[1] >> 2
    explicit_congestion_notification = raw_unpacked[1] & 0x03
    total_length = raw_unpacked[2]
    identification = raw_unpacked[3]
    flags = raw_unpacked[4] >> 5
    fragment_offset = ((raw_unpacked[4] & 0x1F) << 8) | raw_unpacked[5]
    time_to_live = raw_unpacked[6]
    protocol = raw_unpacked[7]
    header_checksum = raw_unpacked[8]
    source_address = raw_unpacked[9:13]
    destination_address = raw_unpacked[13:17]

    # FIXME read ipv4 options
    # FIXME store flags as namedtuple

    return Ipv4Header(version, internet_hdr_length, dscp, explicit_congestion_notification,
                      total_length, identification, flags, fragment_offset,
                      time_to_live, protocol, header_checksum, source_address,
                      destination_address)
