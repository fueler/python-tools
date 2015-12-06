import struct

__author__ = 'wmoorefi'

# http://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
PROTOCOL_HOPOPTS = 0
PROTOCOL_ICMP = 1
PROTOCOL_IGMP = 2
PROTOCOL_GGP = 3
PROTOCOL_IPV4 = 4
PROTOCOL_ST = 5
PROTOCOL_TCP = 6
PROTOCOL_CBT = 7
PROTOCOL_EGP = 8
PROTOCOL_IGP = 9
PROTOCOL_BBN_RCC_MON = 10
PROTOCOL_NVP_II = 11
PROTOCOL_PUP = 12
PROTOCOL_ARGUS = 13
PROTOCOL_EMCON = 14
PROTOCOL_XNET = 15
PROTOCOL_CHAOS = 16
PROTOCOL_UDP = 17
PROTOCOL_MUX = 18


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

    def __len__(self):
        return self.internet_hdr_length


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
