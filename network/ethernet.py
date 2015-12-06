import struct

__author__ = 'wmoorefi'

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_8021Q = 0x8100
ETHERTYPE_8021AD = 0x88A8


class EthernetExtensionHeader(object):
    """"
    typedef struct ethernet_ext_hdr_s {
        uint3_t pcp;
        uint1_t de;
        uint12_t vid;
        uint16_t ethertype;
    } ethernet_ext_hdr_t;
    """
    __slots__ = ['pcp', 'de', 'vid', 'ethertype']

    def __init__(self, pcp, de, vid, ethertype):
        self.pcp = pcp
        self.de = de
        self.vid = vid
        self.ethertype = ethertype


class EthernetHeader(object):
    """
    typedef struct ethernet_hdr_s {
        uint8_t  destination_mac[6];
        uint8_t  source_mac[6];
        uint16_t ethertype
        ethernet_ext_hdr_t ext[variable];
    } ethernet_hdr_t;
    """
    __slots__ = ['destination_mac', 'source_mac', 'ethertype', 'ext']

    def __init__(self, destination_mac, source_mac, ethertype, ext=[]):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.ethertype = ethertype
        self.ext = ext

    def __len__(self):
        return 14  # FIXME account for ext size


def read_ethernet_header(input_stream, byte_swap):
    chunk = input_stream.read(14)
    if chunk == '':
        return

    if byte_swap:
        raw_unpacked = struct.unpack('<BBBBBBBBBBBBH', chunk)
    else:
        raw_unpacked = struct.unpack('>BBBBBBBBBBBBH', chunk)
    destination_mac = raw_unpacked[:6]
    source_mac = raw_unpacked[6:12]
    ethertype = raw_unpacked[-1]

    return EthernetHeader(destination_mac, source_mac, ethertype)
