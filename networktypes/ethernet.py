import ctypes

__author__ = 'wmoorefi'

class EthernetExtensionHeader(ctypes.Structure):
    """"
    typedef struct ethernet_ext_hdr_s {
        uint16_t ethertype;
        uint3_t pcp;
        uint1_t de;
        uint12_t vid;
    } ethernet_ext_hdr_t;
    """

    _fields_ = [('ethertype', ctypes.c_uint16),
                ('pcp', ctypes.c_uint),
                ('de', ctypes.c_uint),
                ('vid', ctypes.c_uint16)]

class EthernetHeader(ctypes.Structure):
    """
    C-struct of the following header

    typedef struct ethernet_hdr_s {
        uint8_t  destination_mac[6];
        uint8_t  source_mac[6];
        ethernet_ext_hdr_t ext[variable];
    } ethernet_hdr_t;
    """

    _fields_ = [('destination_mac', ctypes.c_uint8 * 6),
                ('source_mac', ctypes.c_uint8 * 6),
                ('ext', EthernetExtensionHeader * variable??)]
