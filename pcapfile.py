"""
https://wiki.wireshark.org/Development/LibpcapFileFormat
https://wiki.wireshark.org/Development/PcapNg

pcap format:
Global Header
    PacketHeader
    PacketData
    ... repeat
"""

import logging
import struct

__author__ = 'Wayne Moorefield'
__copyright__ = 'Copyright 2015, Wayne Moorefield'
__license__ = 'MIT'
__maintainer__ = 'Wayne Moorefield'
__status__ = 'Development'

_module_logger = logging.getLogger(__name__)

_PCAP_HDR_MAGIC_NUMBER = 0xA1B2C3D4  # seconds and microseconds
_PCAP_HDR_MAGIC_NUMBER_NS = 0xA1B23C4D  # seconds and nanoseconds


def get_logger():
    return _module_logger


def load(input_file):
    """
    Loads a pcap file
    """

    header = _load_header(input_file)


def _load_header(input_file):
    """
    load the pcap header from file
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    """

    try:
        raw_header = input_file.read(24)  # size of header
    except UnicodeDecodeError:
        _module_logger.error('Unable to read pcap header')
        raise

    # typedef struct pcap_hdr_s {
    #    guint32 magic_number;   /* magic number */
    #    guint16 version_major;  /* major version number */
    #    guint16 version_minor;  /* minor version number */
    #    gint32  thiszone;       /* GMT to local correction */
    #    guint32 sigfigs;        /* accuracy of timestamps */
    #    guint32 snaplen;        /* max length of captured packets, in octets */
    #    guint32 network;        /* data link type */
    # } pcap_hdr_t;
    pcap_hdr_template = "IhhIIII"

    if raw_header[:4] in [struct.pack('>I', _PCAP_HDR_MAGIC_NUMBER),
                          struct.pack('>I', _PCAP_HDR_MAGIC_NUMBER_NS)]:
        # Big Endian
        byte_swap = True if sys.byteorder == 'little' else False

        unpack_template = ''.join(['>', pcap_hdr_template])
    elif raw_header[:4] in [struct.pack('<I', _PCAP_HDR_MAGIC_NUMBER),
                            struct.pack('<I', _PCAP_HDR_MAGIC_NUMBER_NS)]:
        # Little Endian
        byte_swap = True if sys.byteorder == 'big' else False

        unpack_template = ''.join(['<', pcap_hdr_template])
    else:
        raise Exception('Invalid pcap stream, magic number not found')

    unpacked = struct.unpack(unpack_template, raw_header)

    # todo validate header

    _module_logger.info('read the pcap header %r, byteswap %s', unpacked, byte_swap)

    return unpacked

# Temporary Code
import sys

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

_module_logger.setLevel(logging.DEBUG)
_module_logger.addHandler(ch)
# End Temporary Code
