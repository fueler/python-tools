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
import ctypes

__author__ = 'Wayne Moorefield'
__copyright__ = 'Copyright 2015, Wayne Moorefield'
__license__ = 'MIT'
__maintainer__ = 'Wayne Moorefield'
__status__ = 'Development'

_module_logger = logging.getLogger(__name__)

_PCAP_HDR_MAGIC_NUMBER = 0xA1B2C3D4  # seconds and microseconds
_PCAP_HDR_MAGIC_NUMBER_NS = 0xA1B23C4D  # seconds and nanoseconds


class PcapHeader(ctypes.Structure):
    """
    C-struct of the following header.
    https://wiki.wireshark.org/Development/LibpcapFileFormat

    typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
    } pcap_hdr_t;
    """

    _fields_ = [('magic_number', ctypes.c_uint32),
                ('version_major', ctypes.c_uint16),
                ('version_minor', ctypes.c_uint16),
                ('thiszone', ctypes.c_int32),
                ('sigfigs', ctypes.c_uint32),
                ('snaplen', ctypes.c_uint32),
                ('network', ctypes.c_uint32),
                # Associated Metadata
                ('byte_swap', ctypes.c_bool),
                ('timestamp_in_ns', ctypes.c_bool)]

class PcapRecordHeader(ctypes.Structure):
    """
    C-struct of the following header.
    https://wiki.wireshark.org/Development/LibpcapFileFormat

    typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
    } pcaprec_hdr_t;
    """

    _fields_ = [('ts_sec', ctypes.c_uint32),
                ('ts_usec', ctypes.c_uint32),
                ('incl_len', ctypes.c_uint32),
                ('orig_len', ctypes.c_uint32)]

def get_logger():
    return _module_logger


def load(input_file):
    """
    Loads a pcap file
    """

    header = _read_header(input_file)
    return header


def _read_header(input_file):
    """
    load the pcap header from file
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    """

    # typedef struct pcap_hdr_s {
    #     guint32 magic_number;   /* magic number */
    #     guint16 version_major;  /* major version number */
    #     guint16 version_minor;  /* minor version number */
    #     gint32  thiszone;       /* GMT to local correction */
    #     guint32 sigfigs;        /* accuracy of timestamps */
    #     guint32 snaplen;        /* max length of captured packets, in octets */
    #     guint32 network;        /* data link type */
    # } pcap_hdr_t;
    pcap_hdr_fmt = "IhhIIII"

    try:
        raw_header = input_file.read(24)  # size of header
    except UnicodeDecodeError:
        _module_logger.error('Unable to read pcap header')
        raise

    if raw_header[:4] in [struct.pack('>I', _PCAP_HDR_MAGIC_NUMBER),
                          struct.pack('>I', _PCAP_HDR_MAGIC_NUMBER_NS)]:
        # Big Endian
        byte_swap = True if sys.byteorder == 'little' else False

        unpack_template = ''.join(['>', pcap_hdr_fmt])
    elif raw_header[:4] in [struct.pack('<I', _PCAP_HDR_MAGIC_NUMBER),
                            struct.pack('<I', _PCAP_HDR_MAGIC_NUMBER_NS)]:
        # Little Endian
        byte_swap = True if sys.byteorder == 'big' else False

        unpack_template = ''.join(['<', pcap_hdr_fmt])
    else:
        raise Exception('Invalid pcap stream, magic number not found')

    unpacked_header = struct.unpack(unpack_template, raw_header)
    (magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network) = unpacked_header
    pcap_header = PcapHeader(magic_number,
                             version_major,
                             version_minor,
                             thiszone,
                             sigfigs,
                             snaplen,
                             network,
                             byte_swap,
                             magic_number == _PCAP_HDR_MAGIC_NUMBER_NS)

    # todo validate header

    _module_logger.info('[%d] pcap header %r, byteswap %s', input_file.tell(), unpacked_header, byte_swap)
    #_module_logger.info('read the pacp header %r', pcap_header)

    return pcap_header

def _read_record(pcap_hdr, input_file):
    """
    read the next packet
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    """

    # typedef struct pcaprec_hdr_s {
    #     guint32 ts_sec;         /* timestamp seconds */
    #     guint32 ts_usec;        /* timestamp microseconds */
    #     guint32 incl_len;       /* number of octets of packet saved in file */
    #     guint32 orig_len;       /* actual length of packet */
    # } pcaprec_hdr_t;

    pcaprec_hdr_fmt = "IIII"

    try:
        raw_header = input_file.read(16)  # size of header
    except UnicodeDecodeError:
        _module_logger.error('Unable to read pcap packet header')
        raise

    if raw_header == '':
        return

    if pcap_hdr.byte_swap:
        unpack_template = ''.join(['>', pcaprec_hdr_fmt])
    else:
        unpack_template = ''.join(['<', pcaprec_hdr_fmt])

    unpacked_header = struct.unpack(unpack_template, raw_header)
    (ts_sec, ts_usec, incl_len, orig_len) = unpacked_header
    pcap_record = PcapRecordHeader(ts_sec,
                                   ts_usec,
                                   incl_len,
                                   orig_len)

    _module_logger.info('[%d] record header %r', input_file.tell(), unpacked_header)

    return pcap_record

def record_reader(pcap_hdr, input_file):
    while True:
        try:
            record = _read_record(pcap_hdr, input_file)
            if record:
                yield record
            else:
                break
        except UnicodeDecodeError:
            pass  # ignore, file done

def payload_reader(pcap_hdr, record_hdr, input_file):
    input_file.read(record_hdr.incl_len)

# Temporary Code
import sys

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

_module_logger.setLevel(logging.DEBUG)
_module_logger.addHandler(ch)
# End Temporary Code

if __name__ == '__main__':
    with open('test.pcap', 'rb') as f:
        hdr = load(f)
        for record in record_reader(hdr, f):
            payload_reader(hdr, record, f)
