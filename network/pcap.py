import logging
import struct
import sys

__author__ = 'wmoorefi'

_PCAP_HDR_MAGIC_NUMBER = 0xA1B2C3D4  # seconds and microseconds
_PCAP_HDR_MAGIC_NUMBER_NS = 0xA1B23C4D  # seconds and nanoseconds

_module_logger = logging.getLogger(__name__)

class PcapHeader(object):
    """
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
    __slots__ = ['magic_number', 'version_major', 'version_minor', 'thiszone',
                 'sigfigs', 'snaplen', 'network', 'byte_swap',
                 'timestamp_in_ns']

    def __init__(self,
                 magic_number, version_major, version_minor, thiszone,
                 sigfigs, snaplen, network, byte_swap,
                 timestamp_in_ns):
        self.magic_number = magic_number
        self.version_major = version_major
        self.version_minor = version_minor
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.network = network
        self.byte_swap = byte_swap
        self.timestamp_in_ns = timestamp_in_ns


class PcapRecordHeader(object):
    """
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
    } pcaprec_hdr_t;
    """
    __slots__ = ['ts_sec', 'ts_usec', 'incl_len', 'orig_len']

    def __init__(self, ts_sec, ts_usec, incl_len, orig_len):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len


def read_pcap_header(input_file):
    """
    Parse pcap header from stream
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


def read_pcap_record(pcap_hdr, input_file):
    """
    Parse pcap record from stream
    https://wiki.wireshark.org/Development/LibpcapFileFormat
    typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
    } pcaprec_hdr_t;
    """
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
