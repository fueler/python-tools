import struct

__author__ = 'wmoorefi'

class RtpHeaderExtension(object):
    """
    RFC3550
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Profile-specific Ext Hdr ID   | Ext Hdr Length                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Header Data                                                   |
       |                          ....                                 |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       Length field is in 32-bit words minus the size of the ext header,
       4 bytes.
    """
    __slots__ = ['header_id', 'length', 'data']

    def __init__(self, header_id, length, data):
        self.header_id = header_id
        self.length = length
        self.data = data

    def __len__(self):
        return 4 + (self.length * 4)

class RtpHeader(object):
    """
    RFC3550
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |V=2|P|X|  CC   |M|     PT      |       sequence number         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           timestamp                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           synchronization source (SSRC) identifier            |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
       |            contributing source (CSRC) identifiers             |
       |                             ....                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

       CC derived from length of csrc_list
       Extension Header
    """
    __slots__ = ['version', 'padding_flag', 'marker_bit', 'payload_type',
                 'sequence_number', 'timestamp', 'ssrc', 'csrc_list',
                 'extension_headers']

    def __init__(self,
                 version, padding_flag, marker_bit, payload_type,
                 sequence_number, timestamp, ssrc, csrc_list,
                 extension_headers):
        self.version = version
        self.padding_flag = padding_flag
        self.marker_bit = marker_bit
        self.payload_type = payload_type
        self.sequence_number = sequence_number
        self.timestamp = timestamp
        self.ssrc = ssrc
        self.csrc_list = csrc_list
        self.extension_headers = extension_headers

    def __len__(self):
        return 12 + (len(self.csrc_list) * 4) + sum([len(hdr) for hdr in self.extension_headers])

def read_rtp_header(input_stream, byte_swap):
    chunk = input_stream.read(12)
    if chunk == '':
        return

    if byte_swap:
        raw_unpacked = struct.unpack('<BBHII', chunk)
    else:
        raw_unpacked = struct.unpack('>BBHII', chunk)

    version = raw_unpacked[0] >> 6
    padding_flag = (raw_unpacked[0] >> 5) & 0x1
    extension_header_present_flag = (raw_unpacked[0] >> 4) & 0x1
    csrc_count = raw_unpacked[0] & 0x0F
    marker_bit = (raw_unpacked[1] >> 7)
    payload_type = raw_unpacked[1] & 0x7F
    sequence_number = raw_unpacked[2]
    timestamp = raw_unpacked[3]
    ssrc = raw_unpacked[4]
    csrc_list = []
    extension_headers = []

    # FIXME - there is a pattern here and this code looks ugly
    for i in range(0, csrc_count):
        chunk = input_stream.read(4)
        if chunk == '':
            return

        if byte_swap:
            raw_unpacked = struct.unpack('<I', chunk)
        else:
            raw_unpacked = struct.unpack('>I', chunk)

        csrc_list.append(raw_unpacked[0])

    # FIXME - handle hdr extensions

    return RtpHeader(version, padding_flag, marker_bit, payload_type,
                     sequence_number, timestamp, ssrc, csrc_list,
                     extension_headers)