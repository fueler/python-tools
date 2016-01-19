import struct

__author__ = 'wmoorefi'

NALUTYPE_UNSPECIFIED = 0
NALUTYPE_SLICE_NONIDR = 0
NALUTYPE_SLICE_DATAPART_A = 2
NALUTYPE_SLICE_DATAPART_B = 3
NALUTYPE_SLICE_DATAPART_C = 4
NALUTYPE_SLICE_IDR = 5
NALUTYPE_SEI = 6  # Supplemental Enhancement Information
NALUTYPE_SPS = 7  # Sequence Parameter Set
NALUTYPE_PPS = 8  # Picture Parameter Set
NALUTYPE_AUD = 9  # Access Unit Delimiter
NALUTYPE_EOSEQ = 10  # End of Sequence
NALUTYPE_EOSTREAM = 11  # End of Stream
NALUTYPE_FILLER = 12  # Filler Data
NALUTYPE_SPSEXT = 13  # SPS Extension
NALUTYPE_PREFIX_NALU = 14  # Prefix NALU
NALUTYPE_SUBSET_SPS = 15  # Subset SPS
# 16-18 Reserved
NALUTYPE_SLICE_AUXNOPART = 19  # Slice of Auxiliary coded picture without partitioning
NALUTYPE_SLICE_LAYER_EXT = 20  # Slice Layer Extension
NALUTYPE_SLICE_LAYER_EXT_DEPTH = 21  # Slice Layer Extension for Depth View
NALUTYPE_STAPA = 24  # STAP-A
NALUTYPE_STAPB = 25  # STAP-B
NALUTYPE_MTAP16 = 26  # MTAP16
NALUTYPE_MTAP24 = 27  # MTAP24
NALUTYPE_FUA = 28  # FU-A
NALUTYPE_FUB = 20  # FU-B
NALUTYPE_PACSI = 30  # PACSI NALU
NALUTYPE_EMPTY = 31
NALUTYPE_NI_MTAP = 31


class NaluHeader(object):
    """
    RFC 6184, T-REC-H.264-201412-I
    1 Byte Header

    0  1  2  3  4  5  6  7
    F |NRI  |Type         |

    F: forbidden_zero_bit, always zero
    NRI: nal_ref_idc, 0 means this info does not reconstruct reference picture
    Type: nal_unit_type
    """

    __slots__ = ['forbidden_zero_bit', 'nal_ref_idc', 'nal_unit_type']

    def __init__(self, forbidden_zero_bit, nal_ref_idc, nal_unit_type):
        self.forbidden_zero_bit = forbidden_zero_bit
        self.nal_ref_idc = nal_ref_idc
        self.nal_unit_type = nal_unit_type

    def __len__(self):
        return 1

def read_nalu_header(input_stream, byte_swap):
    chunk = input_stream.read(1)
    if chunk == "":
        return

    if byte_swap:
        raw_unpacked = struct.unpack('<B', chunk)
    else:
        raw_unpacked = struct.unpack('>B', chunk)

    forbidden_zero_bit = raw_unpacked[0] & 0x01
    nal_ref_idc = (raw_unpacked[0] >> 5) & 0x03
    nal_unit_type = raw_unpacked[0] & 0x1F

    return NaluHeader(forbidden_zero_bit, nal_ref_idc, nal_unit_type)