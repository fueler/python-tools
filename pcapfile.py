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
from network import ethernet
from network import pcap

__author__ = 'Wayne Moorefield'
__copyright__ = 'Copyright 2015, Wayne Moorefield'
__license__ = 'MIT'
__maintainer__ = 'Wayne Moorefield'
__status__ = 'Development'

_module_logger = logging.getLogger(__name__)

def get_logger():
    return _module_logger

def load(input_file):
    """
    Loads a pcap file
    """
    header = pcap.read_pcap_header(input_file)
    return header


def record_reader(pcap_hdr, input_file):
    while True:
        try:
            record = pcap.read_pcap_record(pcap_hdr, input_file)
            if record:
                yield record
            else:
                break
        except UnicodeDecodeError:
            pass  # ignore, file done

def payload_reader(pcap_hdr, record_hdr, input_file):
    input_file.read(record_hdr.incl_len - 14)

# Temporary Code
import sys

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

_module_logger.setLevel(logging.DEBUG)
_module_logger.addHandler(ch)
# End Temporary Code

if __name__ == '__main__':
    with open('test.pcap', 'rb') as fp:
        hdr = load(fp)
        for record in record_reader(hdr, fp):
            hdr = ethernet.read_ethernet_header(fp, hdr.byte_swap)

            print 'ethernet header'
            print 'dst:', ' '.join([hex(i) for i in hdr.destination_mac])
            print 'src:', ' '.join([hex(i) for i in hdr.source_mac])
            print 'type:', hex(hdr.ethertype)

            payload_reader(hdr, record, fp)
            break
