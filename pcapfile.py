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
from network import ipv4
from network import udp

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


def payload_reader(input_stream, remaining_bytes):
    input_stream.read(remaining_bytes)


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
        pcap_hdr = load(fp)
        for record_hdr in record_reader(pcap_hdr, fp):
            remaining_bytes = record_hdr.incl_len

            eth_hdr = ethernet.read_ethernet_header(fp, pcap_hdr.byte_swap)
            print 'ethernet header'
            print 'dst:', ' '.join([hex(i) for i in eth_hdr.destination_mac])
            print 'src:', ' '.join([hex(i) for i in eth_hdr.source_mac])
            print 'type:', hex(eth_hdr.ethertype)

            remaining_bytes -= len(eth_hdr)

            if eth_hdr.ethertype == ethernet.ETHERTYPE_IPV4:
                ipv4_hdr = ipv4.read_ipv4_header(fp, pcap_hdr.byte_swap)
                print 'ipv4 header'
                print 'version: ', hex(ipv4_hdr.version)
                print 'hdr len: ', ipv4_hdr.internet_hdr_length
                print 'dscp: ', ipv4_hdr.dscp
                print 'total len: ', ipv4_hdr.total_length, ' bytes'
                print 'identification: ', hex(ipv4_hdr.identification)
                print 'flags: ', hex(ipv4_hdr.flags)
                print 'fragment_offset: ', ipv4_hdr.fragment_offset
                print 'time_to_live: ', ipv4_hdr.time_to_live
                print 'protocol: ', ipv4_hdr.protocol
                print 'checksum: ', hex(ipv4_hdr.header_checksum)
                print 'src:', '.'.join([str(i) for i in ipv4_hdr.source_ip])
                print 'dst:', '.'.join([str(i) for i in ipv4_hdr.destination_ip])

                remaining_bytes -= len(ipv4_hdr)

                if ipv4_hdr.protocol == ipv4.PROTOCOL_UDP:
                    udp_hdr = udp.read_udp_header(fp, pcap_hdr.byte_swap)
                    print 'src_port: ', udp_hdr.source_port
                    print 'dst_port: ', udp_hdr.destination_port
                    print 'length: ', udp_hdr.length
                    print 'checksum: ', hex(udp_hdr.checksum)

                    remaining_bytes -= len(udp_hdr)

            payload_reader(fp, remaining_bytes)
            break
