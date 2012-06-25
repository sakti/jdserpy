#!/usr/bin/env python

import pcapy
import sys
from impacket.ImpactDecoder import EthDecoder
import socket
import javaobj
import re

all_chars = (unichr(i) for i in xrange(0x110000))
control_chars = ''.join(map(unichr, range(0, 32) + range(127, 160)))

control_char_re = re.compile('[%s]' % re.escape(control_chars))


def remove_control_chars(s):
    return control_char_re.sub(' ', s)

decoder = EthDecoder()


def packet_handler(hdr, data):
    tmp = decoder.decode(data)

    try:
        ip_src = tmp.child().get_ip_src()
        ip_dst = tmp.child().get_ip_dst()
        proto = tmp.child().child().protocol
    except:
        return

    if proto == socket.IPPROTO_TCP:
        dport = tmp.child().child().get_th_dport()
        sport = tmp.child().child().get_th_sport()
    elif proto == socket.IPPROTO_UDP:
        dport = tmp.child().child().get_uh_dport()
        sport = tmp.child().child().get_uh_sport()

    # java serialization detection
    packet_data = tmp.child().child().child()
    packet_data_str = packet_data.get_packet()
    index = packet_data_str.find('\xac\xed')
    if index != -1:
        print '\n\n'
        print '=' * 80
        print ip_src, ip_dst, proto
        print dport, sport
        packet_data_str = packet_data_str[index:]

        try:
            pobj = javaobj.loads(packet_data_str)
            if isinstance(pobj, str):
                print remove_control_chars(pobj)
            else:
                print pobj
            print '-' * 80
            print remove_control_chars(packet_data_str)
            # import pdb
            # pdb.set_trace()
        except Exception as e:
            print e


def main(fileinputname, live=False):
    if live:
        handler = pcapy.open_live('wlan0', 1500, 0, 100)
    else:
        handler = pcapy.open_offline(fileinputname)
    handler.loop(0, packet_handler)


def help():
    print '%s <pcap filename>' % __file__


if __name__ == '__main__':
    if len(sys.argv) != 2:
        help()
        sys.exit(1)
    livecapture = False
    if sys.argv[1] == 'live':
        livecapture = True
    main(sys.argv[1], livecapture)
