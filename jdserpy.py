#!/usr/bin/env python

import pcapy
import sys
from impacket.ImpactDecoder import EthDecoder
import socket
import javaobj
import re
import optparse
from pprint import pprint
from colorama import Fore

all_chars = (unichr(i) for i in xrange(0x110000))
control_chars = ''.join(map(unichr, range(0, 32) + range(127, 160)))
control_char_re = re.compile('[%s]' % re.escape(control_chars))


def remove_control_chars(s):
    return control_char_re.sub(' ', s)

decoder = EthDecoder()

MAGIC_NUMBER = '\xac\xed'


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
        proto_desc = 'TCP'
    elif proto == socket.IPPROTO_UDP:
        dport = tmp.child().child().get_uh_dport()
        sport = tmp.child().child().get_uh_sport()
        proto_desc = 'UDP'

    # java serialization detection
    packet_data = tmp.child().child().child()
    packet_data_str = packet_data.get_packet()
    index = packet_data_str.find(MAGIC_NUMBER)
    if index != -1:
        print '\n\n'
        print Fore.CYAN + '=' * 80 + Fore.RESET
        print Fore.GREEN + '%s:%s -> %s:%s [%s]' % (ip_src, sport, ip_dst,
                dport, proto_desc) + Fore.RESET
        packet_data_str = packet_data_str[index:]

        try:
            # parse java serialization to python object
            pobj = javaobj.loads(packet_data_str)

            if isinstance(pobj, str):
                print(remove_control_chars(pobj).split()[0][1:])
                print Fore.CYAN + '-' * 80 + Fore.RESET
                # print package body, cause fail parse.
                print pprint(remove_control_chars(packet_data_str).split())
            else:
                print pobj

            print Fore.CYAN + '=' * 80 + Fore.RESET

            # import pdb
            # pdb.set_trace()
        except Exception as e:
            print e


def main(input_res, live=False):
    if live:
        handler = pcapy.open_live(input_res, 1500, 0, 100)
    else:
        handler = pcapy.open_offline(input_res)
    handler.loop(0, packet_handler)


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-i', '--input', action='store', dest='input_res',
            type='string')
    parser.add_option('--live', action='store_true', dest='is_live',
            default=False)

    options, remainder = parser.parse_args(sys.argv)

    if not options.input_res:
        parser.print_help()
        sys.exit(2)

    main(options.input_res, options.is_live)
