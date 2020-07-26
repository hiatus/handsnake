import re
import subprocess

from scapy.all import get_if_hwaddr, sniff, sendp


class NetworkInterface(object):
    def __init__(self, name: str):
        try:
            self.name = name
            self.channel = None
            self.hwaddr = get_if_hwaddr(name)

        except Exception as x:
            raise type(x)(f'Invalid network interface: {name}')

    # Set NIC to monitor mode
    def set_monitor(self, state: bool):
        mode = 'monitor' if state else 'managed'

        try:
            cp = subprocess.run(
                ['ip', 'link', 'set', self.name, 'down'],
                stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL
            )

            if cp.returncode:
                raise RuntimeError

            cp = subprocess.run(
                ['iwconfig', self.name, 'mode', mode],
                stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL
            )

            if cp.returncode:
                raise RuntimeError

            cp = subprocess.run(
                ['ip', 'link', 'set', self.name, 'up'],
                stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL
            )

            if cp.returncode:
                raise RuntimeError

        except Exception as x:
            raise type(x)(f'Failed to set {self.name} to {mode} mode')

    # Set the NIC's channel
    def set_channel(self, channel):
        if channel not in range(1, 15):
            raise ValueError(f'Invalid channel: {channel}')

        try:
            cp = subprocess.run(
                ['iwconfig', self.name, 'channel', str(channel)],
                stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL
            )

            if cp.returncode:
                raise RuntimeError

        except Exception as x:
            raise type(x)(f'Failed to set {self.name} on channel {channel}')

        self.channel = channel

    # Receive (sniff) packets
    def recv(self, **kwargs):
        sniff(iface = self.name, **kwargs)

    # Send packets
    def send(self, pkt, **kwargs):
        sendp(pkt, iface = self.name, **kwargs)
