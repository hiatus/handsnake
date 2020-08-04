handsnake
=========

WPA2 handshake capture automator

Features
--------
- Automatic deauthentication
	- Client stations
	- Broadcast (option `-b`, `--broadcast`)


- Granular control
	- Target ESSIDs
	- Target channels
	- Minimum signal strength
	- Number of injected packets
	- Number of capture attemtps


Dependencies
------------
- [Scapy](https://scapy.net)
	- Packet forging and sniffing


- [Tcpdump](http://tcpdump.org)
	- Using BPF filters with Scapy
