# savage
Automated Wifi Encryption Defeat Tool
Given an aircrack-ng compatible wireless network card, savage will automatically deauth all WPA-enabled wireless networks within range and save the 4-way WPA handshake to disk for later offline cracking.  With optional tweaks this tool can be optimized for deauthing stationary or moving targets, such as during wardriving.
savage takes a lot of code inspiration from the popular tool, wifite.  Much thanks and credit goes to the wifite team.  If you are unfamiliar with wifite, please check out their repo:  https://github.com/derv82/wifite2
# Requirements
savage was written on and developed with Kali Linux in mind.
1.  An aircrack-ng compatible network card.  This tool was developed and tested with an Alfa Network Wireless USB Adapter, Model: AWUS036NH.  Visit http://www.aircrack-ng.org/doku.php?id=compatibility_drivers for more information about compatible wireless network cards.
2.  aircrack-ng installed.
# Upcoming Capabilities
1.  Automatically start hashcat jobs against captured handshakes that exhibit a high probability of having a weak default PSK set.  Ideally, savage will use an internal database of known default SSIDs that have known weak default PSK schemas to determine which captured PSK is most likely to be cracked in the shortest amount of time.
2.  Automatically configure network manager to connect to cracked APs.
