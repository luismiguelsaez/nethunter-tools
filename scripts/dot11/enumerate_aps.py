from scapy.all import *
import threading
from itertools import cycle
from os import system
from time import sleep

def iface_set_monitor(iface = 'wlan1'):
    system(f"ip link set {iface} down")
    system(f"iw {iface} set monitor none")
    system(f"ip link set {iface} up")

def loop_channels():
    for c in cycle(['1','2','3','4','5','6','7','8','9','10','11']):
        system(f"iwconfig wlan1 channel {c}")
        sleep(0.5)

def get_ap(p):
    if p.haslayer(Dot11Beacon):
        essid = p[Dot11Elt].info.decode()
        ssid = p.addr2
        freq = p.ChannelFrequency
        dBm = p.dBm_AntSignal
        if ssid not in ssids and ssid != "":
            print(f"Saw new SSID [{dBm}]: '{ssid}', ESSID: '{essid}', Freq: {freq}")
            ssids[ssid] = { 'essid': essid, 'freq': freq }

ssids = {}

interface = "wlan1"

iface_set_monitor(iface=interface)

thread_loop_channels = Thread(target=loop_channels)
thread_loop_channels.daemon = True
thread_loop_channels.start()

sniff(iface=interface, prn=get_ap)
