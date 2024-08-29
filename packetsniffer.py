# Importing the scapy library, which is super handy for messing with network packets
from scapy.all import *

# This is where the magic happens – we're going to capture packets and do some basic analysis on them
def capture_packet(packet):
    # Check if the packet even has an IP layer – because if it doesn't, who cares, right?
    if packet.haslayer(IP):
        # Grab the source and destination IP addresses, and the protocol in use
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto  # This is just a number, but it tells us what protocol we're dealing with
        
        # Now, let's just print this out so we can see what's going on
        print(f"[*] Oh look! A packet! {source_ip} is talking to {destination_ip} using protocol number {protocol}.")
        # This summary gives us a one-liner about the packet, which is cool and all
        print(f"    Here's a quick summary: {packet.summary()}")
        # Just to make things look neat
        print("-" * 50)

# This function gets the whole sniffing process going
def start_sniffer(interface=None):
    # Just a little friendly message to let us know the sniffer is running
    print("Sniffing on the network... (Press Ctrl+C when you're bored or overwhelmed)")
    try:
        # Start sniffing! If you have a specific interface (like wlan0 or eth0), plug it in. If not, it just sniffs everything.
        sniff(iface=interface, prn=capture_packet)
    except KeyboardInterrupt:
        # If you hit Ctrl+C to stop the sniffer, it'll say goodbye nicely
        print("\nSniffer is stopping... Hope you caught some interesting stuff!")
    except Exception as e:
        # If something explodes, we'll at least know what went wrong
        print(f"Ouch, something went wrong: {str(e)}")

# This is where the script starts running. It's the main attraction.
if __name__ == "__main__":
    # You can specify your network interface here. Like, if you're on Wi-Fi, it might be 'wlan0', or for wired it could be 'eth0'.
    interface = "eth0"  # Feel free to change this to whatever interface you want to snoop on.
    start_sniffer(interface)
