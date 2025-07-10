siosniffer

SIOSniffer is a lightweight Python-based packet sniffer that captures and displays raw network packets in real-time. It supports protocol filtering, packet counts, and optional hexdump views for deeper inspection.

Features:
          Real-time packet capture using raw sockets
          Protocol filtering (TCP, UDP, ICMP, ARP, etc.
          Optional hexdump of payload data
          Works on any interface (including loopback)

Installation:
          Make sure you have Python 3 installed. Then, install the required dependencies:
                    pip3 install colorama hexdump

Usage:
          Run the script with sudo for raw socket permissions:
                    sudo python3 siosniffer.py -i eth0 -p ALL

Examples:
          Help Command
                  sudo python3 siosniffer.py -h
          
  Capture all packets on eth0:
                  sudo python3 siosniffer.py -i eth0 -p ALL

  Capture 10 packets with hexdump:
                  sudo python3 siosniffer.py -i eth0 -p ALL -c 10 -x

  Capture 5 ARP packets:
                  sudo python3 siosniffer.py -i eth0 -p ARP -c 5

  Sniff loopback interface (lo):
                  sudo python3 siosniffer.py -i lo -p ALL


⚠️ Notes:
          Must be run with root privileges (sudo) to access raw sockets.
          Works best on Linux environments (like Kali, Ubuntu, etc.).
