#!/usr/bin/python3

import socket
import os
import struct
import binascii
import argparse
import logging
import sys
from datetime import datetime
try:
    from colorama import init, Fore, Style
    colorama_available = True
except ImportError:
    colorama_available = False
try:
    import hexdump
    hexdump_available = True
except ImportError:
    hexdump_available = False

# Initialize colorama if available
if colorama_available:
    init()

# Global variables
sock_created = False
sniffer_socket = None
packet_count = 0
src_port = 0
dst_port = 0

def setup_logging(log_file):
    """Configure logging to file and console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def validate_interface(interface):
    """Check if the network interface exists."""
    try:
        with open('/sys/class/net/' + interface + '/operstate') as f:
            return True
    except FileNotFoundError:
        return False

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Packet Sniffer for Kali Linux with protocol and IP filtering")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff (e.g., eth0, wlan0)")
    parser.add_argument("-p", "--protocol", choices=['TCP', 'UDP', 'ALL'], default='ALL', help="Filter by protocol (TCP, UDP, or ALL)")
    parser.add_argument("--src-ip", help="Filter by source IP address")
    parser.add_argument("--dst-ip", help="Filter by destination IP address")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture before exiting")
    parser.add_argument("-l", "--log", default=f"sniffer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log", help="Log file name")
    parser.add_argument("-s", "--summary", action="store_true", help="Display summary mode (less detailed output)")
    parser.add_argument("-x", "--hexdump", action="store_true", help="Show payload hexdump (requires hexdump package)")
    return parser.parse_args()

def color_print(text, color=None):
    """Print with color if colorama is available, else plain."""
    if colorama_available and color:
        print(f"{color}{text}{Style.RESET_ALL}")
    else:
        print(text)

def simple_hexdump(data):
    """Fallback hexdump function if hexdump package is unavailable."""
    hex_str = binascii.hexlify(data).decode()
    return '\n'.join(hex_str[i:i+32] for i in range(0, len(hex_str), 32))

def analyse_arp_header(data):
    """Analyze ARP header (simplified)."""
    try:
        if len(data) < 28:
            logging.error(f"ARP header too short: {len(data)} bytes (expected 28), raw data: {binascii.hexlify(data).decode()}")
            return None, None, None
        # Explicitly define the expected 28-byte ARP header format
        arp_hdr = struct.unpack('!2H2BHH6s4s6s4s', data[:28])
        htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = arp_hdr
        operation = "Request" if oper == 1 else "Reply" if oper == 2 else "Unknown"
        sender_ip = socket.inet_ntoa(spa)
        target_ip = socket.inet_ntoa(tpa)
        
        if not args.summary:
            color_print("__________ARP HEADER__________", Fore.CYAN)
            color_print(f"Hardware Type: {htype}", Fore.YELLOW)
            color_print(f"Protocol Type: 0x{ptype:04x}", Fore.YELLOW)
            color_print(f"Hardware Length: {hlen}", Fore.YELLOW)
            color_print(f"Protocol Length: {plen}", Fore.YELLOW)
            color_print(f"Operation: {operation} ({oper})", Fore.YELLOW)
            color_print(f"Sender MAC: {':'.join(binascii.hexlify(sha).decode()[i:i+2] for i in range(0, 12, 2))}", Fore.GREEN)
            color_print(f"Sender IP: {sender_ip}", Fore.GREEN)
            color_print(f"Target MAC: {':'.join(binascii.hexlify(tha).decode()[i:i+2] for i in range(0, 12, 2))}", Fore.GREEN)
            color_print(f"Target IP: {target_ip}", Fore.GREEN)
        
        logging.info(f"Parsed ARP packet: Operation={operation}, Sender IP={sender_ip}, Target IP={target_ip}")
        return data[28:], sender_ip, target_ip
    except struct.error as e:
        logging.error(f"ARP header parsing error: {e}, data length: {len(data)} bytes (expected 28), raw data: {binascii.hexlify(data).decode()}")
        color_print(f"ARP header parsing error: {e}", Fore.RED)
        return None, None, None

def analyse_udp_header(data_recv):
    """Analyze UDP header."""
    global src_port, dst_port
    try:
        if len(data_recv) < 8:
            logging.error(f"UDP header too short: {len(data_recv)} bytes")
            return None
        udp_hdr = struct.unpack('!4H', data_recv[:8])
        src_port, dst_port, length, checksum = udp_hdr
        data = data_recv[8:]
        
        if not args.summary:
            color_print("__________UDP HEADER__________", Fore.CYAN)
            color_print(f"Source Port: {src_port}", Fore.GREEN)
            color_print(f"Destination Port: {dst_port}", Fore.GREEN)
            color_print(f"Length: {length}", Fore.YELLOW)
            color_print(f"Checksum: {checksum}", Fore.YELLOW)
        
        return data
    except struct.error as e:
        logging.error(f"UDP header parsing error: {e}")
        color_print(f"UDP header parsing error: {e}", Fore.RED)
        return None

def analyze_tcp_header(data_recv):
    """Analyze TCP header."""
    global src_port, dst_port
    try:
        if len(data_recv) < 20:
            logging.error(f"TCP header too short: {len(data_recv)} bytes")
            return None
        tcp_hdr = struct.unpack('!2H2I4H', data_recv[:20])
        src_port, dst_port, seq_num, ack_num, data_offset, window, checksum, urg_ptr = tcp_hdr
        data_offset = tcp_hdr[4] >> 12
        flags = tcp_hdr[4] & 0x003f
        urg = bool(flags & 0x0020)
        ack = bool(flags & 0x0010)
        psh = bool(flags & 0x0008)
        rst = bool(flags & 0x0004)
        syn = bool(flags & 0x0002)
        fin = bool(flags & 0x0001)
        data = data_recv[20:]

        if not args.summary:
            color_print("__________TCP HEADER__________", Fore.CYAN)
            color_print(f"Source Port: {src_port}", Fore.GREEN)
            color_print(f"Destination Port: {dst_port}", Fore.GREEN)
            color_print(f"Sequence: {seq_num}", Fore.YELLOW)
            color_print(f"Acknowledgment: {ack_num}", Fore.YELLOW)
            color_print(f"Flags: URG={urg}, ACK={ack}, PSH={psh}, RST={rst}, SYN={syn}, FIN={fin}", Fore.RED)
            color_print(f"Window Size: {window}", Fore.YELLOW)
            color_print(f"Checksum: {checksum}", Fore.YELLOW)

        return data
    except struct.error as e:
        logging.error(f"TCP header parsing error: {e}")
        color_print(f"TCP header parsing error: {e}", Fore.RED)
        return None

def analyse_ip_header(data_recv):
    """Analyze IP header."""
    global src_port, dst_port
    try:
        if len(data_recv) < 20:
            logging.error(f"IP header too short: {len(data_recv)} bytes")
            return None, None, None, None
        ip_hdr = struct.unpack('!6H4s4s', data_recv[:20])
        ver = ip_hdr[0] >> 12
        ihl = (ip_hdr[0] >> 8) & 0x0f
        tos = ip_hdr[0] & 0x00ff
        tot_len = ip_hdr[1]
        ip_id = ip_hdr[2]
        flags = ip_hdr[3] >> 13
        frag_offset = ip_hdr[3] & 0x1fff
        ip_ttl = ip_hdr[4] >> 8
        ip_proto = ip_hdr[4] & 0x00ff
        checksum = ip_hdr[5]
        src_address = socket.inet_ntoa(ip_hdr[6])
        dst_address = socket.inet_ntoa(ip_hdr[7])
        data = data_recv[20:]

        # Apply IP filters
        if args.src_ip and src_address != args.src_ip:
            logging.info(f"Packet filtered out: src IP {src_address} does not match {args.src_ip}")
            return None, None, None, None
        if args.dst_ip and dst_address != args.dst_ip:
            logging.info(f"Packet filtered out: dst IP {dst_address} does not match {args.dst_ip}")
            return None, None, None, None

        if args.summary:
            color_print(f"Packet {packet_count}: {src_address}:{src_port} -> {dst_address}:{dst_port} Proto: {ip_proto}", Fore.MAGENTA)
        else:
            color_print("__________IP HEADER__________", Fore.CYAN)
            color_print(f"Version: {ver}", Fore.YELLOW)
            color_print(f"IHL: {ihl}", Fore.YELLOW)
            color_print(f"TOS: {tos}", Fore.YELLOW)
            color_print(f"Length: {tot_len}", Fore.YELLOW)
            color_print(f"ID: {ip_id}", Fore.YELLOW)
            color_print(f"Offset: {frag_offset}", Fore.YELLOW)
            color_print(f"TTL: {ip_ttl}", Fore.YELLOW)
            color_print(f"Protocol: {ip_proto}", Fore.YELLOW)
            color_print(f"Checksum: {checksum}", Fore.YELLOW)
            color_print(f"Source IP: {src_address}", Fore.GREEN)
            color_print(f"Destination IP: {dst_address}", Fore.GREEN)

        if ip_proto == 6:
            tcp_udp = "TCP"
        elif ip_proto == 17:
            tcp_udp = "UDP"
        else:
            tcp_udp = f"OTHER_{ip_proto}"
            logging.info(f"Non-TCP/UDP packet detected, protocol: {ip_proto}")
            src_port = 0
            dst_port = 0  # Reset ports for non-TCP/UDP protocols

        return data, tcp_udp, src_address, dst_address
    except struct.error as e:
        logging.error(f"IP header parsing error: {e}")
        color_print(f"IP header parsing error: {e}", Fore.RED)
        return None, None, None, None

def analyse_ether_header(data_recv):
    """Analyze Ethernet header."""
    try:
        if len(data_recv) < 14:
            logging.error(f"Ethernet header too short: {len(data_recv)} bytes")
            return None, False, False
        eth_hdr = struct.unpack('!6s6sH', data_recv[:14])
        dest_mac = binascii.hexlify(eth_hdr[0]).decode()
        src_mac = binascii.hexlify(eth_hdr[1]).decode()
        proto = eth_hdr[2]  # Use full 16-bit protocol value
        data = data_recv[14:]

        if not args.summary:
            color_print("__________ETHERNET HEADER__________", Fore.CYAN)
            color_print(f"Destination MAC: {':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))}", Fore.GREEN)
            color_print(f"Source MAC: {':'.join(src_mac[i:i+2] for i in range(0, 12, 2))}", Fore.GREEN)
            color_print(f"Protocol: 0x{proto:04x}", Fore.YELLOW)

        ip_bool = (proto == 0x0800)  # IPv4
        arp_bool = (proto == 0x0806)  # ARP
        if not ip_bool and not arp_bool:
            logging.info(f"Non-IPv4/ARP packet detected, protocol: 0x{proto:04x}")

        return data, ip_bool, arp_bool
    except struct.error as e:
        logging.error(f"Ethernet header parsing error: {e}")
        color_print(f"Ethernet header parsing error: {e}", Fore.RED)
        return None, False, False

def main():
    """Main packet sniffing loop."""
    global sock_created, sniffer_socket, packet_count, args, src_port, dst_port
    args = parse_args()
    setup_logging(args.log)

    # Display banner
    color_print("Sniffer By SIONetwork", Fore.CYAN)
    logging.info("Sniffer By SIONetwork")

    # Validate interface
    if not validate_interface(args.interface):
        color_print(f"Error: Interface {args.interface} does not exist", Fore.RED)
        sys.exit(1)

    # Check hexdump availability
    if args.hexdump and not hexdump_available:
        color_print("Warning: hexdump package not installed. Falling back to simple hexdump.", Fore.YELLOW)
        args.hexdump = False

    try:
        if not sock_created:
            sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sniffer_socket.bind((args.interface, 0))
            sock_created = True
            logging.info(f"Started sniffing on interface {args.interface}")
            color_print(f"Sniffing on {args.interface}...", Fore.BLUE)

        while True:
            try:
                data_recv = sniffer_socket.recv(2048)
                packet_count += 1
                logging.info(f"Received packet {packet_count}, length: {len(data_recv)} bytes")
                color_print(f"\n=== Packet {packet_count} ===", Fore.BLUE)

                data, ip_bool, arp_bool = analyse_ether_header(data_recv)
                if data is None:
                    logging.info(f"Skipping packet {packet_count}: Invalid Ethernet header")
                    continue

                src_address = "Unknown"
                dst_address = "Unknown"
                tcp_udp = "Unknown"

                if ip_bool:
                    data, tcp_udp, src_address, dst_address = analyse_ip_header(data)
                    if data is None or tcp_udp is None:
                        logging.info(f"Skipping packet {packet_count}: Invalid IP header or filtered out")
                        continue

                    # Apply protocol filter
                    if args.protocol != 'ALL' and not tcp_udp.startswith(args.protocol):
                        logging.info(f"Skipping packet {packet_count}: Protocol {tcp_udp} does not match {args.protocol}")
                        continue

                    if tcp_udp == "TCP":
                        data = analyze_tcp_header(data)
                    elif tcp_udp == "UDP":
                        data = analyse_udp_header(data)
                    else:
                        if not args.summary:
                            color_print(f"__________NON-TCP/UDP PAYLOAD (Protocol {tcp_udp.split('_')[1]})__________", Fore.CYAN)
                            color_print(f"Raw data length: {len(data)} bytes", Fore.YELLOW)

                elif arp_bool:
                    tcp_udp = "ARP"
                    data, sender_ip, target_ip = analyse_arp_header(data)
                    if data is None:
                        logging.info(f"Skipping packet {packet_count}: Invalid ARP header")
                        continue
                    src_address = sender_ip if sender_ip else "ARP"
                    dst_address = target_ip if target_ip else "ARP"
                    src_port = 0
                    dst_port = 0  # Reset ports for ARP

                else:
                    logging.info(f"Skipping packet {packet_count}: Non-IPv4/ARP protocol")
                    continue

                if data is None:
                    logging.info(f"Skipping packet {packet_count}: Invalid transport layer header")
                    continue

                # Log packet summary
                logging.info(f"Packet {packet_count}: {tcp_udp} from {src_address}:{src_port} to {dst_address}:{dst_port}")

                # Display hexdump if requested
                if args.hexdump and data:
                    color_print("__________PAYLOAD HEXDUMP__________", Fore.CYAN)
                    if hexdump_available:
                        hexdump.hexdump(data)
                    else:
                        print(simple_hexdump(data))

                # Check packet count limit
                if args.count and packet_count >= args.count:
                    logging.info(f"Reached packet count limit: {args.count}")
                    color_print(f"Reached packet count limit: {packet_count} packets captured", Fore.RED)
                    break

            except struct.error as e:
                logging.error(f"Packet parsing error: {e}")
                color_print(f"Packet parsing error: {e}", Fore.RED)
                continue

    except PermissionError:
        color_print("Error: This script requires root privileges. Run with sudo.", Fore.RED)
        logging.error("Permission denied: Run with sudo")
        sys.exit(1)
    except OSError as e:
        color_print(f"Error: {str(e)}", Fore.RED)
        logging.error(f"OS error: {str(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Sniffer stopped by user")
        color_print(f"Sniffer stopped. Total packets captured: {packet_count}", Fore.RED)
    except Exception as e:
        color_print(f"Unexpected error: {str(e)}", Fore.RED)
        logging.error(f"Unexpected error: {str(e)}")
        sys.exit(1)
    finally:
        if sniffer_socket:
            sniffer_socket.close()
            logging.info("Socket closed")

if __name__ == "__main__":
    main()
