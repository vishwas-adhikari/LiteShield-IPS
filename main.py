# main.py

import argparse
import config
from ips.engine import IPSEngine
from ips.logger import setup_logger

def main():
    """
    Parses command-line arguments and runs the IPS.
    """
    setup_logger()
    
    parser = argparse.ArgumentParser(
        description="LiteShield IPS - A lightweight Intrusion Prevention System.",
        formatter_class=argparse.RawTextHelpFormatter # For better help text formatting
    )
    
    # Use a mutually exclusive group so the user can only choose one mode at a time
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-r', '--read-pcap', dest='pcap_file',
                       help="Path to a PCAP file to read for offline analysis.")
    group.add_argument('-i', '--interface', dest='interface',
                       help="Network interface name for live packet capture (e.g., 'eth0').")

    args = parser.parse_args()

    pcap_to_read = args.pcap_file
    interface_to_sniff = args.interface

    # --- Fallback Logic ---
    # If no command-line arguments are given, use the settings from config.py
    if not pcap_to_read and not interface_to_sniff:
        pcap_to_read = config.PCAP_FILE
        # Only use the interface from config if no PCAP is specified in config
        if not pcap_to_read:
            interface_to_sniff = config.NETWORK_INTERFACE

    try:
        # Pass the determined source (from command line or config) to the engine
        engine = IPSEngine(pcap_file=pcap_to_read, interface=interface_to_sniff)
        engine.start()
    except PermissionError:
        print("\n[ERROR] Permission denied. Please run this script with root/administrator privileges.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()