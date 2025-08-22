# config.py

# --- Detection Rule Thresholds ---

# ICMP Ping Flood Detection
# Block an IP if it sends more than PING_FLOOD_THRESHOLD packets in PING_FLOOD_WINDOW seconds.
PING_FLOOD_THRESHOLD = 100
PING_FLOOD_WINDOW = 1.0  # in seconds

# TCP SYN Flood Detection
# Block an IP if it sends more than SYN_FLOOD_THRESHOLD SYN packets in SYN_FLOOD_WINDOW seconds.
SYN_FLOOD_THRESHOLD = 50
SYN_FLOOD_WINDOW = 1.0  # in seconds

# Port Scan Detection
# Block an IP if it attempts to connect to more than PORT_SCAN_THRESHOLD unique ports in PORT_SCAN_WINDOW seconds.
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 5.0  # in seconds

# --- Prevention Settings ---

# How long (in seconds) an IP should be blocked after being detected.
BLOCK_DURATION = 300  # 5 minutes

# --- Payload Inspection ---

# A list of simple string patterns to detect in packet payloads.
# These are case-insensitive.
SUSPICIOUS_PAYLOADS = [
    # SQL Injection
    "union select",
    "' or 1=1",
    "drop table",
    
    # Command Injection / Directory Traversal
    "../etc/passwd",
    "/bin/bash",
    
    # Cross-Site Scripting (XSS)
    "<script>",
    "alert('xss')",
]

# --- General Settings ---

# Set to a file path to read from a PCAP file instead of a live interface.
# Example: 'tests/pcap_samples/malicious_traffic.pcap'
PCAP_FILE = None 

# Network interface to sniff on if not reading from a PCAP file.
# Use the command 'scapy.get_if_list()' in a Python shell to see available interfaces.
NETWORK_INTERFACE = "eth0"

# Network interface to sniff on if not reading from a PCAP file.
# On Windows, find this name using scapy.get_if_list()
NETWORK_INTERFACE = "Loopback Pseudo-Interface 1" # <-- PASTE YOUR EXACT INTERFACE NAME HERE