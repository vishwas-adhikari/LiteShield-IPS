# ips/engine.py

from scapy.all import sniff, IP, TCP, ICMP # <-- MODIFIED: Import TCP and ICMP
import logging
from collections import deque
import socket

from ips.state_manager import StateManager
from ips.prevention import PreventionManager
from ips.detection_rules import DetectionEngine
import config

class IPSEngine:
    """
    The main engine for the Intrusion Prevention System.
    """
    def __init__(self, pcap_file=None, interface=None):
        self.pcap_file = pcap_file
        self.interface = interface
        
        self.packet_count = 0
        self.alert_count = 0
        self.log_messages = deque(maxlen=50)
        
        try:
            self.host_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            self.host_ip = "127.0.0.1" 
        logging.info(f"IPS Host IP identified as: {self.host_ip}. This traffic will be ignored.")
        
        self.state_manager = StateManager()
        self.prevention_manager = PreventionManager(config.BLOCK_DURATION)
        self.detection_engine = DetectionEngine(self.state_manager, self.prevention_manager, self, self.host_ip)

    def _process_packet(self, packet):
        # --- NEW: Manual Python-based filter for PCAP mode ---
        # If we are in PCAP mode, we apply the filter here instead of in the sniff command.
        if self.pcap_file and not (packet.haslayer(TCP) or packet.haslayer(ICMP)):
            return
        # --------------------------------------------------------
            
        self.packet_count += 1
        self.detection_engine.inspect_packet(packet)

    def start(self):
        """
        Starts the packet sniffing process based on the source provided during initialization.
        """
        bpf_filter = "icmp or tcp"
        
        try:
            if self.pcap_file:
                logging.info(f"Starting analysis of PCAP file: {self.pcap_file}...")
                # --- MODIFIED: Removed the 'filter' argument to avoid using tcpdump ---
                sniff(offline=self.pcap_file, prn=self._process_packet, store=False)
            elif self.interface:
                logging.info(f"Starting live capture on interface: {self.interface}...")
                logging.info("Press Ctrl+C to stop.")
                sniff(iface=self.interface, prn=self._process_packet, store=False, filter=bpf_filter)
            else:
                logging.error("No packet source specified. Please provide a PCAP file (-r) or an interface (-i), or set one in config.py.")
                return
        except (KeyboardInterrupt, Exception) as e:
            if isinstance(e, KeyboardInterrupt):
                print("\nShutdown signal received.")
            else:
                logging.error(f"An error occurred during sniffing: {e}")
        finally:
            # This summary block runs when sniffing is complete or interrupted
            print("\n" + "="*50)
            print("         LiteShield IPS Session Summary")
            print("="*50)
            print(f"Total Packets Processed: {self.packet_count}")
            print(f"Total Alerts Triggered:  {self.alert_count}")
            print("-"*50)
            print("Alerts Logged During Session:")
            if not self.log_messages:
                print("   (None)")
            else:
                unique_alerts = sorted(list(set(self.log_messages)))
                for msg in unique_alerts:
                    print(f"   - {msg}")
            
            print("\nIPs that were blocked during the session:")
            blocked_ips = self.prevention_manager.blocklist.keys()
            if not blocked_ips:
                print("   (None)")
            else:
                for ip in blocked_ips:
                    print(f"   - {ip}")
            print("="*50)

        logging.info("LiteShield IPS has stopped.")