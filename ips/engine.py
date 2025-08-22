# ips/engine.py

from scapy.all import sniff, IP
import logging
from collections import deque

# --- THIS IS THE FIX ---
# We changed the relative imports (e.g., .state_manager) to absolute imports (e.g., ips.state_manager)
# This tells Python to look for the 'ips' package from the root directory.
from ips.state_manager import StateManager
from ips.prevention import PreventionManager
from ips.detection_rules import DetectionEngine
import config
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

        self.state_manager = StateManager()
        self.prevention_manager = PreventionManager(config.BLOCK_DURATION)
        self.detection_engine = DetectionEngine(self.state_manager, self.prevention_manager, self)

    def _process_packet(self, packet):
        self.packet_count += 1
        self.detection_engine.inspect_packet(packet)

    def start(self):
        """
        Starts the packet sniffing process based on the source provided during initialization.
        """
        try:
            if self.pcap_file:
                logging.info(f"Starting analysis of PCAP file: {self.pcap_file}...")
                sniff(offline=self.pcap_file, prn=self._process_packet, store=False)
            elif self.interface:
                logging.info(f"Starting live capture on interface: {self.interface}...")
                logging.info("Press Ctrl+C to stop.")
                sniff(iface=self.interface, prn=self._process_packet, store=False)
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


#engine logic slightly changed aftr a few refresh issues with the console 