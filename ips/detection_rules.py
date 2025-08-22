# ips/detection_rules.py

from scapy.all import IP, ICMP, TCP, Raw
import config
import logging # <-- Added import for real-time logging

class DetectionEngine:
    """
    Contains the logic for detecting various types of malicious traffic.
    """

    def __init__(self, state_manager, prevention_manager, engine_ref):
        self.state_manager = state_manager
        self.prevention_manager = prevention_manager
        self.engine = engine_ref

    def _trigger_alert(self, ip, reason):
        """
        Logs an alert in real-time, saves it for the summary, and blocks the IP.
        """
        if self.prevention_manager.is_blocked(ip):
            return # Do nothing if already blocked

        # 1. Log the alert to the console IN REAL TIME with color
        logging.warning(f"[ALERT] {reason} detected from {ip}.")

        # 2. Save a clean version of the message for the final summary report
        log_message = f"{reason} detected from {ip}."
        self.engine.log_messages.append(log_message)

        # 3. Block the IP and update the counter
        self.prevention_manager.block_ip(ip)
        self.engine.alert_count += 1

    def inspect_packet(self, packet):
        """
        Main inspection function. Calls specific checks based on packet type.
        """
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        
        # Stop processing packets from already-blocked IPs
        if self.prevention_manager.is_blocked(src_ip):
            return

        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            self.check_ping_flood(src_ip)
        elif packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            if flags == 'S':
                self.check_syn_flood(src_ip)

            self.check_port_scan(src_ip, dst_port)
            self.check_stealth_scans(src_ip, flags)
        elif packet.haslayer(Raw):
            self.check_payload(src_ip, packet[Raw].load)

    def check_ping_flood(self, ip):
        self.state_manager.record_icmp_request(ip)
        count = self.state_manager.get_icmp_request_count(ip, config.PING_FLOOD_WINDOW)
        if count > config.PING_FLOOD_THRESHOLD:
            self._trigger_alert(ip, f"ICMP Ping Flood (count: {count})")
            self.state_manager.icmp_requests[ip] = [] # Reset counter after detection

    def check_syn_flood(self, ip):
        self.state_manager.record_syn_request(ip)
        count = self.state_manager.get_syn_request_count(ip, config.SYN_FLOOD_WINDOW)
        if count > config.SYN_FLOOD_THRESHOLD:
            self._trigger_alert(ip, f"TCP SYN Flood (count: {count})")
            self.state_manager.syn_requests[ip] = [] # Reset counter after detection

    def check_port_scan(self, ip, port):
        """Detects simple port scanning behavior."""
        self.state_manager.record_port_scan_attempt(ip, port, config.PORT_SCAN_WINDOW)
        count = self.state_manager.get_port_scan_count(ip)
        if count > config.PORT_SCAN_THRESHOLD:
            self._trigger_alert(ip, f"Port Scan (scanned {count} ports)")
            # Reset the counter to prevent this from firing on every subsequent packet.
            self.state_manager.reset_port_scan_tracker(ip)
            
    def check_stealth_scans(self, ip, flags):
        """Detects NULL, FIN, and XMAS scans."""
        if flags == 0: # NULL Scan
            self._trigger_alert(ip, "NULL Scan")
        elif flags == 'F': # FIN Scan
            self._trigger_alert(ip, "FIN Scan")
        elif flags == 'FPU': # XMAS Scan
            self._trigger_alert(ip, "XMAS Scan")

    def check_payload(self, ip, payload):
        """Inspects packet payload for suspicious strings."""
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore').lower()
            for pattern in config.SUSPICIOUS_PAYLOADS:
                if pattern in decoded_payload:
                    self._trigger_alert(ip, f"Malicious payload (pattern: '{pattern}')")
                    break # Stop after the first match
        except Exception:
            pass