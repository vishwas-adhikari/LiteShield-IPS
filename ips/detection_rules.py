# ips/detection_rules.py

from scapy.all import IP, ICMP, TCP, Raw
import config
import logging

class DetectionEngine:
    """
    Contains the logic for detecting various types of malicious traffic.
    """
    # --- MODIFIED: Accept host_ip in the constructor ---
    def __init__(self, state_manager, prevention_manager, engine_ref, host_ip):
        self.state_manager = state_manager
        self.prevention_manager = prevention_manager
        self.engine = engine_ref
        self.host_ip = host_ip # <-- NEW: Store the host's IP

    def _trigger_alert(self, ip, reason):
        """
        Logs an alert in real-time, saves it for the summary, and blocks the IP.
        """
        if self.prevention_manager.is_blocked(ip):
            return

        logging.warning(f"[ALERT] {reason} detected from {ip}.")
        log_message = f"{reason} detected from {ip}."
        self.engine.log_messages.append(log_message)
        self.prevention_manager.block_ip(ip)
        self.engine.alert_count += 1

    def inspect_packet(self, packet):
        """
        Main inspection function. Calls specific checks based on packet type.
        """
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        
        # --- NEW: Ignore traffic from our own machine ---
        if src_ip == self.host_ip:
            return
        # -------------------------------------------------
        
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

    # --- NO CHANGES TO ANY OF THE check_... METHODS BELOW ---
    def check_ping_flood(self, ip):
        self.state_manager.record_icmp_request(ip)
        count = self.state_manager.get_icmp_request_count(ip, config.PING_FLOOD_WINDOW)
        if count > config.PING_FLOOD_THRESHOLD:
            self._trigger_alert(ip, f"ICMP Ping Flood (count: {count})")
            self.state_manager.icmp_requests[ip] = []

    def check_syn_flood(self, ip):
        self.state_manager.record_syn_request(ip)
        count = self.state_manager.get_syn_request_count(ip, config.SYN_FLOOD_WINDOW)
        if count > config.SYN_FLOOD_THRESHOLD:
            self._trigger_alert(ip, f"TCP SYN Flood (count: {count})")
            self.state_manager.syn_requests[ip] = []

    def check_port_scan(self, ip, port):
        self.state_manager.record_port_scan_attempt(ip, port, config.PORT_SCAN_WINDOW)
        count = self.state_manager.get_port_scan_count(ip)
        if count > config.PORT_SCAN_THRESHOLD:
            self._trigger_alert(ip, f"Port Scan (scanned {count} ports)")
            self.state_manager.reset_port_scan_tracker(ip)
            
    def check_stealth_scans(self, ip, flags):
        if flags == 0:
            self._trigger_alert(ip, "NULL Scan")
        elif flags == 'F':
            self._trigger_alert(ip, "FIN Scan")
        elif flags == 'FPU':
            self._trigger_alert(ip, "XMAS Scan")

    def check_payload(self, ip, payload):
        try:
            decoded_payload = payload.decode('utf-8', errors='ignore').lower()
            for pattern in config.SUSPICIOUS_PAYLOADS:
                if pattern in decoded_payload:
                    self._trigger_alert(ip, f"Malicious payload (pattern: '{pattern}')")
                    break
        except Exception:
            pass