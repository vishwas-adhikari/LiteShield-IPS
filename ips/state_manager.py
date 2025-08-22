# ips/state_manager.py

import time

class StateManager:
    """Manages the state of network traffic for pattern detection."""

    def __init__(self):
        # Stores timestamps of ICMP echo requests per source IP
        # Format: {'ip_address': [timestamp1, timestamp2, ...]}
        self.icmp_requests = {}

        # Stores timestamps of TCP SYN packets per source IP
        # Format: {'ip_address': [timestamp1, timestamp2, ...]}
        self.syn_requests = {}

        # Stores destination ports contacted by a source IP
        # Format: {'ip_address': {'ports': {port1, port2}, 'start_time': timestamp}}
        self.port_scan_tracker = {}

    def _cleanup_timestamps(self, records, window):
        """Removes timestamps that are older than the given time window."""
        current_time = time.time()
        for ip in list(records.keys()):
            records[ip] = [ts for ts in records[ip] if current_time - ts < window]
            if not records[ip]:
                del records[ip]
        return records

    # --- ICMP Flood Tracking ---
    def record_icmp_request(self, ip):
        """Records an ICMP echo request from a given IP."""
        if ip not in self.icmp_requests:
            self.icmp_requests[ip] = []
        self.icmp_requests[ip].append(time.time())

    def get_icmp_request_count(self, ip, window):
        """Gets the number of ICMP requests from an IP in the last 'window' seconds."""
        self.icmp_requests = self._cleanup_timestamps(self.icmp_requests, window)
        return len(self.icmp_requests.get(ip, []))

    # --- TCP SYN Flood Tracking ---
    def record_syn_request(self, ip):
        """Records a TCP SYN packet from a given IP."""
        if ip not in self.syn_requests:
            self.syn_requests[ip] = []
        self.syn_requests[ip].append(time.time())

    def get_syn_request_count(self, ip, window):
        """Gets the number of TCP SYN packets from an IP in the last 'window' seconds."""
        self.syn_requests = self._cleanup_timestamps(self.syn_requests, window)
        return len(self.syn_requests.get(ip, []))

    # --- Port Scan Tracking ---
    def record_port_scan_attempt(self, ip, port, window):
        """Records a connection attempt to a port from a given IP."""
        current_time = time.time()
        
        if ip not in self.port_scan_tracker:
            self.port_scan_tracker[ip] = {'ports': set(), 'start_time': current_time}

        # Reset if the last attempt was outside the current window
        if current_time - self.port_scan_tracker[ip]['start_time'] > window:
            self.port_scan_tracker[ip] = {'ports': {port}, 'start_time': current_time}
        else:
            self.port_scan_tracker[ip]['ports'].add(port)

    def get_port_scan_count(self, ip):
        """Gets the number of unique ports scanned by an IP."""
        return len(self.port_scan_tracker.get(ip, {}).get('ports', set()))
    
    def reset_port_scan_tracker(self, ip):
        """Resets the port scan tracking for a specific IP after detection."""
        if ip in self.port_scan_tracker:
            del self.port_scan_tracker[ip]