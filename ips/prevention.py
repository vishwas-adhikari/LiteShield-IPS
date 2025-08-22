# ips/prevention.py

import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PreventionManager:
    """Manages the blocklist for malicious IP addresses."""

    def __init__(self, block_duration):
        # The blocklist stores the IP and the timestamp when it should be unblocked.
        # Format: {'ip_address': unblock_timestamp}
        self.blocklist = {}
        self.block_duration = block_duration

    def _cleanup_blocklist(self):
        """Removes IPs from the blocklist whose block duration has expired."""
        current_time = time.time()
        # Use list() to create a copy of keys for safe iteration while deleting
        for ip in list(self.blocklist.keys()):
            if current_time > self.blocklist[ip]:
                del self.blocklist[ip]
                logging.info(f"IP UNBLOCKED: {ip} has been removed from the blocklist.")

    def block_ip(self, ip):
        """Adds an IP address to the blocklist."""
        if ip not in self.blocklist:
            unblock_time = time.time() + self.block_duration
            self.blocklist[ip] = unblock_time
            logging.warning(f"IP BLOCKED: {ip} blocked for {self.block_duration} seconds.")
        else:
            # If already blocked, extend the block duration
            unblock_time = time.time() + self.block_duration
            self.blocklist[ip] = unblock_time
            logging.warning(f"IP BLOCK EXTENDED: {ip}'s block extended for {self.block_duration} seconds.")


    def is_blocked(self, ip):
        """Checks if an IP is currently on the blocklist."""
        # Clean up expired entries before checking
        self._cleanup_blocklist()
        return ip in self.blocklist