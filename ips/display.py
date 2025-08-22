# ips/display.py

import os
import time
import threading

class Dashboard:
    """Manages the live terminal dashboard display."""

    def __init__(self, prevention_manager, engine_ref,log_queue):
        self.prevention_manager = prevention_manager
        self.engine = engine_ref
        self.logs = log_queue 
        self.stop_event = threading.Event()

    def _clear_screen(self):
        """Clears the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def _display_header(self):
        print("🛡️  LiteShield IPS - Live Monitor 🛡️")
        print("="*40)

    def _display_stats(self):
        print(f"Packets Processed: {self.engine.packet_count}")
        print(f"Alerts Triggered: {self.engine.alert_count}")
        print("-"*40)

    def _display_blocklist(self):
        print("🔴 Blocked IPs:")
        blocklist = self.prevention_manager.blocklist
        if not blocklist:
            print("   (None)")
        else:
            current_time = time.time()
            for ip, expiry_time in list(blocklist.items()):
                time_left = expiry_time - current_time
                if time_left > 0:
                    print(f"   - {ip:<15} (Unblocked in {int(time_left)}s)")
        print("="*40)
        print("Real-time logs will appear below:")

    def _display_logs(self): # <-- ADD THIS NEW METHOD
        """Displays recent log messages."""
        print("Recent Alerts:")
        if not self.logs:
            print("   (None)")
        else:
            for msg in self.logs:
                # Add color codes here for impressive display!
                print(f"   \x1b[33;20m-> {msg}\x1b[0m") # Yellow text
        print("="*40)


    def run(self):
        """The main loop for the dashboard thread."""
        while not self.stop_event.is_set():
            self._clear_screen()
            self._display_header()
            self._display_stats()
            self._display_blocklist()
            self._display_logs()
            time.sleep(1) # Refresh every second

    def stop(self):
        self.stop_event.set()