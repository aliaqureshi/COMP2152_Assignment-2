"""
Author: Alia Qureshi
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# dictionary storing common network ports and their services
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using property decorators allows controlled access to private attributes.
    # Instead of accessing self.__target directly, the getter and setter allow
    # validation logic to be added when values are read or modified. This helps
    # protect the data and prevents invalid values like empty strings.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# The PortScanner class inherits from the NetworkTool parent class.
# This allows PortScanner to reuse the target property and validation logic
# without rewriting it. For example, the constructor calls super().__init__(target)
# which initializes the target variable defined in the parent class.
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):

        # Q4: What would happen without try-except here?
        # Without try-except, the program could crash if a network error occurs
        # while attempting to connect to a port. For example, if the target
        # machine is unreachable or the socket fails, Python would raise an
        # exception and terminate the program instead of continuing the scan.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            with self.lock:
                self.scan_results.append((port, status, service_name))

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows multiple ports to be scanned at the same time instead
    # of sequentially. If we scanned 1024 ports one by one, the process would
    # be extremely slow because each connection attempt waits for a timeout.
    # Using threads allows the scanner to perform many checks concurrently.
    def scan_range(self, start_port, end_port):

        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def save_results(target, results):

    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print("Database error:", e)


def load_past_scans():

    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")

        conn.close()

    except:
        print("No past scans found.")


if __name__ == "__main__":

    try:

        target = input("Enter target IP (default 127.0.0.1): ")

        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024")
            exit()

        scanner = PortScanner(target)

        print(f"Scanning {target} from port {start_port} to {end_port}...")

        scanner.scan_range(start_port, end_port)

        open_ports = scanner.get_open_ports()

        print(f"\n--- Scan Results for {target} ---")

        for port, status, service in open_ports:
            print(f"Port {port}: {status} ({service})")

        print("Total open ports found:", len(open_ports))

        save_results(target, scanner.scan_results)

        view = input("Would you like to see past scan history? (yes/no): ")

        if view.lower() == "yes":
            load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")


# Q5: New Feature Proposal
# One feature I would add is the ability to export scan results to a CSV file.
# This would allow users to easily analyze scan data using spreadsheet tools.
# A list comprehension could be used to quickly format the results list into
# rows before writing them to the CSV file.
# Diagram: See diagram_101535665D.png in the repository roott
