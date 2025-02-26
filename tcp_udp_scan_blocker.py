#!/usr/bin/env python3

import subprocess
import time
import re
from datetime import datetime, timedelta

# Log file to monitor
LOG_FILE = "/var/log/messages"  # Adjust for system: use /var/log/syslog on Debian/Ubuntu
SCAN_PATTERN = re.compile(r"Port Scan Detected.*SRC=([\d\.]+)")

# Timeout for blocking IPs (in minutes)
BLOCK_TIMEOUT = 30  

# Dictionary to track blocked IPs
blocked_ips = {}

def block_ip_firewalld(ip):
    """ Block the IP address using firewalld. """
    if ip not in blocked_ips:
        print(f"Blocking IP: {ip}")
        try:
            # Add IP to firewalld drop zone
            subprocess.run(["firewall-cmd", "--zone=drop", "--add-source", ip, "--permanent"], check=True)
            subprocess.run(["firewall-cmd", "--reload"], check=True)
            blocked_ips[ip] = datetime.now()
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}: {e}")

def unblock_ip_firewalld(ip):
    """ Unblock expired IP addresses. """
    print(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["firewall-cmd", "--zone=drop", "--remove-source", ip, "--permanent"], check=True)
        subprocess.run(["firewall-cmd", "--reload"], check=True)
        del blocked_ips[ip]
    except subprocess.CalledProcessError as e:
        print(f"Failed to unblock IP {ip}: {e}")

def cleanup_expired_blocks():
    """ Remove IPs that exceeded the block timeout. """
    now = datetime.now()
    expired_ips = [ip for ip, block_time in blocked_ips.items() if now - block_time > timedelta(minutes=BLOCK_TIMEOUT)]
    for ip in expired_ips:
        unblock_ip_firewalld(ip)

def detect_service_scan():
    """ Detect aggressive service scans using tcpdump. """
    try:
        print("Monitoring for service scans...")
        process = subprocess.Popen(
            ["tcpdump", "-n", "-c", "100", "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            # Use this instead of 'text=True' for Python 3.6 compatibility
            #universal_newlines=True
            text=True
        )
        for line in process.stdout:
            match = re.search(r"IP ([\d\.]+)", line)
            if match:
                ip = match.group(1)
                print(f"Potential scan detected from {ip}")
                block_ip_firewalld(ip)
    except KeyboardInterrupt:
        print("Stopping scan detection...")

def monitor_logs():
    """ Monitor logs for port scan detections. """
    print("Monitoring logs for suspicious activity...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                cleanup_expired_blocks()
                time.sleep(1)
                continue
            match = SCAN_PATTERN.search(line)
            if match:
                ip = match.group(1)
                block_ip_firewalld(ip)

if __name__ == "__main__":
    try:
        from threading import Thread
        Thread(target=monitor_logs).start()
        detect_service_scan()
    except KeyboardInterrupt:
        print("Exiting...")
