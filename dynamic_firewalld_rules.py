#!/usr/bin/env python3

import subprocess
import time
import re
from datetime import datetime, timedelta

# Log file to monitor
LOG_FILE = "/var/log/syslog"  # Change to /var/log/messages for CentOS/RHEL

# Regular expression to detect suspicious scan logs
SCAN_PATTERN = re.compile(r"Port Scan Detected.*SRC=([\d\.]+)")

# Timeout in minutes for blocking IPs
BLOCK_TIMEOUT = 10  # Adjust this value as needed (default: 60 minutes)

# Dictionary to track blocked IPs and their block timestamps
blocked_ips = {}

def block_ip_firewalld(ip):
    """
    Block the IP address using firewalld.
    """
    if ip not in blocked_ips:
        print(f"Blocking IP: {ip}")
        try:
            # Add the IP to firewalld's drop zone (permanent)
            subprocess.run(["firewall-cmd", "--zone=drop", "--add-source", ip, "--permanent"], check=True)
            # Reload firewalld to apply the rule
            subprocess.run(["firewall-cmd", "--reload"], check=True)
            # Track the time the IP was blocked
            blocked_ips[ip] = datetime.now()
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}: {e}")

def unblock_ip_firewalld(ip):
    """
    Unblock the IP address using firewalld.
    """
    print(f"Unblocking IP: {ip}")
    try:
        # Remove the IP from firewalld's drop zone
        subprocess.run(["firewall-cmd", "--zone=drop", "--remove-source", ip, "--permanent"], check=True)
        # Reload firewalld to apply the rule
        subprocess.run(["firewall-cmd", "--reload"], check=True)
        # Remove the IP from the tracking dictionary
        del blocked_ips[ip]
    except subprocess.CalledProcessError as e:
        print(f"Failed to unblock IP {ip}: {e}")

def cleanup_expired_blocks():
    """
    Unblock IPs that have exceeded the timeout period.
    """
    now = datetime.now()
    expired_ips = [ip for ip, block_time in blocked_ips.items() if now - block_time > timedelta(minutes=BLOCK_TIMEOUT)]
    for ip in expired_ips:
        unblock_ip_firewalld(ip)

def monitor_logs():
    """
    Monitor the log file for port scan detection and block offending IPs.
    """
    print("Monitoring logs for suspicious activity...")
    with open(LOG_FILE, "r") as f:
        # Seek to the end of the log file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                # Periodically clean up expired blocks
                cleanup_expired_blocks()
                time.sleep(1)
                continue
            # Match suspicious scan logs
            match = SCAN_PATTERN.search(line)
            if match:
                ip = match.group(1)
                block_ip_firewalld(ip)

if __name__ == "__main__":
    try:
        monitor_logs()
    except KeyboardInterrupt:
        print("Exiting...")
