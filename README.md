# DFR
Dynamic FirewallD Rules

The purpose of this python script is to block incoming TCP/UDP scans from tools like nmap, rustscan, etc. It creates dynamic firewalld rules to block and deny IP addresses that

**Requirements:**
Python 3.10+ installed.
Firewalld installed.

**INSTALLATION**

1. Clone the code to a directory of your liking.
2. Create a systemd service so it can run and protect your system constanly:
sudo nano /etc/system/systemd/dynamic_firewalld_rules.service
Example service unit file:
[Unit]
Description=Dynamic Firewall Rules for TCP/UDP Scans
After=network.target
[Service]
ExecStart=/usr/bin/python3 /path/to/dynamic_firewalld_rules.py
Restart=always
User=root
[Install]
WantedBy=multi-user.target
3. Enable the service:
sudo systemctl enable dynamic_firewalld_rules.service
4. Start the service:
sudo systemctl start dynamic_firewalld_rules.service
5. Enjoy! :)
