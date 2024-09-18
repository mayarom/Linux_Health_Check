#!/bin/bash

# Get the server's IP address (assuming eth0 as the network interface)
server_ip=$(hostname -I | awk '{print $1}')

# Create a text file on the Desktop with the IP address in the filename
output_file="$HOME/Desktop/SEND_TO_MAYA_$server_ip.txt"

# Define a function to print a section title
print_section_title() {
    echo "===================================" >> $output_file
    echo "   $1" >> $output_file
    echo "===================================" >> $output_file
}

# Define a function to print a subsection title
print_subsection_title() {
    echo -e "\n--- $1 ---\n" >> $output_file
}

# Start of the report
print_section_title "Server Information Report"

echo "Date: $(date)" >> $output_file
echo "Hostname: $(hostname)" >> $output_file
echo "Server IP: $server_ip" >> $output_file
echo -e "\n" >> $output_file

# Operating System Version
print_section_title "Operating System Version"
lsb_release -a >> $output_file 2>&1
uname -r >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# System Updates Information
print_section_title "System Updates"
print_subsection_title "Last Update Date"
sudo grep "upgrade" /var/log/dpkg.log | tail -n 1 >> $output_file
print_subsection_title "List of Installed Updates"
sudo apt list --installed >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Password Policies
print_section_title "Password Policies"
print_subsection_title "Password Policy (PAM)"
grep -E '^password\s+requisite\s+pam_pwquality\.so' /etc/pam.d/common-password >> $output_file 2>&1
print_subsection_title "Maximum Password Age (PASS_MAX_DAYS)"
grep '^PASS_MAX_DAYS' /etc/login.defs >> $output_file 2>&1
print_subsection_title "Minimum Password Age (PASS_MIN_DAYS)"
grep '^PASS_MIN_DAYS' /etc/login.defs >> $output_file 2>&1
print_subsection_title "Password Expiration Warning Period (PASS_WARN_AGE)"
grep '^PASS_WARN_AGE' /etc/login.defs >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# User Groups and Users
print_section_title "User Groups and Users"
print_subsection_title "Admin Users"
getent passwd | awk -F: '$3 == 0 { print $1 }' >> $output_file 2>&1
print_subsection_title "All User Groups and Members"
getent group >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Server Management Settings
print_section_title "Server Management Settings"
print_subsection_title "SSH Configuration"
grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config >> $output_file 2>&1
print_subsection_title "UFW Status"
sudo ufw status >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Monitoring Settings
print_section_title "Monitoring Settings"
print_subsection_title "Fail2Ban Status"
sudo systemctl status fail2ban >> $output_file 2>&1
print_subsection_title "Cron Jobs"
sudo crontab -l >> $output_file 2>&1
print_subsection_title "Syslog Configuration"
grep -E '^*.*' /etc/rsyslog.conf >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Installed Software
print_section_title "Installed Software"
dpkg-query -l >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Additional Security Checks
print_section_title "Additional Security Checks"
print_subsection_title "Active Services"
systemctl list-units --type=service --state=running >> $output_file 2>&1
print_subsection_title "Active Network Connections"
netstat -tuln >> $output_file 2>&1
print_subsection_title "Sudoers Configuration"
sudo cat /etc/sudoers | grep -v '^#' >> $output_file 2>&1
print_subsection_title "Vulnerable Packages Check"
sudo apt-get -s upgrade | grep "^Inst" | grep -i securi >> $output_file 2>&1

# Collect iptables rules
print_section_title "Firewall and Networking"
print_subsection_title "iptables Rules"
sudo iptables -L -v -n >> $output_file 2>&1

# Check system audit policies (auditd)
print_subsection_title "Auditd Service Status"
sudo systemctl status auditd >> $output_file 2>&1

# Check for unattended upgrades
print_subsection_title "Unattended Upgrades Status"
sudo systemctl status unattended-upgrades >> $output_file 2>&1

# Check system logs for recent auth failures
print_subsection_title "Recent Authentication Failures (Last 10)"
sudo journalctl -u ssh --since "7 days ago" | grep "Failed password" | tail -n 10 >> $output_file 2>&1

# Kernel Parameters for Security
print_section_title "Kernel Parameters for Security"
sysctl net.ipv4.conf.all.rp_filter >> $output_file 2>&1
sysctl net.ipv4.conf.default.rp_filter >> $output_file 2>&1
sysctl net.ipv4.conf.all.accept_source_route >> $output_file 2>&1
sysctl net.ipv4.conf.default.accept_source_route >> $output_file 2>&1
sysctl net.ipv4.icmp_echo_ignore_broadcasts >> $output_file 2>&1
sysctl net.ipv4.conf.all.log_martians >> $output_file 2>&1
sysctl net.ipv4.conf.default.log_martians >> $output_file 2>&1

# Check for services running as root
print_subsection_title "Services Running as Root"
ps aux | grep root >> $output_file 2>&1

# Check file permissions for sensitive files
print_subsection_title "Sensitive File Permissions"
ls -l /etc/passwd /etc/shadow /etc/gshadow /etc/group >> $output_file 2>&1

# Check if passwordless sudo is allowed
print_subsection_title "Passwordless Sudo Check"
grep -E '^%sudo\s+ALL=\(ALL:ALL\)\s+NOPASSWD:ALL' /etc/sudoers >> $output_file 2>&1

# Check for open ports using netstat
print_subsection_title "Open Ports"
sudo netstat -tulnp >> $output_file 2>&1

# End of report
echo -e "\nInformation collection completed. Check the file at $output_file" >> $output_file
