import csv
import subprocess
import os

# Function to run shell commands and return output
def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

# Compliance check for cramfs kernel module
def check_cramfs_module():
    command = "lsmod | grep cramfs"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for freevxfs kernel module
def check_freevxfs_module():
    command = "lsmod | grep freevxfs"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for hfs kernel module
def check_hfs_module():
    command = "lsmod | grep hfs"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for hfsplus kernel module
def check_hfsplus_module():
    command = "lsmod | grep hfsplus"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for jffs2 kernel module
def check_jffs2_module():
    command = "lsmod | grep jffs2"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for /tmp being a separate partition
def check_tmp_partition():
    command = "grep '/tmp' /etc/fstab"
    output = run_command(command)
    return "Non-Compliant" if not output else "Compliant"

# Compliance check for nodev option on /tmp partition
def check_tmp_nodev():
    command = "findmnt -kn /tmp | grep -v nodev"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nosuid option on /tmp partition
def check_tmp_nosuid():
    command = "findmnt -kn /tmp | grep -v nosuid"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for noexec option on /tmp partition
def check_tmp_noexec():
    command = "findmnt -kn /tmp | grep -v noexec"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for /dev/shm being a separate partition with expected options
def check_dev_shm_partition():
    command = "findmnt -kn /dev/shm"
    output = run_command(command)
    expected_output = "/dev/shm tmpfs tmpfs rw,nosuid,nodev,noexec,relatime,seclabel"
    return "Compliant" if output == expected_output else "Non-Compliant"

# Compliance check for nodev option on /dev/shm partition
def check_dev_shm_nodev():
    command = "findmnt -kn /dev/shm | grep -v nodev"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nosuid option on /dev/shm partition
def check_dev_shm_nosuid():
    command = "findmnt -kn /dev/shm | grep -v 'nosuid'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for noexec option on /dev/shm partition
def check_dev_shm_noexec():
    command = "findmnt -kn /dev/shm | grep -v 'noexec'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nodev option on /home partition
def check_home_nodev():
    command = "findmnt -nk /home | grep -v 'nodev'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nosuid option on /home partition
def check_home_nosuid():
    command = "findmnt -nk /home | grep -v 'nosuid'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nodev option on /var partition
def check_var_nodev():
    command = "findmnt -nk /var | grep -v 'nodev'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nosuid option on /var partition
def check_var_nosuid():
    command = "findmnt -nk /var | grep -v 'nosuid'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nodev option on /var/tmp partition
def check_var_tmp_nodev():
    command = "findmnt -nk /var/tmp | grep -v 'nodev'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nosuid option on /var/tmp partition
def check_var_tmp_nosuid():
    command = "findmnt -nk /var/tmp | grep -v 'nosuid'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for noexec option on /var/tmp partition
def check_var_tmp_noexec():
    command = "findmnt -nk /var/tmp | grep -v 'noexec'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nodev option on /var/log partition
def check_var_log_nodev():
    command = "findmnt -nk /var/log | grep -v 'nodev'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nosuid option on /var/log partition
def check_var_log_nosuid():
    command = "findmnt -nk /var/log | grep -v 'nosuid'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for noexec option on /var/log partition
def check_var_log_noexec():
    command = "findmnt -nk /var/log | grep -v 'noexec'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nodev option on /var/log/audit partition
def check_var_log_audit_nodev():
    command = "findmnt -nk /var/log/audit | grep -v 'nodev'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for nosuid option on /tmp partition
def check_tmp_nosuid():
    command = "findmnt -nk /tmp | grep -v 'nosuid'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for noexec option on /tmp partition
def check_tmp_noexec():
    command = "findmnt -nk /tmp | grep -v 'noexec'"
    output = run_command(command)
    return "Compliant" if not output else "Non-Compliant"

# Compliance check for /dev/shm partition being separate with partial match
def check_dev_shm_separate():
    command = "findmnt -kn /dev/shm"
    output = run_command(command)
    # Key components that should be present in the output
    expected_keywords = [
        "/dev/shm",
        "tmpfs",
        "rw",
        "nosuid",
        "nodev",
        "noexec",
        "relatime",
        "seclabel"
    ]
    
    # Check if all key components are present in the output (partial match)
    if all(keyword in output for keyword in expected_keywords):
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for GPG keys configuration (Manual)
def check_gpg_keys():
    return "Manual Check Needed"

# Compliance check for gpgcheck globally activated
def check_gpgcheck():
    command = "grep ^gpgcheck /etc/dnf/dnf.conf"
    output = run_command(command)
    return "Compliant" if output.strip() == "gpgcheck=1" else "Non-Compliant"

# Compliance check for GDM login banner configuration
def check_gdm_banner():
    command = rf"grep -E 'banner-message-enable|banner-message-text' /etc/dconf/db/gdm.d/01-banner-message"
    output = run_command(command)
    return "Compliant" if "banner-message-enable=true" in output else "Non-Compliant"

# Compliance check for GDM disable-user-list option
def check_gdm_disable_user_list():
    command = rf"grep -Piq '^\h*disable-user-list\h*=\h*true\b' /etc/dconf/db/*/* && echo 'Compliant' || echo 'Non-Compliant'"
    output = run_command(command)
    return "Compliant" if "Compliant" in output else "Non-Compliant"

# Compliance check for GDM screen lock when the user is idle
def check_gdm_screen_lock():
    command = rf"grep -Piq '^\h*idle-delay\h*=\h*uint32\s*(900)\b' /etc/dconf/db/*/* && grep -Piq '^\h*lock-delay\h*=\h*uint32\s*(5)\b' /etc/dconf/db/*/* && echo 'Compliant' || echo 'Non-Compliant'"
    output = run_command(command)
    return "Compliant" if "Compliant" in output else "Non-Compliant"

# Compliance check for GDM screen locks cannot be overridden
def check_gdm_screen_lock_override():
    command = "grep -rE '/org/gnome/desktop/session/idle-delay|/org/gnome/desktop/screensaver/lock-delay' /etc/dconf/db/*/locks/* || echo 'Non-Comp'"
    output = run_command(command)
    return "Non-Compliant" if "Non-Comp" in output else "Compliant"

# Compliance check for GDM autorun-never not overridden
def check_gdm_autorun_never():
    command = "grep -H '/org/gnome/desktop/media-handling/autorun-never' /etc/dconf/db/*/locks/* | wc -l"
    output = run_command(command)
    return "Compliant" if int(output) > 0 else "Non-Compliant"

# Compliance check for XDMCP not being enabled
def check_xdmcp_enabled():
    command = "grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm/custom.conf && echo 'XDMCP is enabled' || echo 'XDMCP is not enabled'"
    output = run_command(command)
    return "Non-Compliant" if "XDMCP is not enabled" in output else "Compliant"

# Compliance check for time synchronization (chrony)
def check_time_sync():
    command = "rpm -q chrony || echo 'chrony is not installed'"
    output = run_command(command)
    return "Non-Compliant" if "chrony is not installed" in output else "Compliant"

# Compliance check for chrony configuration
def check_chrony_config():
    command = "grep -P '^pool\s+2.rhel.pool.ntp.org' /etc/chrony.conf || echo 'Remote server not configured properly'"
    output = run_command(command)
    return "Non-Compliant" if "Remote server not configured properly" in output else "Compliant"

# Compliance check for chrony running as root user
def check_chrony_root_user():
    command = 'grep -Psi -- "^\h*OPTIONS="?+-u\h+root\b" /etc/sysconfig/chronyd || echo "Chrony is not running as root"'
    output = run_command(command)
    return "Non-Compliant" if "Chrony is not running as root" in output else "Compliant"

# Compliance check for dhcp-server package installation
def check_dhcp_server_installed():
    command = "rpm -q dhcp-server"
    output = run_command(command)
    return "Non-Compliant" if "package dhcp-server is not installed" in output else "Compliant"

# Compliance check for bind package installation
def check_bind_installed():
    command = "rpm -q bind"
    output = run_command(command)
    return "Compliant" if "package bind is not installed" in output else "Non-Compliant"

# Compliance check for dhcp-server package installation
def check_dhcp_server_installed():
    command = "rpm -q dhcp-server"
    output = run_command(command)
    return "Compliant" if "package dhcp-server is not installed" in output else "Non-Compliant"

# Compliance check for dnsmasq package installation
def check_dnsmasq_installed():
    command = "rpm -q dnsmasq"
    output = run_command(command)
    return "Compliant" if "package dnsmasq is not installed" in output else "Non-Compliant"

# Compliance check for samba package installation
def check_samba_installed():
    command = "rpm -q samba"
    output = run_command(command)
    return "Compliant" if "package samba is not installed" in output else "Non-Compliant"

# Compliance check for vsftpd package installation
def check_vsftpd_installed():
    command = "rpm -q vsftpd"
    output = run_command(command)
    return "Compliant" if "package vsftpd is not installed" in output else "Non-Compliant"

# Compliance check for dovecot and cyrus-imapd packages installation
def check_message_access_server_services():
    command = "rpm -q dovecot cyrus-imapd"
    output = run_command(command)
    return "Compliant" if "package dovecot is not installed" in output and "package cyrus-imapd is not installed" in output else "Non-Compliant"

# Compliance check for nfs-utils package installation
def check_nfs_utils():
    command = "rpm -q nfs-utils"
    output = run_command(command)
    return "Compliant" if "package nfs-utils is not installed" in output else "Non-Compliant"

# Compliance check for ypserv package installation
def check_ypserv():
    command = "rpm -q ypserv"
    output = run_command(command)
    return "Compliant" if "package ypserv is not installed" in output else "Non-Compliant"

# Compliance check for IPv4 and IPv6 forwarding status
def check_ip_forwarding():
    command = "./scripts/52.sh"
    output = run_command(command)
    if "IPv4 forwarding is correctly disabled." in output and "IPv6 forwarding is correctly disabled." in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for ICMP redirect sending status
def check_packet_redirect():
    command = "./scripts/53.sh"
    output = run_command(command)
    if "ICMP redirect sending for 'all' is correctly disabled." in output and "ICMP redirect sending for 'default' is correctly disabled." in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for bogus ICMP responses
def check_bogus_icmp():
    command = "./scripts/54.sh"
    output = run_command(command)
    if "Bogus ICMP error responses are correctly ignored." in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for broadcast ICMP requests
def check_broadcast_icmp():
    command = "./scripts/55.sh"
    output = run_command(command)
    if "Broadcast ICMP requests are correctly ignored." in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for ICMP redirects
def check_icmp_redirects():
    command = "./scripts/56.sh"
    output = run_command(command)
    if "IPv4 ICMP redirects are not accepted." in output and "IPv6 ICMP redirects are not accepted." in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for secure ICMP redirects
def check_secure_icmp_redirects():
    command = "./scripts/57.sh"
    output = run_command(command)
    if "Secure IPv4 ICMP redirects are not accepted." in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for reverse path filtering
def check_reverse_path_filtering():
    command = "sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter"
    output = run_command(command)
    if "net.ipv4.conf.all.rp_filter = 1" in output and "net.ipv4.conf.default.rp_filter = 1" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for source routed packets
def check_source_routed_packets():
    command = "sysctl net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route"
    output = run_command(command)
    if "net.ipv4.conf.all.accept_source_route = 0" in output and "net.ipv4.conf.default.accept_source_route = 0" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for suspicious packets logging
def check_suspicious_packets_logging():
    command = "sysctl net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians"
    output = run_command(command)
    if "net.ipv4.conf.all.log_martians = 1" in output and "net.ipv4.conf.default.log_martians = 1" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for tcp syn cookies
def check_tcp_syn_cookies():
    command = "sysctl net.ipv4.tcp_syncookies"
    output = run_command(command)
    if "net.ipv4.tcp_syncookies = 1" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for ipv6 router advertisements
def check_ipv6_router_advertisements():
    command = "sysctl net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra"
    output = run_command(command)
    if "net.ipv6.conf.all.accept_ra = 0" in output and "net.ipv6.conf.default.accept_ra = 0" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for nftables installation
def check_nftables_installed():
    command = "rpm -q nftables"
    output = run_command(command)
    if "nftables-" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for cron daemon being enabled and active
def check_cron_enabled_active():
    command_enabled = "systemctl is-enabled crond"
    command_active = "systemctl is-active crond"
    
    output_enabled = run_command(command_enabled)
    output_active = run_command(command_active)
    
    if "enabled" in output_enabled and "active" in output_active:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/ssh/sshd_config
def check_sshd_config_permissions():
    command = "./scripts/65.sh"
    
    output = run_command(command)
    
    if "PASS" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/crontab
def check_crontab_permissions():
    command = "stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/crontab"
    
    output = run_command(command)
    
    if "Access: (600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/cron.hourly
def check_cron_hourly_permissions():
    command = "stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.hourly/"
    
    output = run_command(command)
    
    if "Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/cron.daily
def check_cron_daily_permissions():
    command = "stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.daily/"
    
    output = run_command(command)
    
    if "Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/cron.weekly
def check_cron_weekly_permissions():
    command = "stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.weekly/"
    
    output = run_command(command)
    
    if "Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/cron.monthly
def check_cron_monthly_permissions():
    command = "stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.monthly/"
    
    output = run_command(command)
    
    if "Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/cron.d
def check_cron_d_permissions():
    command = "stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.d/"
    
    output = run_command(command)
    
    if "Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for permissions on /etc/cron.deny
def check_cron_deny_permissions():
    command = '[ -e "/etc/cron.deny" ] && stat -Lc "Access: (%a/%A) Owner: (%U) Group: (%G)" /etc/cron.deny'
    
    output = run_command(command)
    
    if "Access: (640/-rw-r-----) Owner: (root) Group: (root)" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for /etc/at.allow and /etc/at.deny permissions
def check_at_permissions():
    # Check permissions for /etc/at.allow
    command_allow = 'stat -Lc "Access: (%a/%A) Owner: (%U) Group: (%G)" /etc/at.allow'
    output_allow = run_command(command_allow)
    
    compliant_allow = False
    if "Access: (640/-rw-r-----) Owner: (root) Group: (daemon)" in output_allow or "Access: (640/-rw-r-----) Owner: (root) Group: (root)" in output_allow:
        compliant_allow = True

    # Check permissions for /etc/at.deny (if it exists)
    command_deny = '[ -e "/etc/at.deny" ] && stat -Lc "Access: (%a/%A) Owner: (%U) Group: (%G)" /etc/at.deny'
    output_deny = run_command(command_deny)
    
    compliant_deny = False
    if output_deny:  # Check if the file exists and its permissions
        if "Access: (640/-rw-r-----) Owner: (root) Group: (daemon)" in output_deny or "Access: (640/-rw-r-----) Owner: (root) Group: (root)" in output_deny:
            compliant_deny = True

    if compliant_allow and compliant_deny:
        return "Compliant"
    elif compliant_allow and not compliant_deny:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for /etc/ssh/sshd_config
def check_sshd_config_permissions():
    # Run the script to check permissions of /etc/ssh/sshd_config
    command = './scripts/74.sh'
    output = run_command(command)
    
    if "PASS" in output:
        return "Compliant"
    else:
        return "Non-Compliant"


# Compliance check for SSH private host key files
def check_ssh_private_key_permissions():
    # Run the script to check SSH private key permissions
    command = './scripts/75.sh'
    output = run_command(command)
    
    if "All SSH private keys are compliant" in output:
        return "Compliant"
    else:
        return "Non-Compliant"
        
# Compliance check for SSH public host key files
def check_ssh_public_key_permissions():
    # Run the command to list permissions of SSH public key files
    command = 'ls -l /etc/ssh/*.pub'
    output = run_command(command).splitlines()

    # Check if all lines start with '-rw-r--r--'
    for line in output:
        if not line.startswith("-rw-r--r--"):
            return "Non-Compliant"
    
    return "Compliant"

# Compliance check for sshd access configuration
def check_sshd_access():
    # Run the script to check sshd access
    command = './scripts/77.sh'
    output = run_command(command)
    
    if "PASS" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd Banner configuration
def check_sshd_banner():
    # Run the command to check sshd banner
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep banner"
    output = run_command(command)
    
    if "banner" in output and "none" not in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd ciphers configuration
def check_sshd_ciphers():
    # Run the command to check sshd ciphers
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep ciphers"
    output = run_command(command)

    # List of insecure ciphers to check for
    insecure_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "rijndael-cbc@lysator.liu.se"]
    
    # Check if any insecure cipher is present in the output
    if any(cipher in output for cipher in insecure_ciphers):
        return "Non-Compliant"
    else:
        return "Compliant"

# Compliance check for sshd ClientAliveInterval and ClientAliveCountMax
def check_sshd_client_alive():
    # Run the command to check sshd ClientAliveInterval and ClientAliveCountMax
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep -E 'clientaliveinterval|clientalivecountmax'"
    output = run_command(command)

    # Check if the expected values are in the output
    if "clientaliveinterval 15" not in output or "clientalivecountmax 3" not in output:
        return "Non-Compliant"
    else:
        return "Compliant"

# Compliance check for sshd HostbasedAuthentication
def check_sshd_hostbased_authentication():
    # Run the command to check sshd HostbasedAuthentication
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep hostbasedauthentication"
    output = run_command(command)

    # Check if the expected value is in the output
    if "hostbasedauthentication no" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd IgnoreRhosts
def check_sshd_ignorerhosts():
    # Run the command to check sshd IgnoreRhosts
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep ignorerhosts"
    output = run_command(command)

    # Check if the expected value is in the output
    if "ignorerhosts yes" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd KexAlgorithms
def check_sshd_kexalgorithms():
    # Run the command to check sshd KexAlgorithms
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep kexalgorithms"
    output = run_command(command)

    # Check if any weak algorithms are present in the output
    weak_algorithms = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1"
    ]
    
    if any(weak_algorithm in output for weak_algorithm in weak_algorithms):
        return "Non-Compliant"
    else:
        return "Compliant"

# Compliance check for sshd LoginGraceTime
def check_sshd_logingracetime():
    # Run the command to check sshd LoginGraceTime
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep logingracetime"
    output = run_command(command)

    # Extract the value of LoginGraceTime from the output
    try:
        login_gracetime = int(output.split()[-1])  # Assuming the value is the last element
        if login_gracetime <= 60:
            return "Compliant"
        else:
            return "Non-Compliant"
    except ValueError:
        return "Non-Compliant"

# Compliance check for sshd LogLevel
def check_sshd_loglevel():
    # Run the command to check sshd LogLevel
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep loglevel"
    output = run_command(command)

    # Check if the output contains 'loglevel VERBOSE'
    if "loglevel VERBOSE" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd MACs
def check_sshd_macs():
    # Run the command to check sshd MACs
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep -i 'MACs'"
    output = run_command(command)

    # List of weak algorithms to check for
    weak_mac_algorithms = [
        "hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1-96", 
        "umac-64@openssh.com", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
        "hmac-ripemd160-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com"
    ]

    # Check if any of the weak algorithms are present in the output
    if any(weak_algorithm in output for weak_algorithm in weak_mac_algorithms):
        return "Non-Compliant"
    else:
        return "Compliant"

# Compliance check for sshd MaxAuthTries
def check_sshd_maxauthtries():
    # Run the command to check sshd MaxAuthTries
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep maxauthtries"
    output = run_command(command)

    # Check if the output contains maxauthtries set to 4
    if "maxauthtries 4" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd MaxSessions
def check_sshd_maxsessions():
    # Run the command to check sshd MaxSessions
    command = "grep -Pis '^\h*#?\h*MaxSessions' /etc/ssh/sshd_config"
    output = run_command(command)

    # Ensure that only "MaxSessions 10" is present in the output
    if output.strip() == "MaxSessions 10":
        return "Compliant"
    else:
        return "Non-Compliant"


# Compliance check for sshd MaxStartups
def check_sshd_maxstartups():
    # Run the command to check sshd MaxStartups
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep -i 'maxstartups 10:30:60'"
    output = run_command(command)

    # Check if the output is not blank
    if output.strip() != "":
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd PermitEmptyPasswords
def check_sshd_permitemptypasswords():
    # Run the command to check sshd PermitEmptyPasswords
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep 'permitemptypasswords no'"
    output = run_command(command)

    # Check if the output is not blank
    if output.strip() != "":
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd PermitRootLogin
def check_sshd_permitrootlogin():
    # Run the command to check sshd PermitRootLogin
    command = "sshd -T -C user=root -C host=$(hostname) -C addr=$(grep $(hostname) /etc/hosts | awk '{print $1}') | grep 'permitrootlogin no'"
    output = run_command(command)

    # Check if the output is not blank
    if output.strip() != "":
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for sshd PermitUserEnvironment
def check_sshd_permituserenvironment():
    # Run the command to check PermitUserEnvironment
    command = "grep -Pis '^\s*#\s*PermitUserEnvironment' /etc/ssh/sshd_config"
    output = run_command(command)

    # Check if the output matches the exact string "PermitUserEnvironment no"
    if output.strip() == "PermitUserEnvironment no":
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for rsyslog installation
def check_rsyslog_installed():
    # Run the command to check rsyslog installation
    command = "./scripts/93.sh"
    output = run_command(command)

    # Check if the output contains "rsyslog is installed."
    if "rsyslog is installed." in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for rsyslog service enabled status
def check_rsyslog_service_enabled():
    # Run the command to check rsyslog service status
    command = "systemctl is-enabled rsyslog"
    output = run_command(command)

    # Check if the output contains "enabled"
    if "enabled" in output:
        return "Compliant"
    else:
        return "Non-Compliant"

# Compliance check for journald sending logs to rsyslog
def check_journald_forward_to_syslog():
    # Run the command to check if journald is configured to forward logs to rsyslog
    command = "grep -Piq '^\s*ForwardToSyslog\s*=\s*yes' /etc/systemd/journald.conf.d/50-journald_forward.conf"
    output = run_command(command)

    # If output is blank, it's compliant
    if output == "":
        return "Compliant"
    else:
        return "Non-Compliant"


# Compliance check for rsyslog default file permissions
def check_rsyslog_file_permissions():
    # Run the command to check the rsyslog file create mode
    command = "grep -Ps '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf"
    output = run_command(command)

    # If the output matches the expected value, it's compliant
    if "$FileCreateMode 0640" in output:
        return "Compliant"
    else:
        return "Non-Compliant"


# Manual check for logging configuration
def check_logging_configuration():
    return "Manual Check Needed"


# Manual check for rsyslog remote log host configuration
def check_rsyslog_remote_log_host():
    return "Manual Check Needed"




# Function to check if rsyslog is not configured to receive logs from a remote client
def check_rsyslog_no_remote_client():
    commands = [
        "grep -Ps -- '^\h*module(load=\"imtcp\")' /etc/rsyslog.conf /etc/rsyslog.d/*",
        "grep -Ps -- '^\h*input(type=\"imtcp\" port=\"514\")' /etc/rsyslog.conf /etc/rsyslog.d/*",
        "grep -s '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*",
        "grep -s '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*"
    ]
    
    for command in commands:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stdout or result.stderr:  # If there is output
            return "Non-Compliant"
    
    return "Compliant"



# Check for systemd-journal-remote installation status
def check_systemd_journal_remote_installation():
    result = run_command('rpm -q systemd-journal-remote')
    if 'not installed' in result:
        return 'Non-Compliant'
    return 'Compliant'

# Manual check for systemd-journal-remote configuration
def check_systemd_journal_remote_configuration():
    return "Manual Check Needed"

# Check if systemd-journal-upload.service is enabled
def check_systemd_journal_upload():
    command = "systemctl is-enabled systemd-journal-upload.service"
    output = run_command(command)
    if "enabled" in output:
        return "Compliant"
    return "Non-Compliant"


# Check if systemd-journal-remote.socket is masked
def check_systemd_journal_remote():
    command = "systemctl is-enabled systemd-journal-remote.socket"
    output = run_command(command)
    if "masked" in output:
        return "Compliant"
    return "Non-Compliant"

# Check if systemd-journald.service is static
def check_systemd_journald():
    command = "systemctl is-enabled systemd-journald.service"
    output = run_command(command)
    if "static" in output:
        return "Compliant"
    return "Non-Compliant"

# Check if journald is configured to compress large log files
def check_journald_compress():
    command = "grep ^\s*Compress /etc/systemd/journald.conf"
    output = run_command(command)
    if "Compress=yes" in output:
        return "Compliant"
    return "Non-Compliant"

# Check if journald is configured to not send logs to rsyslog
def check_journald_forward_to_syslog_2():
    command = "grep ^\s*ForwardToSyslog /etc/systemd/journald.conf"
    output = run_command(command)
    if output == "":
        return "Compliant"
    return "Non-Compliant"


# Manual check for journald log rotation configuration
def check_journald_log_rotation():
    return "Manual Check Needed"

def check_logrotate_configured():
    return "Manual Check Needed"

# Check if the output is blank
def check_logfile_access():
    output = run_command("./scripts/109.sh")
    if not output:  # Output is blank
        return "Compliant"
    return "Non-Compliant"

def check_passwd_permissions():
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/passwd"
    result = run_command(command)
    
    if "Access: (0644/-rw-r--r--)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_passwd_dash_permissions():
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/passwd-"
    result = run_command(command)
    
    if "Access: (0644/-rw-r--r--)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"


def check_opasswd_permissions():
    result_opasswd = run_command("if [ -e \"/etc/security/opasswd\" ]; then stat -Lc '%n Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/security/opasswd; fi")
    result_opasswd_old = run_command("if [ -e \"/etc/security/opasswd.old\" ]; then stat -Lc '%n Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/security/opasswd.old; fi")
    
    opasswd_compliant = False
    opasswd_old_compliant = False
    
    # Check for /etc/security/opasswd
    if "/etc/security/opasswd Access: (0600/-rw-------)" in result_opasswd and "Uid: ( 0/ root)" in result_opasswd and "Gid: ( 0/ root)" in result_opasswd:
        opasswd_compliant = True

    # Check for /etc/security/opasswd.old
    if "/etc/security/opasswd.old Access: (0600/-rw-------)" in result_opasswd_old and "Uid: ( 0/ root)" in result_opasswd_old and "Gid: ( 0/ root)" in result_opasswd_old:
        opasswd_old_compliant = True
    
    # If either file is compliant, the overall status is compliant
    if opasswd_compliant or opasswd_old_compliant:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_group_permissions():
    result = run_command("stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group")
    
    # Check if the result matches the expected output
    if "Access: (0644/-rw-r--r--)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_group_permissions_():
    result = run_command("stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group-")
    
    # Check if the result matches the expected output
    if "Access: (0644/-rw-r--r--)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_shadow_permissions():
    result = run_command("stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow")
    
    # Check if the result matches the expected output
    if "Access: (0/----------)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_shadow_permissions_():
    result = run_command("stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow-")
    
    # Check if the result matches the expected output
    if "Access: (0/----------)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_gshadow_permissions():
    result = run_command("stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow")
    
    # Check if the result matches the expected output
    if "Access: (0/----------)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_gshadow_permissions_():
    result = run_command("stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow-")
    
    # Check if the result matches the expected output
    if "Access: (0/----------)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_shells_permissions():
    result = run_command("stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shells")
    
    # Check if the result matches the expected output
    if "Access: (0644/-rw-r--r--)" in result and "Uid: ( 0/ root)" in result and "Gid: ( 0/ root)" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_world_writable_files():
    result = run_command("./scripts/120.sh")
    
    # Check if the output contains the word "PASS"
    if "PASS" in result:
        return "Compliant"
    else:
        return "Non-Compliant"

def check_unowned_ungrouped_files():
    result = run_command("./scripts/121.sh")
    
    # Check if the output contains the word "PASS"
    if "PASS" in result:
        return "Compliant"
    else:
        return "Non-Compliant"







# Function to write compliance result to CSV
def write_to_csv(data):
    with open('compliance_report.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["Sr No.","Control Objective", "Compliance Status"])
        writer.writeheader()
        writer.writerows(data)
# Main function
def main():
    results = []

    # List of functions for compliance checks
    compliance_checks = [
        (check_cramfs_module, "Ensure cramfs kernel module is not available (Automated)"),
        (check_freevxfs_module, "Ensure freevxfs kernel module is not available (Automated)"),
        (check_hfs_module, "Ensure hfs kernel module is not available (Automated)"),
        (check_hfsplus_module, "Ensure hfsplus kernel module is not available (Automated)"),
        (check_jffs2_module, "Ensure jffs2 kernel module is not available (Automated)"),
        (check_tmp_partition, "Ensure /tmp is a separate partition (Automated)"),
        (check_tmp_nodev, "Ensure nodev option set on /tmp partition (Automated)"),
        (check_tmp_nosuid, "Ensure nosuid option set on /tmp partition (Automated)"),
        (check_tmp_noexec, "Ensure noexec option set on /tmp partition (Automated)"),
        (check_dev_shm_partition, "Ensure /dev/shm is a separate partition (Automated)"),
        (check_dev_shm_nodev, "Ensure nodev option set on /dev/shm partition (Automated)"),
        (check_dev_shm_nosuid, "Ensure nosuid option set on /dev/shm partition (Automated)"),
        (check_dev_shm_noexec, "Ensure noexec option set on /dev/shm partition (Automated)"),
        (check_home_nodev, "Ensure nodev option set on /home partition (Automated)"),
        (check_home_nosuid, "Ensure nosuid option set on /home partition (Automated)"),
        (check_var_nodev, "Ensure nodev option set on /var partition (Automated)"),
        (check_var_nosuid, "Ensure nosuid option set on /var partition (Automated)"),
        (check_var_tmp_nodev, "Ensure nodev option set on /var/tmp partition (Automated)"),
        (check_var_tmp_nosuid, "Ensure nosuid option set on /var/tmp partition (Automated)"),
        (check_var_tmp_noexec, "Ensure noexec option set on /var/tmp partition (Automated)"),
        (check_var_log_nodev, "Ensure nodev option set on /var/log partition (Automated)"),
        (check_var_log_nosuid, "Ensure nosuid option set on /var/log partition (Automated)"),
        (check_var_log_noexec, "Ensure noexec option set on /var/log partition (Automated)"),
        (check_var_log_audit_nodev, "Ensure nodev option set on /var/log/audit partition (Automated)"),
        (check_tmp_nosuid, "Ensure nosuid option set on /tmp partition (Automated)"),
        (check_tmp_noexec, "Ensure noexec option set on /tmp partition (Automated)"),
        (check_dev_shm_separate, "Ensure /dev/shm is a separate partition (Automated)"),
        (check_gpg_keys, "Ensure GPG keys are configured (Manual)"),
        (check_gpgcheck, "Ensure gpgcheck is globally activated (Automated)"),
        (check_gpg_keys,"Ensure package manager repositories are configured (Manual)"),
        (check_gdm_banner, "Ensure GDM login banner is configured (Automated)"),
        (check_gdm_disable_user_list, "Ensure GDM disable-user-list option is enabled (Automated)"),
        (check_gdm_screen_lock, "Ensure GDM screen locks when the user is idle (Automated)"),
        (check_gdm_screen_lock_override, "Ensure GDM screen locks cannot be overridden (Automated)"),
        (check_gpg_keys, "Ensure GDM autorun-never is enabled (Automated)"),
        (check_gdm_autorun_never, "Ensure GDM autorun-never is not overridden (Automated)"),
        (check_xdmcp_enabled, "Ensure XDMCP is not enabled (Automated)"),
        (check_time_sync, "Ensure time synchronization is in use (Automated)"),
        (check_chrony_config, "Ensure chrony is configured (Automated)"),
        (check_chrony_root_user, "Ensure chrony is not run as the root user (Automated)"),
        (check_dhcp_server_installed, "Ensure dhcp server services are not in use (Automated)"),
        (check_bind_installed, "Ensure dns server services are not in use (Automated)"),
        (check_dhcp_server_installed, "Ensure dhcp server services are not in use (Automated)"),
        (check_dnsmasq_installed, "Ensure dnsmasq services are not in use (Automated)"),
        (check_samba_installed, "Ensure samba file server services are not in use (Automated)"),
        (check_vsftpd_installed, "Ensure ftp server services are not in use (Automated)"),
        (check_message_access_server_services, "Ensure message access server services are not in use (Automated)"),
        (check_nfs_utils, "Ensure network file system services are not in use (Automated)"),
        (check_ypserv, "Ensure nis server services are not in use (Automated)"),
        (check_gpg_keys,"Ensure IPv6 status is identified (Manual)"),
        (check_gpg_keys,"Enable or disable IPv6 in accordance with system requirements and local site policy"),
        (check_ip_forwarding, "Ensure ip forwarding is disabled (Automated)"),
        (check_packet_redirect, "Ensure packet redirect sending is disabled (Automated)"),
        (check_bogus_icmp, "Ensure bogus ICMP responses are ignored (Automated)"),
        (check_broadcast_icmp, "Ensure broadcast ICMP requests are ignored (Automated)"),
        (check_icmp_redirects, "Ensure ICMP redirects are not accepted (Automated)"),
        (check_secure_icmp_redirects, "Ensure secure ICMP redirects are not accepted (Automated)"),
        (check_reverse_path_filtering, "Ensure reverse path filtering is enabled (Automated)"),
        (check_source_routed_packets, "Ensure source routed packets are not accepted (Automated)"),
        (check_suspicious_packets_logging, "Ensure suspicious packets are logged (Automated)"),
        (check_tcp_syn_cookies, "Ensure tcp syn cookies is enabled (Automated)"),
        (check_ipv6_router_advertisements, "Ensure ipv6 router advertisements are not accepted (Automated)"),
        (check_nftables_installed, "Ensure nftables is installed (Automated)"),
        (check_cron_enabled_active, "Ensure cron daemon is enabled and active (Automated)"),
        (check_sshd_config_permissions, "Ensure permissions on /etc/ssh/sshd_config is configured"),
        (check_crontab_permissions, "Ensure permissions on /etc/crontab are configured"),
        (check_cron_hourly_permissions, "Ensure permissions on /etc/cron.hourly are configured"),
        (check_cron_daily_permissions, "Ensure permissions on /etc/cron.daily are configured"),
        (check_cron_weekly_permissions, "Ensure permissions on /etc/cron.weekly are configured"),
        (check_cron_monthly_permissions, "Ensure permissions on /etc/cron.monthly are configured"),
        (check_cron_d_permissions, "Ensure permissions on /etc/cron.d are configured"),
        (check_cron_deny_permissions, "Ensure crontab is restricted to authorized users"),
        (check_at_permissions, "Ensure at is restricted to authorized users"),
        (check_sshd_config_permissions, "Ensure permissions on /etc/ssh/sshd_config are configured"),
        (check_ssh_private_key_permissions, "Ensure permissions on SSH private host key files are configured"),
        (check_ssh_public_key_permissions, "Ensure permissions on SSH public host key files are configured"),
        (check_sshd_access, "Ensure sshd access is configured"),
        (check_sshd_banner, "Ensure sshd Banner is configured"),
        (check_sshd_ciphers, "Ensure sshd Ciphers are configured"),
        (check_sshd_client_alive, "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"),
        (check_sshd_hostbased_authentication, "Ensure sshd HostbasedAuthentication is disabled"),
        (check_sshd_ignorerhosts, "Ensure sshd IgnoreRhosts is enabled"),
        (check_sshd_kexalgorithms, "Ensure sshd KexAlgorithms is configured"),
        (check_sshd_logingracetime, "Ensure sshd LoginGraceTime is configured"),
        (check_sshd_loglevel, "Ensure sshd LogLevel is configured"),
        (check_sshd_macs, "Ensure sshd MACs are configured"),
        (check_sshd_maxauthtries, "Ensure sshd MaxAuthTries is configured"),
        (check_sshd_maxsessions, "Ensure sshd MaxSessions is configured"),
        (check_sshd_maxstartups, "Ensure sshd MaxStartups is configured"),
        (check_sshd_permitemptypasswords, "Ensure sshd PermitEmptyPasswords is disabled"),
        (check_sshd_permitrootlogin, "Ensure sshd PermitRootLogin is disabled"),
        (check_sshd_permituserenvironment, "Ensure sshd PermitUserEnvironment is disabled"),
        (check_rsyslog_installed, "Ensure rsyslog is installed"),
        (check_rsyslog_service_enabled, "Ensure rsyslog service is enabled"),
        (check_journald_forward_to_syslog, "Ensure journald is configured to send logs to rsyslog"),
        (check_rsyslog_file_permissions, "Ensure rsyslog default file permissions are configured"),
        (check_logging_configuration, "Ensure logging is configured"),
        (check_rsyslog_remote_log_host, "Ensure rsyslog is configured to send logs to a remote log host"),
        (check_rsyslog_no_remote_client, "Ensure rsyslog is not configured to receive logs from a remote client"),
        (check_systemd_journal_remote_installation, "Ensure systemd-journal-remote is installed"),
        (check_systemd_journal_remote_configuration, "Ensure systemd-journal-remote is configured"),
        (check_systemd_journal_upload,"Ensure systemd-journal-remote is enabled (Manual)"),
        (check_systemd_journal_remote, "Ensure journald is not configured to receive logs from a remote client (Automated)"),
        (check_systemd_journald, "Ensure journald service is enabled (Automated)"),
        (check_journald_compress, "Ensure journald is configured to compress large log files (Automated)"),
        (check_journald_forward_to_syslog_2,"Ensure journald is not configured to send logs to rsyslog (Manual)"),
        (check_journald_log_rotation, "Ensure journald log rotation is configured per site policy"),
        (check_logrotate_configured, "Ensure logrotate is configured (Manual)"),
        (check_logfile_access, "Ensure all logfiles have appropriate access configured (Automated)"),
        (check_passwd_permissions, "Ensure permissions on /etc/passwd are configured (Automated)"),
        (check_passwd_dash_permissions,"Ensure permissions on /etc/passwd- are configured (Automated)"),
        (check_opasswd_permissions,"Ensure permissions on /etc/opasswd are configured (Automated)"),
        (check_group_permissions,"Ensure permissions on /etc/group are configured (Automated)"),
        (check_group_permissions_,"Ensure permissions on /etc/group- are configured (Automated)"),
        (check_shadow_permissions,"Ensure permissions on /etc/shadow are configured (Automated)"),
        (check_shadow_permissions_,"Ensure permissions on /etc/shadow- are configured (Automated)"),
        (check_gshadow_permissions,"Ensure permissions on /etc/gshadow are configured (Automated)"),
        (check_gshadow_permissions_,"Ensure permissions on /etc/gshadow- are configured (Automated)"),
        (check_shells_permissions,"Ensure permissions on /etc/shells are configured (Automated)"),
        (check_world_writable_files,"Ensure world writable files and directories are secured (Automated)"),
        (check_unowned_ungrouped_files,"Ensure no unowned or ungrouped files or directories exist (Automated)")
        
        


















        















































































    ]

    # Iterate over the compliance checks and dynamically assign Sr No.
    for idx, (check_func, control_obj) in enumerate(compliance_checks, start=1):
        compliance_status = check_func()
        results.append({
            "Sr No.": idx,
            "Control Objective": control_obj,
            "Compliance Status": compliance_status
        })

    # Write results to CSV
    write_to_csv(results)
    print("Compliance checks completed. Results saved to compliance_report.csv.")

if __name__ == "__main__":
    main()