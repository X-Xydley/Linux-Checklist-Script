#!/bin/bash

# LAST UPDATED: Mar 4, 2025

manageServices() {
    # Predetermined list of services to be removed
    local SERVICES_TO_REMOVE=(openssh-server ssh nmap rsh-client talk telnet rpcbind dnsmasq dovecot-imapd dovecot-pop3d squid dnmpd nis iptables-persistent nginx aisleriot rsync netcat netcat-openbsd netcat-traditional ncat pnetcat socat sock sbd hydra hydra-gtk john john-data aircrack-ng fcrackzip lcrack ophcrack ophcrack-cli pdfcrack pyrit rarcrack sipcrack irpas wireshark samba* apport ntp avahi-daemon cups isc-dhcp-server ldap-utils slapd nfs-kernel-server bind9 vsftpd apache2 dovecot-imapd dovecot-pop3d squid dnmpd nis dnsmasq snort)
    
    # Display services to be removed
    echo "The following services are planned for removal:"
    echo "${SERVICES_TO_REMOVE[*]}"
    echo "Please list the services (by package name) you want to keep, separated by spaces:"
    
    # Read user input for required services
    read -rp "Required services: " -a REQUIRED_SERVICES
    
    # Updates required services
    echo "Updating and upgrading the following required services: ${REQUIRED_SERVICES[*]}"
    for service in "${REQUIRED_SERVICES[@]}"; do
        if dpkg-query -W | grep -q "^ii.*$service"; then
            echo "Updating and upgrading $service..."
            sudo apt-get install -y "$service" && echo "$service upgraded successfully." || echo "Failed to upgrade $service."
        else
            echo "$service is not installed on the system, skipping upgrade."
        fi
    done

    # Filter out required services
    local FINAL_SERVICES_TO_REMOVE=()
    for service in "${SERVICES_TO_REMOVE[@]}"; do
        if [[ ! " ${REQUIRED_SERVICES[*]} " =~ " $service " ]]; then
            FINAL_SERVICES_TO_REMOVE+=("$service")
        fi
    done
    
    # Confirm removal
    echo "The following services will be removed: ${FINAL_SERVICES_TO_REMOVE[*]}"
    read -rp "Proceed with removal? (y/n): " CONFIRM
    if [[ $CONFIRM != "y" ]]; then
        echo "Aborted by user. Exiting."
        return 1
    fi
    
    # Remove services
    for service in "${FINAL_SERVICES_TO_REMOVE[@]}"; do
        echo "Removing $service..."
        if sudo apt-get remove --purge -y "$service"; then
            echo "$service removed successfully."
        else
            echo "Failed to remove $service."
        fi
    done

    prelink -ua
    apt purge prelink -y
}

# Updates packages and services
runUpdates() {
    echo "Running updates..."
    for updatesetting in update dist-upgrade upgrade "install -f" autoclean check; do
        apt-get $updatesetting -y || true
    done
    sudo apt-get autoremove -y
    echo "System has been updated."
}

# Installs useful programs
installPrograms() {
    echo "Installing programs..."
    for program in libpam-pwquality chkrootkit clamav rkhunter sudo ufw auditd rsyslog systemd-journal-remote sudo-ldap; do
        apt-get install $program -y || true
    done
    echo "Necessary programs installed."
}

# sudo-ldap(ldap)

# Installs and runs AIDE
AIDEsetup() {
    read -p "Would you like to install and run AIDE? (y/n): " response
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
    if [[ "$response" == "y" ]]; then
        echo "Installing AIDE..."
        apt install aide aide-common -y
        echo "Running AIDE..."
        aideinit
        mv /var/lib/aide/aide.db.net /var/lib/aide/aide.db
    else
        echo "Will not install AIDE. Continuing.."
    fi
}

# All sysctl configs
sysctlConfig() {
    # Asks about disabling IPv6
    read -p "Would you like to disable IPv6? (Y/n): " disableIPv6response
    if [[ "$disableIPv6response" == "y" ]]; then
        echo "Disabling IPv6..."
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -w net.ipv6.conf.all.disable_ipv6=1
        sysctl -w net.ipv6.conf.default.disable_ipv6=1
        sysctl -w net.ipv6.conf.lo.disable_ipv6=1
        # Update GRUB to disable IPv6 at boot
        echo "Updating GRUB configuration..."
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"/' /etc/default/grub
        update-grub
        echo "IPv6 has been disabled. A system reboot is required to fully apply the changes."
    else
        echo "Continuing..."
    fi

    # Enables Address Space Layout Randomization (ASLR)
    if ! grep -q "^kernel.randomize_va_space" /etc/sysctl.conf; then
        echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    else
        sed -i 's/^kernel\.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
    fi
    sysctl -w kernel.randomize_va_space=2

    # Ensure ptrace_scope is restricted
    if ! grep -q "^kernel.yama.ptrace_scope" /etc/sysctl.conf; then
        echo "kernel.yama.ptrace_scope = 2" >> /etc/sysctl.conf
    else
        sed -i 's/^kernel\.yama.ptrace_scope.*/kernel.yama.ptrace_scope = 2/' /etc/sysctl.conf
    fi
    sysctl -w kernel.yama.ptrace_scope=1

    # Disables packet redirect sending
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.send_redirects=0
    sysctl -w net.ipv4.route.flush=1

    # Disabled IPv4 forwarding
    sed -i '/ipv4.ip_forward/c\net.ipv4.ip_forward=0' /etc/sysctl.conf 
    sysctl -w net.ipv4.ip_forward=0

    # Enables TCP SYN cookies
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.tcp_syncookies=1

    # Ensure source routed packets are not accepted
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.default.accept_source_route=0
    sysctl -w net.ipv4.conf.all.accept_source_route=0

    # Ensure all ICMP redirects are not accepted
    echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.default.accept_redirects=0
    sysctl -w net.ipv4.conf.all.secure_redirects=0
    sysctl -w net.ipv4.conf.default.secure_redirects=0

    # Ensure suspicious packets are logged
    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.log_martians=1
    sysctl -w net.ipv4.conf.default.log_martians=1

    # Ensure broadcast ICMP requests are ignored
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

    # Ensure bogus ICMP responses are ignored 
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

    # Ensure Reverse Path Filtering is enabled
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.rp_filter=1
    sysctl -w net.ipv4.conf.default.rp_filter=1

    echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.tcp.rfc1337=1

    # Ensure core dumps are restricted
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    sysctl -w fs.suid_dumpable=0

    sysctl -p
}

# Configures apparmor
apparmorConfig() {
    apt install apparmor apparmor-profiles apparmor-utils -y
    systemctl enable apparmor
    systemctl start apparmor
    # Sets all profiles to enforce mode
    aa-enforce /etc/apparmor.d/*
}

# Sets perms for anything necessary
permsConfig() {
    # bootloader config 
    chown root:root /boot/grub/grub.cfg
    chmod u-x,go-rwx /boot/grub/grub.cfg

    # /home
    chown root:root /home

    # /swapfile
    chmod 600 /swapfile
    chown root:root /swapfile

    # /etc/issue
    chown root:root $(readlink -e /etc/issue)
    chmod u-x,go-wx $(readlink -e /etc/issue)

    # /etc/issue
    chown root:root $(readlink -e /etc/issue.net)
    chmod u-x,go-wx $(readlink -e /etc/issue.net)

    # /etc/crontab
    chown root:root /etc/crontab
    chmod og-rwx /etc/crontab

    # /etc/cron.hourly
    chown root:root /etc/cron.hourly/
    chmod og-rwx /etc/cron.hourly/

    # /etc/cron.daily
    chown root:root /etc/cron.daily/
    chmod og-rwx /etc/cron.daily/

    # /etc/cron.weekly
    chown root:root /etc/cron.weekly/
    chmod og-rwx /etc/cron.weekly/

    # /etc/cron.monthly
    chown root:root /etc/cron.monthly/
    chmod og-rwx /etc/cron.monthly/

    # /etc/cron.d
    chown root:root /etc/cron.d/
    chmod og-rwx /etc/cron.d/
    
    # /etc/ssh/sshd_config
    chmod u-x,og-rwx /etc/ssh/sshd_config
    chown root:root /etc/ssh/sshd_config

    # /etc/passwd
    chmod u-x,go-wx /etc/passwd
    chown root:root /etc/passwd

    # /etc/passwd-
    chmod u-x,go-wx /etc/passwd-
    chown root:root /etc/passwd-

    # /etc/group
    chmod u-x,go-wx /etc/group
    chown root:root /etc/group

    # /etc/group-
    chmod u-x,go-wx /etc/group-
    chown root:root /etc/group-

    # /etc/shadow
    chmod u-x,g-wx,o-rwx /etc/shadow
    chown root:root /etc/shadow

    # /etc/shadow-
    chmod u-x,g-wx,o-rwx /etc/shadow-
    chown root:root /etc/shadow-

    # /etc/gshadow
    chmod u-x,g-wx,o-rwx /etc/gshadow
    chown root:root /etc/gshadow

    # /etc/gshadow-
    chmod u-x,g-wx,o-rwx /etc/gshadow-
    chown root:root /etc/gshadow-

    # /etc/shells
    chmod u-x,go-wx /etc/shells
    chown root:root /etc/shells

    # /etc/security/opasswd
    [ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd
    [ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd
    [ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old
    [ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old
}

UFWSettings() {
    # Ensures ufw is enabled
    systemctl unmask ufw.service
    systemctl --now enable ufw.service
    ufw enable
    # Configures loopback traffic
    ufw allow in on lo
    ufw allow out on lo
    ufw deny in from 127.0.0.0/8
    ufw deny in from ::1
    # Configure outbound connections
    ufw allow out on all
    # Ensure ufw default deny firewall policy
    ufw default deny incoming
    ufw default deny outgoing
    ufw default deny routed
    # Does something ig
    ufw logging high
    ufw status verbose

    # If apache2 is installed, configure ufw to allow it
    if dpkg-query -W | grep -q apache2; then
        echo "Apache is installed. Configuring UFW to "Apache Secure" profile..."
        sudo ufw allow "Apache Secure"
    else
        echo "Apache is not installed. No changes made to UFW"
    fi

    # If openssh is installed, configure ufw to allow it
    if dpkg-query -W | grep -q openssh; then
        echo "OpenSSH is installed. Configuring UFW to allow OpenSSH..."
        sudo ufw allow OpenSSH
    else
        echo "OpenSSH is not installed. No changes made to UFW"
    fi

    # If FTP(vsftpd) is installed, configure ufw to allow it
    if dpkg-query -W | grep -q vsftpd; then
        echo "vsftpd is installed. Configuring UFW to allow FTP..."
        sudo ufw allow vsftpd
    else
        echo "vsftpd is not installed. No changes made to UFW"
    fi
}

# Password Security
passConfig() {
    sed -i 's/nullok/ /g' /etc/pam.d/common-auth
    sed -i '/dcredit/c\dcredit=-1' /etc/security/pwquality.conf
    sed -i '/ucredit/c\ucredit=-1' /etc/security/pwquality.conf
    sed -i '/ocredit/c\ocredit=-1' /etc/security/pwquality.conf
    sed -i '/lcredit/c\lcredit=-1' /etc/security/pwquality.conf
    sed -i '/minlen/c\minlen=14' /etc/security/pwquality.conf
    sed -i '/usercheck/c\usercheck=1' /etc/security/pwquality.conf
    #sed -i '$a auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' /etc/pam.d/common-auth
    #sed -i '$a auth required pam_tally2.so onerr=fail audit deny=5 unlock_time=900' /etc/pam.d/common-auth
    sed -i '$a account requisite pam_deny.so' /etc/pam.d/common-account
    sed -i '$a account required pam_tally2.so' /etc/pam.d/common-account
    sed -i '$a password required pam_pwhistory.so' /etc/pam.d/common-password
    sed -i '/pam_unix.so/ s/$/ use_authtok sha512 remember=10/' /etc/pam.d/common-password
    sed -i '/ENCRYPT_METHOD/c\ENCRYPT_METHOD SHA512' /etc/login.defs
    sed -i '/PASS_MIN_DAYS/c\PASS_MIN_DAYS 7' /etc/login.defs
    sed -i '/PASS_WARN_AGE/c\PASS_WARN_AGE 14' /etc/login.defs
    sed -i '/PASS_MAX_DAYS/c\PASS_MAX_DAYS 28' /etc/login.defs
    sed -i '/LOGIN_RETRIES/c\LOGIN_RETRIES 3' /etc/login.defs
    sed -i '/maxrepeat/c\maxrepeat=3' /etc/security/pwquality.conf
    # Ensure inactive password lock is 28 days
    useradd -D -f 28
    # Ensure number of changed chars in new password is configured
    sed -i '/difok/c\difok = 2' /etc/security/pwquality.conf
    # Disable use of dictionary words in passwords
    sed -i '/dictcheck/c\dictcheck = 1 ' /etc/security/pwquality.conf
    # Set default umask to 027
    sed -i '/umask/c\umask 027' ./.profile
    # Set accounts to use shadowed passwords
    sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd
}

# Ensure default user shell timeout is configured
shellTimeout() {
    # Define the files and directories to search
    local files=("/etc/bash.bashrc" "/etc/profile")
    local profile_d_dir="/etc/profile.d"

    # Add all *.sh files in /etc/profile.d/ to the list if the directory exists
    if [ -d "$profile_d_dir" ]; then
        for script in "$profile_d_dir"/*.sh; do
            [ -e "$script" ] && files+=("$script") # Ensure files exist before adding
        done
    fi

    # Loop through each file and remove occurrences of "TMOUT"
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            echo "Processing $file..."
            # Create a backup before editing
            cp "$file" "$file.bak"

            # Remove lines containing "TMOUT" using sed
            sed -i 's/TMOUT/ /g' "$file"

            echo "Removed 'TMOUT' from $file"
        else
            echo "File $file does not exist or is not a regular file."
        fi
    done
    # Sets TMOUT in /etc/profile file
    echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile
}

# Configuration for journald service
journaldConfig() {
    systemctl --now enable systemd-journal-upload.service
    systemctl --now disable systemd-journal-remote.socket
    # Ensure systemd-journal-remote is configured
    sed -i '/URL/c\URL=192.168.50.42' /etc/systemd/journal-upload.conf
    sed -i '/ServerKeyFile/c\ServerKeyFile=/etc/ssl/private/journal-upload.pem' /etc/systemd/journal-upload.conf
    sed -i '/ServerCertificateFile/c\ServerCertificateFile=/etc/ssl/certs/journal-upload.pem' /etc/systemd/journal-upload.conf
    sed -i '/TrustedCertificateFile/c\TrustedCertificateFile=/etc/ssl/ca/trusted.pem' /etc/systemd/journal-upload.conf
    # Configure to compress large log files
    sed -i '/Compress/c\Compress=yes' /etc/systemd/journald.conf
    # Write logfiles to persistent disk
    sed -i '/Storage/c\Storage=persistent' /etc/systemd/journald.conf
    systemctl restart systemd-journal-upload
}

# Configuration for rsyslog service
rsyslogConfig() {
    systemctl --now enable rsyslog
    # Sends journald logs to rsyslog
    sed -i '/ForwardToSyslog/c\ForwardToSyslog=yes' /etc/systemd/journald.conf
    # Configures rsyslog default file perms
    sed -i '/FileCreateMode/c\$FileCreateMode 0640' /etc/rsyslog.conf
    systemctl restart rsyslog
}

# Configuration for auditd service
auditdConfig() {
    systemctl --now enable auditd
    # Ensure audit log storage size is configured
    sed -i '/max_log_file/c\max_log_file = 8' /etc/audit/auditd.conf
    # Ensure audit logs are not auto deleted
    sed -i '/max_log_file_action/c\max_log_file_action = keep_logs' /etc/audit/auditd.conf
    # Disable system when audit logs are full
    sed -i '/space_left_action/c\space_left_action = email' /etc/audit/auditd.conf
    sed -i '/action_mail_acct/c\action_mail_acct = root' /etc/audit/auditd.conf
    sed -i '/admin_space_left_action/c\admin_space_left_action = halt' /etc/audit/auditd.conf
    # Ensure changes to sudoers is collected
    touch /etc/audit/rules.d/cyber.rules
    sudo bash -c "echo '-w /etc/sudoers -p wa -k scope' >> /etc/audit/rules.d/cyber.rules"
    sudo bash -c "echo '-w /etc/sudoers.d -p wa -k scope' >> /etc/audit/rules.d/cyber.rules"
    augenrules --load
}

# Function to ask end user if they want to add a user to a group
groupUsers() {
    read -p "Do you need to add a user to a group? (y/n): " response
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
    if [[ "$response" == "y" ]]; then
        read -p "Enter the username to add: " username
        read -p "Enter the group name: " group
        if getent group "$group" > /dev/null; then
            sudo usermod -aG "$group" "$username"
            echo "User $username has been added to the group $group."
        else
            echo "Group $group does not exist. Please create it first."
        fi
    else
        echo "No user will be added to any group."
    fi
}

# Lists and deletes possible prohibited media
prohibitedMedia() {
    root_extensions=("*.mp3" "*.mov" "*.mp4" "*.avi" "*.mpg" "*.mpeg" "*.flac" "*.m4a" "*.flv" "*.ogg")
    home_extensions=("*.gif" "*.png" "*.jpg" "*.jpeg")

    echo "Listing all prohibited files..."
    for ext in "${root_extensions[@]}"; do
        echo "Files with extension $ext:"
        sudo find / -type f -name "$ext" 2>/dev/null
    done
    
    for ext in "${home_extensions[@]}"; do
        echo "Files with extension $ext:"
        sudo find /home -type f -name "$ext" 2>/dev/null
    done

    read -p "Would you like to continue with deleting these files?" DelConfirm
    if [[ "$DelConfirm" == "y" ]]; then
        echo "Deleting prohibited files..."

        # Delete files with specified extensions in the root directory
        for ext in "${root_extensions[@]}"; do
            sudo find / -type f -name "$ext" -exec rm -f {} \; 2>/dev/null
        done

        # Delete files with specified extensions in the /home directory
        for ext in "${home_extensions[@]}"; do
            sudo find /home -type f -name "$ext" -exec rm -f {} \; 2>/dev/null
        done

        echo "Prohibited files deleted."
    else
        echo "Deletion canceled."
    fi   
}

# Removes users not listed in users.txt
# Changes passwords for users that are listed
# Removes admin perms from users
# Adds users listed in users.txt but not do not have an account
secureUsers() {
    echo -e "Deleting non listed accounts$"
    # Check if users.txt exists
    if [ ! -f "users.txt" ]; then
        touch users.txt
        nano users.txt
        echo "Resuming script after saving users.txt..."
    fi

    # Read authorized user names from users.txt
    authorized_users=()
    while read -r line; do
        # Assuming usernames can be extracted as lines with alphabetical characters
        if [[ "$line" =~ ^[[:alpha:]]+$ ]]; then
            authorized_users+=("$line")
        fi
    done < users.txt

    # Retrieve list of current system users from /etc/passwd, assuming user ids are typically >= 1000 for regular users
    current_users=( $(awk -F':' '$3>=1000 && $3<65534 {print $1}' /etc/passwd) )

    # Removing duplicate users in authorized_users to speed up deletion check
    readarray -t authorized_users < <(printf '%s\n' "${authorized_users[@]}" | awk '!seen[$0]++')

    # Deleting users not found in the authorized_users list
    for user in "${current_users[@]}"; do
        if [[ " ${authorized_users[*]} " =~ " $user " ]]; then
            echo "Updating password for user: $user"
            echo "$user:Cyb3rPatr!0t$" | sudo chpasswd
        else
            echo "Deleting user: $user"
            sudo userdel -r "$user"
        fi
    done

    # Adds new users if they are listed in users.txt and dont have an account
    for user in "${authorized_users[@]}"; do
        if [[ ! " ${current_users[*]} " =~ " $user " ]]; then
            echo "Adding user: $user"
            sudo useradd -m "$user"
            echo "$user:Cyb3rPatr!0t$" | sudo chpasswd
        fi
    done

    read -p "Enter admin usernames (space-separated): " -a admin_users

    # Filter out admin usernames from users.txt
    for admin in "${admin_users[@]}"; do
        sed -i "/^$admin$/d" users.txt
    done

    # Remove each user remaining in users.txt from the sudo group
    while read -r user; do
        if id -nG "$user" | grep -qw "sudo"; then
            echo "Removing $user from sudo group..."
            sudo deluser "$user" sudo
            sudo deluser "$user" adm
        else
            echo "$user is not in the sudo group."
        fi
    done < users.txt
}

# Ensures each user has a valid ssh key configuration
userSSHKeyCheck() {
    for user in $(cut -d: -f1 /etc/passwd); do
        # Skip system accounts (UID < 1000, except 'root')
        uid=$(id -u "$user")
        if [ "$uid" -lt 1000 ] && [ "$user" != "root" ]; then
            continue
        fi

        # Skip users in the sudo or adm groups
        if groups "$user" | grep -qwE 'sudo|adm'; then
            echo "Skipping user $user (member of sudo or adm group)."
            continue
        fi

        # Define user's home directory and SSH configuration path
        user_home=$(eval echo "~$user")
        ssh_dir="$user_home/.ssh"
        auth_keys="$ssh_dir/authorized_keys"

        # Check if authorized_keys exists and is not empty
        if [ -f "$auth_keys" ] && [ -s "$auth_keys" ]; then
            echo "User $user already has a valid SSH key configuration."
        else
            echo "Generating SSH key for user: $user"

            # Ensure the .ssh directory exists with correct permissions
            mkdir -p "$ssh_dir"
            chmod 700 "$ssh_dir"
            chown "$user:$user" "$ssh_dir"

            # Generate SSH key pair
            ssh-keygen -t rsa -b 2048 -f "$ssh_dir/id_rsa" -N "" -C "$user@$(hostname)" >/dev/null
            chown "$user:$user" "$ssh_dir/id_rsa" "$ssh_dir/id_rsa.pub"

            # Add the public key to authorized_keys
            cat "$ssh_dir/id_rsa.pub" >> "$auth_keys"
            chmod 600 "$auth_keys"
            chown "$user:$user" "$auth_keys"

            echo "SSH key generated and configured for user: $user"
        fi
    done
    echo "SSH key check and configuration complete."
}

# Configures ssh
SSHconfig() {
    # Disable password authentication in SSH
    sed -i '/PasswordAuthentication/c\PasswordAuthentication no' /etc/ssh/sshd_config
}

secondScript() {
    chmod +x secondaryscripts.sh
    ./secondaryscripts.sh
}

sudo apt-get install dbus-x11 gnome-terminal -y

# Enables and starts cron daemon
systemctl unmask cron
systemctl --now enable cron

# Removes message of the day
rm /etc/motd

# Stops bluetooth
systemctl stop bluetooth.service
systemctl mask bluetooth.service

# Ensures default group for root is GID 0
usermod -g 0 root

# Ensure nologin is not listed in /etc/shells
#sed -i '/nologin/d' /etc/shells

# Ensure shadow group is empty
#sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd

#SSHconfig
#export -f secondScript
#secondScript
export -f rsyslogConfig
export -f apparmorConfig
export -f AIDEsetup
export -f UFWSettings
export -f auditdConfig
export -f manageServices
export -f installPrograms
export -f runUpdates
gnome-terminal -- bash -c "rsyslogConfig; apparmorConfig; UFWSettings; auditdConfig; manageServices; installPrograms; runUpdates; AIDEsetup; exec bash"
export -f sysctlConfig
gnome-terminal -- bash -c "sysctlConfig"
export -f permsConfig
gnome-terminal -- bash -c "permsConfig"
#export -f passConfig
#gnome-terminal -- bash -c "passConfig"
export -f shellTimeout
gnome-terminal -- bash -c "shellTimeout"
export -f userSSHKeyCheck
gnome-terminal -- bash -c "userSSHKeyCheck"
#prohibitedMedia
export -f groupUsers
export -f secureUsers
gnome-terminal -- bash -c "groupUsers; secureUsers; exec bash"
