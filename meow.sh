#!/bin/bash

# LAST UPDATED: Dec 3, 2024

# Determine if SSH is required
ManageSSH() {
    read -p "Is SSH a critical service? (y/n): " response
    if [[ "$response" == "y" ]]; then
        echo "Installing SSH..."
        apt-get install -y ssh openssh-server &
    elif [[ "$response" == "n" ]]; then
        echo "Removing SSH..."
        apt-get autoremove --purge -y ssh openssh-server &
    else
        echo "Invalid input. Please enter 'y' or 'n'."
    fi
}

# Installs ufw and makes sure the rest of the script can run
sudo apt-get install ufw dbus-x11 libpam-cracklib -y

# Removes unwanted services
RemoveServices() {
    echo "Removing unwanted services..."
    for service in nginx aisleriot netcat netcat-openbsd netcat-traditional ncat pnetcat socat sock sbd hydra hydra-gtk john john-data aircrack-ng fcrackzip lcrack ophcrack ophcrack-cli pdfcrack pyrit rarcrack sipcrack irpas wireshark samba*; do
        systemctl stop $service || true
        systemctl disable $service || true
        apt-get purge -y "$service" || true
    done
    echo "Unwanted services removed."
}

# Updates packages and services
RunUpdates() {
    echo "Running updates..."
    for updatesetting in update dist-upgrade upgrade "install -f" autoremove autoclean check; do
        apt-get $updatesetting -y || true
    done
    sudo apt-get autoremove
    echo "System has been updated."
}

# Installs useful programs
InstallPrograms() {
    echo "Installing programs..."
    for program in chkrootkit clamav rkhunter apparmor apparmor-profiles; do
        apt-get install $program -y || true
    done
    echo "Necessary programs installed."
}

# Scans for viruses
VirusScan() {
    chkrootkit -q
    rkhunter --update
    rkhunter --propupd
    echo | rkhunter -c --enable all --disable none

    systemctl stop clamav-freshclam
    freshclam --stdout
    systemctl start clamav-freshclam
    clamscan -r -i --stdout --exclude-dir="^/sys" /
}

# Function to ask end user if they want to add a user to a group
GroupUsers() {
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
ProhibitedMedia() {
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

# Configures Apache
apacheSettings() {
    read -p "Is Apache2 a critical service? (y/n): " response

    if [[ "$response" == "y" ]]; then
        echo "Installing Apache2..."
        apt install -y apache2
    elif [[ "$response" == "n" ]]; then
        echo "Removing Apache2..."
        apt autoremove --purge -y apache2
    else 
        echo "Invalid Input"
    fi
    # backup security.conf file
    sudo cp /etc/apache2/conf-enabled/security.conf /etc/apache2/conf-enabled/security.conf.bak

    # VVVV Fucks up apache for wtv reason
    #echo "Disabling X-Powered-By header..." # for apache
    #sudo echo "Header unset X-Powered-By" >> /etc/apache2/conf-enabled/security.conf

    echo "Disabling Server header..."
    sudo echo "ServerTokens Prod" >> /etc/apache2/conf-enabled/security.conf
    sudo echo "ServerSignature Off" >> /etc/apache2/conf-enabled/security.conf

    sudo systemctl restart apache2
}

# Configures UFW
UFWSettings() {
    ufw disable
    ufw enable

    if dpkg -l | grep -q apache2; then
        echo "Apache is installed. Configuring UFW to "Apache Secure" profile..."
        sudo ufw allow "Apache Secure"
    else
        echo "Apache is not installed. No changes made to UFW"
    fi

    read -p "Are there any ports that need to be allowed? (y/n): " allow_response

    if [[ "$allow_response" == "y" ]]; then
        read -p "What ports need to be allowed? (seperate by spaces): " allowed
        ufw allow "$allowed"
    fi

    read -p "Are there any ports that need to be denied? (y/n): " deny_response

    if [[ "$deny_response" == "y" ]]; then
        read -p "What ports need to be denied? (seperate by spaces): " denied
        ufw deny "$denied"
    fi

    ufw logging high
    ufw status verbose
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

# Secures login attempts through PAM
LockoutPolicy() {
    touch /usr/share/pam-configs/faillock
    LINES1=(
        "Name: Enforce failed login attempt counter"
        "Default: no"
        "Priority: 0"
        "Auth-Type: Primary"
        "Auth:"
        "[default=die] pam_faillock.so authfail"
        "sufficient pam_faillock.so authsucc"
    )

    for LINE1 in "${LINES1[@]}"; do
        if ! grep -Fxq "$LINE1" "/usr/share/pam-configs/faillock"; then
            echo "$LINE1" | tee -a "/usr/share/pam-configs/faillock" > /dev/null
            echo "Added to faillock: $LINE1"
        else
            echo "Already exists in faillock: $LINE1"
        fi
    done

    # Ensure faillock_notify file exists and add notification configuration
    touch /usr/share/pam-configs/faillock_notify
    LINES2=(
        "Name: Notify on failed login attempts"
        "Default: no"
        "Priority: 1024"
        "Auth-Type: Primary"
        "Auth:"
        "requisite pam_faillock.so preauth"
    )

    for LINE2 in "${LINES2[@]}"; do
        if ! grep -Fxq "$LINE2" "/usr/share/pam-configs/faillock_notify"; then
            echo "$LINE2" | sudo tee -a "/usr/share/pam-configs/faillock_notify" > /dev/null
            echo "Added to faillock_notify: $LINE2"
        else
            echo "Already exists in faillock_notify: $LINE2"
        fi
    done

    pam-auth-update
}

# Asks if FTP is required
FTPcheck() {
    read -p "Do you need FTP to stay enabled? (Y/n): " response
    if [[ "$response" == "y" ]]; then

        echo "Installing and enabling FTP..."
        apt install vsftpd -y
        systemctl enable --now vsftpd

        echo "Confirming anonymous FTP is disabled..."
        if id "ftp" &>/dev/null; then
            echo "User 'ftp' found. Deleting user..."

            # Delete the user 'ftp' and remove their home directory and mail spool
            sudo userdel -r ftp

            if [[ $? -eq 0 ]]; then
                echo "User 'ftp' has been successfully deleted."
            else
                echo "An error occurred while trying to delete the user 'ftp'."
            fi
        else
            echo "User 'ftp' does not exist."
        fi

    elif [[ "$response" == "n" ]]; then

        echo "Removing and disabling FTP"
        apt autoremove --purge -y vsftpd
        systemctl disable --now vsftpd
    else 
        echo "Invalid Input"
    fi
}

# Configures anything IPv4/v6 related
configIP() {
    # Asks about enabling IPv4 IP forwarding
    read -p "Would you like to disable IPv4 IP forwarding? (Y/n): " IPforwardResponse
    if [[ "$IPforwardResponse" == "y" ]]; then
        echo "Disabling IPv4 IP forwarding.."
        sed -i 's/net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/g' /etc/sysctl.conf
    else
        echo "Continuing..."
    fi

    # Asks about IPv4 TCP SYN cookies
    read -p "Would you like to enable IPv4 TCP SYN cookies? (Y/n): " TCPSYNresponse
    if [[ "$TCPSYNresponse" == "y" ]]; then
        echo "Enabling TCP SYN cookies for IPv4..."
        sed -i 's/net.ipv4.tcp_syncookies=0/net.ipv4.tcp_syncookies=1/g' /etc/sysctl.conf
    else
        echo "Continuing..."
    fi
    
    # Asks about disabling IPv6
    read -p "Would you like to disable IPv6? (Y/n): " disableIPv6response
    if [[ "$disableIPv6response" == "y" ]]; then
        echo "Disabling IPv6..."
        sysctl -w net.ipv6.conf.all.disable_ipv6=1
        sysctl -w net.ipv6.conf.default.disable_ipv6=1
        sysctl -w net.ipv6.conf.lo.disable_ipv6=1
        sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
        sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
        sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
        sysctl -p
        # Update GRUB to disable IPv6 at boot
        echo "Updating GRUB configuration..."
        sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"/' /etc/default/grub
        update-grub
        echo "IPv6 has been disabled. A system reboot is required to fully apply the changes."
    else
        echo "Continuing..."
    fi

    # Enables IPv4 time-wait assassination protection (???)
    echo "Applying IPv4 TIME-WAIT ASSASSINATION protection fix..."

    sysctl -w net.ipv4.tcp.rfc1337=1

    if ! grep -q "net.ipv4.tcp_rfc1337=1" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.conf
        echo "Added net.ipv4.tcp_rfc1337=1 to /etc/sysctl.conf"
    fi

    current_value=$(sysctl net.ipv4.tcp_fin_timeout | awk '{print $3}')

    if [ "$current_value" -eq 30 ]; then
        echo "TCP FIN timeout is already set to 30 seconds. No changes needed."
    else
        # Apply the new TCP FIN timeout setting
        echo "Setting net.ipv4.tcp_fin_timeout to 30 seconds..."
        sudo sysctl -w net.ipv4.tcp_fin_timeout=30
        
        # Make the change persistent across reboots
        echo "Making the change persistent across reboots..."
        echo "net.ipv4.tcp_fin_timeout = 30" | sudo tee -a /etc/sysctl.conf > /dev/null
        sudo sysctl -p
        
        echo "IPv4 TIME-WAIT ASSASSINATION protection has been enabled."
    fi

    sysctl -p
}

# Disable source routing
sourceRouting() {
    echo "Disabling source routing at runtime..."
    sysctl -w net.ipv4.conf.all.accept_source_route=0
    sysctl -w net.ipv4.conf.default.accept_source_route=0
    sysctl -w net.ipv6.conf.all.accept_source_route=0
    sysctl -w net.ipv6.conf.default.accept_source_route=0

    # Remove any existing source routing settings to avoid duplicates
    sed -i '/net.ipv4.conf.all.accept_source_route/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.default.accept_source_route/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.all.accept_source_route/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.accept_source_route/d' /etc/sysctl.conf

    # Append new source routing settings
    echo "# Disable source routing" >> /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
}

# Set password encryption to SHA512
passwordEncrypt() {
    echo "Configuring password encryption to use SHA-512..."

    # Creates backup file
    cp /etc/login.defs /etc/login.defs.bak

    # Update or add the ENCRYPT_METHOD setting
    if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
        echo "Updating existing ENCRYPT_METHOD to SHA512..."
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    else
        echo "Adding ENCRYPT_METHOD SHA512 to /etc/login.defs..."
        echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
    fi

    echo "Password encryption is now set to SHA-512."
}

# Enables dictionary and username checks for password
passwordSecurity() {
    echo "Enabling password dictionary check and username check..."

    # Backup the original configuration file
    if [ -f /etc/security/pwquality.conf ]; then
        echo "Creating a backup of the original /etc/security/pwquality.conf file..."
        cp /etc/security/pwquality.conf /etc/security/pwquality.conf.bak
    else
        echo "/etc/security/pwquality.conf does not exist. Creating it..."
        touch /etc/security/pwquality.conf
    fi

    # Enable dictionary check
    if grep -q "^dictcheck" /etc/security/pwquality.conf; then
        echo "Updating dictionary check setting..."
        sed -i 's/^dictcheck.*/dictcheck=1/' /etc/security/pwquality.conf
    else
        echo "Adding dictionary check setting..."
        echo "dictcheck=1" >> /etc/security/pwquality.conf
    fi

    # Enable username check
    if grep -q "^usercheck" /etc/security/pwquality.conf; then
        echo "Updating username check setting..."
        sed -i 's/^usercheck.*/usercheck=1/' /etc/security/pwquality.conf
    else
        echo "Adding username check setting..."
        echo "usercheck=1" >> /etc/security/pwquality.conf
    fi

    # Ensure PAM is configured to use pam_pwquality
    if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        echo "Configuring PAM to use pam_pwquality..."
        echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password
    else
        echo "PAM is already configured to use pam_pwquality."
    fi

    echo "Password dictionary and username checks have been enabled."
}

# Configures screen timeout policy to 5 minutes
# Enabled automatic screen lock
screenTimeout() {
    echo "Configuring screen timeout..."
    gsettings set org.gnome.desktop.session idle-delay 300
    echo "Screen timeout set successfully."

    echo "Enabling automatic screen lock"
    gsettings set org.gnome.desktop.screensaver lock-enabled true
    gsettings set org.gnome.desktop.screensaver lock-delay 0
    echo "Automatic screen lock enabled"
}

# Stops and disables NFS
stopNFS() {
    echo "Stopping NFS-related services..."
    sudo systemctl stop nfs-server
    sudo systemctl stop nfs-client.target
    sudo systemctl stop rpcbind
    sudo systemctl stop nfs-idmapd
    sudo systemctl stop nfs-blkmap
    sudo systemctl stop nfsdcld
    sudo systemctl stop nfs-kernel-server

    sudo systemctl disable nfs-server
    sudo systemctl disable nfs-client.target
    sudo systemctl disable rpcbind
    sudo systemctl disable nfs-idmapd
    sudo systemctl disable nfs-blkmap
    sudo systemctl disable nfsdcld
    sudo systemctl disable nfs-kernel-server

    sudo umount -a -t nfs,nfs4
    echo "NFS and its related services have been disabled."
}

# Enables ASLR (Address Space Layout Randomization)
enableASLR() {
    echo "Enablng ASLR..."
    
    echo 2 > /proc/sys/kernel/randomize_va_space
    
    if ! grep -q "^kernel.randomize_va_space" /etc/sysctl.conf; then
        echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    else
        sed -i 's/^kernel\.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
    fi

    sysctl -p

    echo "ASLR is now enabled."
}

groupDisableSSH() {
    read -p "Enter the group name to disable SSH access: " GROUP_NAME

    if [ -z "$GROUP_NAME" ]; then
        echo "Group name cannot be empty. Exiting."
        exit 1
    fi

    if [ ! -f "/etc/ssh/sshd_config" ]; then
        echo "Backing up config file to .bak"
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    else
        echo "Backup file already exists. Skipping backup"
    fi

    if grep -q "^Match Group $GROUP_NAME" "$SSH_CONFIG_FILE"; then
        echo "SSH access is already restricted for the group $GROUP_NAME."
    else
        echo "Restricting SSH access for the group $GROUP_NAME."
        echo "\nMatch Group $GROUP_NAME\n  DenyUsers *@*" >> "$SSH_CONFIG_FILE"
    fi

    systemctl restart ssh
}

# // UBUNTU ONLY // Set update interval to daily
sudo echo 'APT::Periodic::Update-Package-Lists "1";' > "/etc/apt/apt.conf.d/10periodic"
sudo echo 'APT::Periodic::Download-Upgradeable-Packages "1";' >> "/etc/apt/apt.conf.d/10periodic"
sudo echo 'APT::Periodic::AutocleanInterval "7";' >> "/etc/apt/apt.conf.d/10periodic"

# Secures password policy
# Disables root login
# Makes null passwords not authenticate
ManageSSH # Run ManageSSH first due to conflict with the last sed command
sudo sed -i 's/nullok/ /g' /etc/pam.d/common-auth
sudo sed -i '/pam_unix.so/ s/$/ minlen=8 remember=5/' /etc/pam.d/common-password
sudo sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS    90/' /etc/login.defs
sudo sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS    7/' /etc/login.defs
sudo sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE    14/' /etc/login.defs
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sudo systemctl reload ssh

# Lock root account
sudo passwd -l root

# Perms for shadow file
sudo chmod 640 /etc/shadow

# Makes sure syslog is running
sudo systemctl enable rsyslog
sudo systemctl start rsyslog

# Runs the functions
passwordEncrypt
sourceRouting
passwordSecurity 
screenTimeout 
stopNFS
enableASLR
#libFiles  ------ need to figure out
export -f apacheSettings
export -f RemoveServices
export -f InstallPrograms
export -f RunUpdates
export -f VirusScan
export -f FTPcheck
export -f UFWSettings
gnome-terminal -- bash -c "apacheSettings; UFWSettings; FTPcheck; RemoveServices; InstallPrograms; RunUpdates; VirusScan; exec bash"
export -f GroupUsers
gnome-terminal -- bash -c "GroupUsers"
export -f ProhibitedMedia
gnome-terminal -- bash -c "ProhibitedMedia"
export -f secureUsers
export -f configIP
gnome-terminal -- bash -c "secureUsers; configIP"
export -f LockoutPolicy
gnome-terminal -- bash -c "LockoutPolicy"

# Secure the /lib folder
#libFiles() {
#    echo "Deleting all hidden files in the /lib folders..."
#    sudo find /lib* -type f -name ".*" -exec rm -f {} \;
#    echo "All hidden files in the /lib folders have been deleted."
#}
