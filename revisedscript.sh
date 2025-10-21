#!/bin/bash

# LAST UPDATED: Nov 14, 2024

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

X2GOserver() {
    read -p "Do you need X2GO Server? (y/n): " response
    if [[ "$response" == "y" ]]; then
        echo "Installing X2GO..."
        apt-get install -y x2goserver &
    elif [[ "$response" == "n" ]]; then
        echo "Continuing..."
    else
        echo "Invalid input. Please enter 'y' or 'n'."
    fi
}

export -f ManageSSH
export -f X2GOserver
gnome-terminal -- bash -c "ManageSSH; X2GOserver; exec bash"

sudo apt-get install ufw dbus-x11 -y 

# remove bad services
RemoveServices() {
    echo "Removing unwanted services..."
    for service in nginx aisleriot netcat netcat-openbsd netcat-traditional ncat pnetcat socat sock sbd hydra hydra-gtk john john-data aircrack-ng fcrackzip lcrack ophcrack ophcrack-cli pdfcrack pyrit rarcrack sipcrack irpas apache2 wireshark; do
        systemctl stop $service || true
        systemctl disable $service || true
        apt-get purge -y "$service" || true
    done
    echo "Unwanted services removed."
}

# runs updates
RunUpdates() {
    echo "Running updates..."
    for updatesetting in update dist-upgrade upgrade "install -f" autoremove autoclean check; do
        apt-get $updatesetting -y || true
    done
    echo "System has been updated."
}

# install programs
InstallPrograms() {
    echo "Installing programs..."
    for program in chkrootkit clamav rkhunter apparmor apparmor-profiles; do
        apt-get install $program -y || true
    done
    echo "Necessary programs installed."
}


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

export -f RemoveServices
export -f InstallPrograms
export -f RunUpdates
export -f VirusScan
gnome-terminal -- bash -c "RemoveServices; InstallPrograms; RunUpdates; VirusScan; exec bash"

# disable guest user if lightdm is being used
DisableLightDMGuest() {
    read -p "Is LightDM being used? (y/n): " response
    if [[ "$response" == "y" ]]; then
        echo "Disabling guest user..."
        sed -i 'aallow-guest=false' /etc/lightdm/lightdm.conf
        restart lightdm
    elif [[ "$response" == "n" ]]; then
        echo "Continuing..."
    else
        echo "Invalid input. Please enter 'y' or 'n'."
    fi
}

# add users to groups
GroupUsers() {
    # Ask if a user needs to be added to a group
    read -p "Do you need to add a user to a group? (y/n): " response

    # Convert response to lowercase
    response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

    if [[ "$response" == "y" ]]; then
        # Prompt for the username
        read -p "Enter the username to add: " username

        # Prompt for the group name
        read -p "Enter the group name: " group

        # Check if the group exists
        if getent group "$group" > /dev/null; then
            # Add the user to the group
            sudo usermod -aG "$group" "$username"
            echo "User $username has been added to the group $group."
        else
            echo "Group $group does not exist. Please create it first."
        fi
    else
        echo "No user will be added to any group."
    fi
}

# removes prohibited media
ProhibitedMedia() {
    read -p "Are there any prohibited files that you need listed? (y/n): " response

    if [[ "$response" == "y" ]]; then
        read -p "Enter the file extension to search for (e.g., .mp3): " extension
        
        echo "Listing all files with extension $extension in the / directory:"
        sudo find / -type f -name "*$extension" 2>/dev/null
    fi

    read -p "Would you like to find any other files to list before proceeding to delete? (y/n): " additional_files

    if [[ "$additional_files" == "y" ]]; then
        read -p "Enter the file extension to search for (e.g., .txt): " additional_extension
        
        echo "Listing all files with extension $additional_extension in the / directory:"
        sudo find / -type f -name "*$additional_extension" 2>/dev/null
    fi

    echo "Deleting prohibited files..."

    root_extensions=("*.mp3" "*.mov" "*.mp4" "*.avi" "*.mpg" "*.mpeg" "*.flac" "*.m4a" "*.flv" "*.ogg")
    home_extensions=("*.gif" "*.png" "*.jpg" "*.jpeg")

    for ext in "${root_extensions[@]}"; do
        sudo find / -type f -name "$ext" -exec rm -f {} \; 2>/dev/null
    done

    for ext in "${home_extensions[@]}"; do
        sudo find /home -type f -name "$ext" -exec rm -f {} \; 2>/dev/null
    done

    echo "Prohibited files deleted."
}

UFWSettings() {
    ufw disable
    ufw enable

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

# runs previous funcs in new terminal window
export -f UFWSettings
export -f ProhibitedMedia
export -f GroupUsers
export -f DisableLightDMGuest
gnome-terminal -- bash -c "DisableLightDMGuest; GroupUsers; UFWSettings; ProhibitedMedia; exec bash"

RemoveUnauthUsers() {
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
        if [[ ! " ${authorized_users[*]} " =~ " $user " ]]; then
            echo "Deleting user: $user"
            userdel -r "$user"
        fi
    done
}
RemoveUnauthUsers

AdminMGT() {
    echo -e "Deleting non listed accounts$"
    # Check if admins.txt exists
    if [ ! -f "admins.txt" ]; then
        touch admins.txt
        nano admins.txt
        echo "Resuming script after saving admins.txt..."
    fi

    while IFS= read -r user; do
        # Check if the user exists on the system
        if id "$user" &>/dev/null; then
            # Remove the user from the "sudo" group
            sudo deluser "$user" sudo
            echo "Removed $user from the sudo group."
        else
            echo "User $user does not exist on the system."
        fi
    done < "admins.txt"
}
AdminMGT

InsecureAdmins() {
    # Ask the user for a list of admin users with insecure passwords
    echo "Enter the usernames of admin users with insecure passwords (space-separated):"
    read -a users

    # Loop through each username
    for user in "${users[@]}"
    do
        # Check if the user exists
        if id "$user" &>/dev/null; then
            # Check if the user is an admin (part of the 'sudo' group)
            if groups "$user" | grep -qw "sudo"; then
                echo "Updating password for admin user: $user"
                # Change the user's password
                echo "$user:Cyb3rPatr!0ts!" | sudo chpasswd
                echo "Password updated for $user."
            else
                echo "User $user is not an admin, skipping."
            fi
        else
            echo "User $user does not exist, skipping."
        fi
    done
}
InsecureAdmins

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

#run LockoutPolicy in new terminal window
export -f LockoutPolicy
gnome-terminal -- bash -c "LockoutPolicy"

# Set update interval to daily
sudo echo 'APT::Periodic::Update-Package-Lists "1";' > "/etc/apt/apt.conf.d/10periodic"
sudo echo 'APT::Periodic::Download-Upgradeable-Packages "1";' >> "/etc/apt/apt.conf.d/10periodic"
sudo echo 'APT::Periodic::AutocleanInterval "7";' >> "/etc/apt/apt.conf.d/10periodic"

# enforce most password security shits
sed -i 's/nullok/ /g' /etc/pam.d/common-auth
sed -i '/pam_unix.so/ s/$/ minlen=8 remember=5/' /etc/pam.d/common-password
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS    90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS    7/' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE    14/' /etc/login.defs
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
systemctl reload ssh

# Perms for shadow file
chmod 640 /etc/shadow

# disable ftp
systemctl disable --now vsftpd
# makes sure syslog is running
systemctl enable rsyslog
systemctl start rsyslog

# disables ipv4 forwarding and enables ipv4 tcp syn cookies
cd /etc
sed -i 's/net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/g' sysctl.conf
sed -i 's/net.ipv4.tcp_syncookies=0/net.ipv4.tcp_syncookies=1/g' sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" > /sysctl.d/50-net-stack.conf
sysctl --system
cd ~
