#!/bin/bash

# ───────────────────────────────────────────────────────────
# Script: debian-hardening.sh
# Purpose: Debian 12 hardening automation with improved security and user prompts.
# Author: Cemeru
# Version: 2.0
# Date: 2025-07-21
# ───────────────────────────────────────────────────────────

set -euo pipefail

# -----------------------------------------------------------
# USER CONFIGURABLE VARIABLES
# -----------------------------------------------------------
# Set your desired SSH port. Default is 22.
SSH_PORT="22"

# Set to "yes" to disable root login via SSH, or "no" to allow it.
DISABLE_ROOT_LOGIN="yes"

# Set to "yes" to disable password authentication for SSH, or "no" to allow it.
# WARNING: Ensure you have a working SSH key pair before enabling this!
DISABLE_SSH_PASSWORD_AUTH="yes"

# Add any additional TCP ports you need to allow through the firewall (e.g., 80, 443, 8080).
# The script will automatically add SSH_PORT and deny all other incoming traffic.
ALLOWED_TCP_PORTS=(80 443)

# Add users that should be allowed to log in via SSH. Separate with spaces.
# Example: ALLOW_SSH_USERS=("user1" "admin_user")
ALLOW_SSH_USERS=()

SCRIPT_NAME=$(basename "$0")
LOG_FILE="/var/log/debian-harden.log"
BACKUP_DIR="/var/backups/debian-harden"
mkdir -p "$BACKUP_DIR"

handle_error() {
    local line="$1"
    local err="$2"
    log_message "ERROR" "Script failed at line $line with exit code $err."
    exit $err
}

trap 'handle_error ${LINENO} $?' ERR

log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local color_reset="\e[0m"
    local color_info="\e[32m"
    local color_warn="\e[33m"
    local color_error="\e[31m"

    case "$level" in
        INFO) echo -e "${color_info}[$timestamp] [$level] $message${color_reset}" ;;
        WARN) echo -e "${color_warn}[$timestamp] [$level] $message${color_reset}" ;;
        ERROR) echo -e "${color_error}[$timestamp] [$level] $message${color_reset}" ;;
        *) echo "[$timestamp] [$level] $message" ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log_message "ERROR" "This script must be run as root."
        exit 1
    fi
}

check_os() {
    if ! grep -qi "debian" /etc/os-release; then
        log_message "ERROR" "This script is intended for Debian systems only."
        exit 1
    fi
}

check_internet() {
    log_message "INFO" "Checking for internet connection..."
    if ! ping -c1 8.8.8.8 >/dev/null 2>&1; then
        log_message "ERROR" "No internet connection detected."
        exit 1
    fi
}

update_system() {
    log_message "INFO" "Updating system packages..."
    if apt-get update && apt-get upgrade -y; then
        log_message "INFO" "System packages updated successfully."
    else
        log_message "ERROR" "System update failed."
        exit 1
    fi
}

install_packages() {
    log_message "INFO" "Installing required packages..."
    local packages=(ufw fail2ban apparmor apparmor-profiles apparmor-utils aide auditd cron logrotate libpam-pwquality)
    local packages_to_install=()

    for pkg in "${packages[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            packages_to_install+=("$pkg")
        fi
    done

    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        apt-get install -y "${packages_to_install[@]}"
        log_message "INFO" "Installed: ${packages_to_install[*]}"
    else
        log_message "INFO" "All required packages are already installed."
    fi
}

configure_firewall() {
    log_message "INFO" "Configuring UFW firewall..."
    if ufw status | grep -q "Status: active"; then
        log_message "WARN" "UFW is already active. Rules will be reloaded."
    else
        ufw --force enable
    fi
    ufw --force reset # Reset to clean slate
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$SSH_PORT"/tcp
    log_message "INFO" "Allowing SSH traffic on port $SSH_PORT"

    for port in "${ALLOWED_TCP_PORTS[@]}"; do
        ufw allow "$port"/tcp
        log_message "INFO" "Allowing additional TCP port: $port"
    done

    ufw --force enable
}

configure_apparmor() {
    log_message "INFO" "Enabling AppArmor..."
    systemctl enable apparmor --now
}

configure_fail2ban() {
    log_message "INFO" "Configuring Fail2Ban..."
    systemctl enable fail2ban --now
}

configure_aide() {
    log_message "INFO" "Initializing AIDE..."
    if [ ! -f /var/lib/aide/aide.db ]; then
        log_message "INFO" "AIDE database not found. Initializing..."
        aide --init
        if [ $? -eq 0 ]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            log_message "INFO" "AIDE initialized successfully."
        else
            log_message "ERROR" "AIDE initialization failed. Please check manually."
            return
        fi
    else
        log_message "INFO" "AIDE already initialized. Skipping."
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").bak-$(date +%Y%m%d%H%M%S)"
        log_message "INFO" "Backed up $file to $BACKUP_DIR/$(basename "$file").bak-$(date +%Y%m%d%H%M%S)"
    fi
}

harden_sysctl() {
    log_message "INFO" "Hardening kernel parameters..."
    backup_file /etc/sysctl.conf

    declare -A sysctl_settings=(
        ["net.ipv4.ip_forward"]=0
        ["net.ipv4.conf.all.accept_redirects"]=0
        ["net.ipv4.conf.all.send_redirects"]=0
        ["net.ipv4.conf.all.accept_source_route"]=0
        ["net.ipv4.conf.all.log_martians"]=1
        ["net.ipv4.conf.default.rp_filter"]=1
        ["net.ipv4.tcp_syncookies"]=1
        ["kernel.randomize_va_space"]=2
        ["fs.suid_dumpable"]=0
    )

    for key in "${!sysctl_settings[@]}"; do
        sed -i "/^#?\s*$key\s*=.*/d" /etc/sysctl.conf
        echo "$key = ${sysctl_settings[$key]}" >> /etc/sysctl.conf
    done

    sysctl -p
    log_message "INFO" "Kernel parameters updated and reloaded."
}

safe_sshd_config_update() {
    local key="$1"
    local value="$2"
    
    if grep -Eq "^\s*#?\s*$key\s+$value" /etc/ssh/sshd_config; then
        log_message "INFO" "$key is already set to the desired value: $value"
    else
        if grep -q "^\s*#?\s*$key" /etc/ssh/sshd_config; then
            sed -i -E "s|^\s*#?\s*${key}\s+.*|${key} ${value}|" /etc/ssh/sshd_config
            log_message "INFO" "Updated $key to $value"
        else
            echo "${key} ${value}" >> /etc/ssh/sshd_config
            log_message "INFO" "Added $key with value $value"
        fi
    fi
}

harden_ssh() {
    log_message "INFO" "Hardening SSH configuration..."
    backup_file /etc/ssh/sshd_config

    if [[ "$DISABLE_ROOT_LOGIN" == "yes" ]]; then
        read -p "WARNING: You are about to disable root login. Do you want to continue? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            safe_sshd_config_update "PermitRootLogin" "no"
        else
            log_message "WARN" "Root login will not be disabled."
        fi
    fi

    if [[ "$DISABLE_SSH_PASSWORD_AUTH" == "yes" ]]; then
        read -p "WARNING: You are about to disable password authentication. ENSURE you have a working SSH key pair. Continue? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            safe_sshd_config_update "PasswordAuthentication" "no"
        else
            log_message "WARN" "Password authentication will not be disabled."
        fi
    fi

    safe_sshd_config_update "Port" "$SSH_PORT"
    safe_sshd_config_update "X11Forwarding" "no"
    safe_sshd_config_update "MaxAuthTries" "3"
    safe_sshd_config_update "ClientAliveInterval" "300"
    safe_sshd_config_update "ClientAliveCountMax" "0"

    if [[ ${#ALLOW_SSH_USERS[@]} -gt 0 ]]; then
        local user_list="${ALLOW_SSH_USERS[*]}"
        safe_sshd_config_update "AllowUsers" "$user_list"
    else
        log_message "WARN" "No specific users were configured for SSH access. All users in the 'ssh' group can still log in if 'PasswordAuthentication' is set to 'yes'."
    fi

    if systemctl is-active --quiet sshd; then
        systemctl restart sshd
    else
        systemctl restart ssh
    fi
    log_message "INFO" "SSH service restarted."
}

configure_user_security() {
    log_message "INFO" "Configuring user account security..."
    
    # Set strong password policy using libpam-pwquality
    backup_file /etc/pam.d/common-password
    sed -i '/pam_unix.so/s/ obscure/ minlen=12 remember=5 sha512/' /etc/pam.d/common-password
    sed -i '/pam_unix.so/s/retry=3//' /etc/pam.d/common-password
    sed -i '/^password\s+requisite\s+pam_pwquality.so/d' /etc/pam.d/common-password
    sed -i '/pam_pwquality.so/s/.*/password requisite pam_pwquality.so retry=3 minlen=12 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1/' /etc/pam.d/common-password
    
    # Set default umask for new users
    backup_file /etc/login.defs
    sed -i 's/UMASK\s*022/UMASK 027/' /etc/login.defs
    log_message "INFO" "Password policy updated and default umask set to 027."
}

set_permissions() {
    log_message "INFO" "Setting correct file permissions..."
    chmod 700 /root
    chmod 600 /etc/crontab
    chmod 600 /etc/ssh/sshd_config
}

enable_auditd() {
    log_message "INFO" "Enabling auditd..."
    systemctl enable auditd --now
}

set_login_banner() {
    log_message "INFO" "Setting login banner..."
    backup_file /etc/issue
    backup_file /etc/issue.net

    echo "Authorized access only. All activity may be monitored and reported." > /etc/issue
    echo "Authorized access only. All activity may be monitored and reported." > /etc/issue.net
}

configure_cron_jobs() {
    log_message "INFO" "Setting up automated cron jobs for security tasks..."
    # Cron job for AIDE integrity check, run weekly
    (crontab -l 2>/dev/null || true; echo "0 5 * * 0 /usr/bin/aide --check >> $LOG_FILE 2>&1") | crontab -
    
    # Cron job for weekly system updates
    (crontab -l | grep -q "apt-get update" || (crontab -l 2>/dev/null || true; echo "0 4 * * 1 apt-get update && apt-get upgrade -y >> $LOG_FILE 2>&1") | crontab -)
    
    log_message "INFO" "Cron jobs for AIDE and system updates added."
}

generate_security_report() {
    log_message "INFO" "Generating final security report..."
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local report_file="/root/hardening_report.txt"

    echo "Security hardening completed on $timestamp" > "$report_file"
    echo "------------------------------------------" >> "$report_file"
    echo "Firewall status:" >> "$report_file"
    ufw status verbose >> "$report_file"
    echo "" >> "$report_file"
    echo "AppArmor status:" >> "$report_file"
    if command -v aa-status &>/dev/null; then
        aa-status >> "$report_file"
    else
        echo "aa-status not available" >> "$report_file"
    fi
    echo "" >> "$report_file"
    echo "Fail2Ban status:" >> "$report_file"
    fail2ban-client status >> "$report_file"
    echo "" >> "$report_file"
    echo "AIDE database location: /var/lib/aide/aide.db" >> "$report_file"
    echo "" >> "$report_file"
    echo "Password Policy (common-password):" >> "$report_file"
    grep pam_pwquality.so /etc/pam.d/common-password >> "$report_file"
    grep UMASK /etc/login.defs >> "$report_file"
    log_message "INFO" "Security report generated at $report_file."
}

configure_logrotate() {
    log_message "INFO" "Setting up logrotate for script logs..."
    local conf="/etc/logrotate.d/debian-harden"
    cat <<EOF > "$conf"
/var/log/debian-harden.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 0640 root adm
}
EOF
}

verify_services() {
    log_message "INFO" "Verifying service statuses..."
    local services=(ufw apparmor fail2ban auditd)
    for svc in "${services[@]}"; do
        if ! systemctl is-active --quiet "$svc"; then
            log_message "ERROR" "Service $svc is not running!"
        else
            log_message "INFO" "Service $svc is active."
        fi
    done
}

verify_script_integrity() {
    log_message "INFO" "Computing script checksum..."
    sha256sum "$0" > /root/hardening_script.sha256
}


main() {
    local start_time
    start_time=$(date "+%Y-%m-%d %H:%M:%S")
    log_message "INFO" "Starting Debian 12 hardening process..."
    
    check_root
    check_os
    check_internet
    update_system
    install_packages
    configure_firewall
    configure_apparmor
    configure_fail2ban
    configure_aide
    harden_sysctl
    configure_user_security
    harden_ssh
    set_permissions
    enable_auditd
    set_login_banner
    configure_cron_jobs
    generate_security_report
    verify_services
    configure_logrotate
    verify_script_integrity
    
    local end_time
    end_time=$(date "+%Y-%m-%d %H:%M:%S")
    log_message "INFO" "Hardening completed successfully."
    log_message "INFO" "Start time: $start_time | End time: $end_time"
    log_message "INFO" "Log saved at: $LOG_FILE"
    log_message "INFO" "Security report saved at: /root/hardening_report.txt"
}

main "$@"
