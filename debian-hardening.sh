#!/bin/bash

# ───────────────────────────────────────────────────────────
# Script: debian-hardening.sh
# Purpose: Debian 12 hardening automation
# Author: Cemeru
# Version: 1.3
# Date: 2025-07-21
# ───────────────────────────────────────────────────────────

set -euo pipefail

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
    if ! ping -c1 8.8.8.8 >/dev/null 2>&1; then
        log_message "ERROR" "No internet connection detected."
        exit 1
    fi
}

update_system() {
    log_message "INFO" "Updating system packages..."
    apt-get update && apt-get upgrade -y
}

install_packages() {
    log_message "INFO" "Installing required packages..."
    local packages=(ufw fail2ban apparmor apparmor-profiles apparmor-utils aide auditd cron logrotate)

    for pkg in "${packages[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            apt-get install -y "$pkg"
        else
            log_message "INFO" "Package $pkg already installed."
        fi
    done
}

configure_firewall() {
    log_message "INFO" "Configuring UFW firewall..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
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
    if ! command -v aideinit &>/dev/null; then
        log_message "WARN" "aideinit command not found, skipping AIDE initialization."
        return
    fi
    
    if [ ! -f /var/lib/aide/aide.db ]; then
        aide --init
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        log_message "INFO" "AIDE initialized."
    else
        log_message "INFO" "AIDE already initialized. Skipping."
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").bak"
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
    )

    for key in "${!sysctl_settings[@]}"; do
        sed -i "/^$key\s*=.*/d" /etc/sysctl.conf
        echo "$key = ${sysctl_settings[$key]}" >> /etc/sysctl.conf
    done

    sysctl -p
}

safe_sshd_config_update() {
    local key="$1"
    local value="$2"
    
    if grep -Eq "^\s*#?\s*$key\s+$value" /etc/ssh/sshd_config; then
        log_message "INFO" "$key already set to $value"
    else
        if grep -q "^\s*#?\s*$key" /etc/ssh/sshd_config; then
            sed -i -E "s|^\s*#?\s*${key}\s+.*|${key} ${value}|" /etc/ssh/sshd_config
        else
            echo "${key} ${value}" >> /etc/ssh/sshd_config
        fi
    fi
}


harden_ssh() {
    log_message "INFO" "Hardening SSH configuration..."
    backup_file /etc/ssh/sshd_config

    safe_sshd_config_update "Port" "22"
    safe_sshd_config_update "PermitRootLogin" "no"
    safe_sshd_config_update "PasswordAuthentication" "no"

    if systemctl is-active sshd &>/dev/null; then
        systemctl restart sshd
    else
        systemctl restart ssh
    fi
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

generate_security_report() {
    log_message "INFO" "Generating final security report..."
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    echo "Security hardening completed on $timestamp" > /root/hardening_report.txt
    echo "------------------------------------------" >> /root/hardening_report.txt
    echo "Firewall status:" >> /root/hardening_report.txt
    ufw status verbose >> /root/hardening_report.txt
    echo "" >> /root/hardening_report.txt
    echo "AppArmor status:" >> /root/hardening_report.txt

    if command -v aa-status &>/dev/null; then
        aa-status >> /root/hardening_report.txt
    else
        echo "aa-status not available" >> /root/hardening_report.txt
    fi

    
    echo "" >> /root/hardening_report.txt
    echo "AIDE database location: /var/lib/aide/aide.db" >> /root/hardening_report.txt
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
    for svc in ufw apparmor fail2ban auditd; do
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
    harden_ssh
    set_permissions
    enable_auditd
    set_login_banner
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
