# 🔒 Debian Harden

Automated hardening script for Debian (headless setup), focused on maximum security, privacy, and full control.

## 🚀 What this script does

- Updates and upgrades the system
- Enables AppArmor and Fail2Ban
- Configures firewall rules with UFW
- Hardens SSH (disables root login and password auth)
- Applies secure sysctl rules
- Initializes AIDE for file integrity monitoring
- Installs essential hardening tools: `firejail`, `unattended-upgrades`, and more

## 📦 Requirements

- Debian 12 or newer (Stable branch)
- Internet connection
- Must be run as `root`

## ⚙️ How to use

1. Clone the repository:
   ```bash
   git clone https://github.com/Cemeru/debian-harden.git
   cd debian-harden/scripts
   chmod +x debian-harden-full.sh
   sudo ./debian-harden-full.sh
   sudo reboot

