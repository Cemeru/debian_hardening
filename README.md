# Debian Hardening Script

**Author:** Cemeru  
**Version:** 2.0
**Date:** 2025-07-21  
**Target OS:** Debian 12 (clean instance)  
**License:** MIT

---

## 📌 Purpose

This script performs automated and comprehensive security hardening on a clean Debian 12 system. It configures firewall rules, disables insecure services, applies system-level protections, installs monitoring and auditing tools, and reinforces SSH and kernel settings — all while logging every action and maintaining idempotency.

---

## 🚀 Features

- Root access and OS checks before execution
- Internet connectivity validation
- Secure backup of modified configuration files
- System update and upgrade
- Installation of key security packages:
  - UFW (firewall)
  - Fail2Ban (brute-force protection)
  - AppArmor (mandatory access control)
  - AIDE (file integrity monitoring)
  - Auditd (system audit logging)
- SSH hardening:
  - Disables root login
  - Disables password authentication
- Kernel-level sysctl hardening
- Permission tightening on sensitive files
- Legal access banners (`/etc/issue` and `issue.net`)
- Logging system:
  - Color-coded console output
  - Persistent log in `/var/log/debian-harden.log`
  - Log rotation configured via `logrotate`
- Final security report saved to `/root/hardening_report.txt`
- SHA-256 checksum of the script saved to `/root/hardening_script.sha256`

---

## ⚠️ Warnings

- **SSH Access Risk:** The script disables root login and password authentication for SSH. Make sure your SSH public key is added to `/root/.ssh/authorized_keys` before running it — or you might lose access to the server.
- **Internet Required:** The system must have access to the internet to update and install packages.
- **AppArmor Support:** Ensure the kernel supports AppArmor and it's enabled in GRUB.

---

## 🛠 Requirements

- Debian 12 (clean install)
- Root privileges
- Internet access

---

## 🧪 How to Use

```bash
chmod +x debian-hardening.sh
sudo ./debian-hardening.sh
```

---

## 🔒 Disclaimer
This script is provided as-is. Use it at your own risk. Always test in a non-production environment before deployment to critical infrastructure.
