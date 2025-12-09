# System Setup Scripts

Scripts for configuring RHEL/AlmaLinux systems with enterprise authentication, certificate management, and automation tools.

## Scripts

### cac-rhel-setup.sh

Installs CAC (Common Access Card) middleware and DoD root certificates on RHEL/AlmaLinux systems.

**What it does:**
- Installs OpenSC, PC/SC middleware for CAC readers
- Downloads and installs DoD PKI root certificates
- Configures system and browser trust stores
- Sets up pcscd service for smart card detection

**Requirements:**
- RHEL 8/9 or AlmaLinux
- Root access
- Internet connectivity

**Usage:**
```bash
sudo ./cac-rhel-setup.sh
```

**Post-installation:**
- Reboot system
- Insert CAC and verify with `pcsc_scan`
- Load PKCS#11 module in Firefox/Chrome: `/usr/lib64/opensc-pkcs11.so`

---

### idm-register.sh

Enrolls RHEL/AlmaLinux systems into Red Hat Identity Management (IdM/FreeIPA).

**What it does:**
- Sets system hostname
- Optionally registers with Red Hat Satellite
- Installs ipa-client packages
- Configures chrony time sync with IdM server
- Joins system to IdM realm
- Performs post-join smoke tests

**Requirements:**
- RHEL 8/9 or AlmaLinux
- Root access
- Network access to IdM server
- IdM admin credentials

**Usage:**
```bash
sudo ./idm-register.sh
```

**Interactive prompts:**
- VM FQDN
- IdM realm
- IdM server IP
- Admin principal and password
- Optional Satellite registration

---

### ansible-install.sh

Installs and configures Ansible with community collections.

**What it does:**
- Detects OS (RHEL/CentOS/Rocky/Ubuntu/Debian)
- Installs Ansible and dependencies
- Installs community.general collection
- Creates /etc/ansible/ansible.cfg with sensible defaults
- Sets up inventory directory structure

**Requirements:**
- RHEL/CentOS/Rocky/Ubuntu/Debian
- Root access
- Package manager access (dnf/yum/apt)

**Usage:**
```bash
sudo ./ansible-install.sh
```

**Post-installation:**
- Populate `/etc/ansible/inventory/ent_hosts` with your hosts
- Organize hosts into groups like [ENT1], [ENT2], etc.

---

## Common Prerequisites

All scripts require:
- Root or sudo privileges
- Basic networking (DNS resolution, internet access)
- RHEL-based system (except ansible-install.sh which supports Debian/Ubuntu)

## Logging

Most scripts create logs in `/var/log/`:
- `idm_register.log` - IdM enrollment logs

## Troubleshooting

**CAC Setup:**
- If `pcsc_scan` shows no reader, check USB connections and pcscd service
- Browser certificate issues: verify `/etc/pki/ca-trust/source/anchors/DoD_Certs.pem` exists

**IdM Registration:**
- Time sync issues: ensure chrony is syncing with IdM server
- DNS resolution: verify IdM server is reachable by IP
- Kerberos errors: check realm name matches IdM configuration

**Ansible:**
- Collection issues: manually run `ansible-galaxy collection install community.general`
- Inventory errors: ensure host file format is correct (INI or YAML)
