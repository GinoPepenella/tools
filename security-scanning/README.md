# Security Scanning Tools

Scripts for deploying and running vulnerability scanners and compliance assessment tools.

## Scripts

### acas-deploy.sh

Automated deployment of ACAS (Assured Compliance Assessment Solution) including Nessus and optionally SecurityCenter.

**What it does:**
- Registers system with Red Hat Satellite (optional)
- Joins system to IdM (optional)
- Sets up LVM volumes for /opt/sc and /opt/nessus
- Installs Java dependencies
- Configures fapolicyd in permissive mode
- Installs and configures Nessus scanner
- Optionally installs SecurityCenter
- Configures firewall ports (8834 for Nessus, 443 for SC)

**Requirements:**
- RHEL 8/9 or AlmaLinux
- Root access
- Additional disk (/dev/sdb) for storage
- ACAS RPM files:
  - acas_configure RPM
  - Nessus RPM
  - SecurityCenter RPM (if mode 1)

**Usage:**
```bash
sudo ./acas-deploy.sh
```

**Interactive prompts:**
- Scanner IP address
- Satellite server IP
- IdM server IP and credentials
- Install mode (1=SC+Nessus, 2=Nessus only)
- Paths to RPM files

**Access:**
- Nessus: `https://<scanner-ip>:8834`
- SecurityCenter: `https://<sc-fqdn>`

**Logs:**
- `/var/log/acas_deploy.log`

---

### openscap-setup.sh

Builds OpenSCAP Security Guide (ComplianceAsCode) from source and runs a sample scan.

**What it does:**
- Installs build dependencies (cmake, make, gcc, python3)
- Clones ComplianceAsCode/content repository
- Builds SCAP DataStream files
- Runs sample OpenSCAP scan for RHEL 9

**Requirements:**
- RHEL 8/9 or AlmaLinux
- Root access
- Internet connectivity (for git clone)
- ~2GB disk space

**Usage:**
```bash
sudo ./openscap-setup.sh
```

**Outputs:**
- SCAP content: `content/build/ssg-rhel9-ds.xml`
- Scan results: `content/build/rhel9-results.xml`

**Available profiles:**
- `standard` - Standard System Security Profile
- `stig` - DISA STIG for RHEL 9
- `pci-dss` - PCI-DSS compliance
- And more...

---

### run-stig-scan.sh

Interactive wrapper for running Ansible-based STIG scans using the Evaluate-STIG.yml playbook.

**What it does:**
- Prompts for target hosts/groups
- Prompts for SSH credentials
- Executes Ansible playbook to evaluate STIG compliance
- Runs with privilege escalation

**Requirements:**
- Ansible installed (use ansible-install.sh)
- `/etc/ansible/inventory/ent_hosts` populated
- `Evaluate-STIG.yml` playbook in current directory
- SSH access to target hosts

**Usage:**
```bash
./run-stig-scan.sh
```

**Interactive prompts:**
- Inventory group or host(s) (e.g., "ENT1" or "host1.mil,host2.mil")
- SSH username
- SSH password

**Note:** Assumes same password for SSH and sudo.

---

## Workflow Example

1. **Initial Setup:**
   ```bash
   # Install Ansible
   sudo ../system-setup/ansible-install.sh

   # Build OpenSCAP content
   sudo ./openscap-setup.sh
   ```

2. **Deploy Scanner:**
   ```bash
   # Deploy ACAS/Nessus
   sudo ./acas-deploy.sh
   ```

3. **Run Compliance Scans:**
   ```bash
   # Run STIG evaluation across your environment
   ./run-stig-scan.sh
   ```

## Logging

- **acas-deploy.sh**: `/var/log/acas_deploy.log`
- **openscap-setup.sh**: stdout (build process)
- **run-stig-scan.sh**: Ansible output to stdout

## Firewall Configuration

After deployment, ensure these ports are accessible:
- **8834/tcp** - Nessus web interface
- **443/tcp** - SecurityCenter web interface
- **22/tcp** - SSH for remote scanning

## Troubleshooting

**ACAS Deployment:**
- Disk setup failures: Verify /dev/sdb exists and is empty
- RPM install errors: Check fapolicyd logs in `/etc/fapolicyd/fapolicy.output`
- Service failures: Check systemctl status for nessus/SecurityCenter

**OpenSCAP:**
- Build failures: Ensure all dependencies are installed
- Scan errors: Verify profile name matches available profiles

**STIG Scans:**
- Connection failures: Test SSH connectivity manually
- Authentication errors: Verify credentials and sudo access
- Inventory errors: Check `/etc/ansible/inventory/ent_hosts` syntax
