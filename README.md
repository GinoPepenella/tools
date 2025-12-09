# Security & System Administration Tools

A collection of scripts and utilities for security scanning, compliance management, and system administration on RHEL/AlmaLinux systems.

## Repository Structure

```
tools/
├── system-setup/         # System configuration and setup scripts
├── security-scanning/    # Vulnerability and compliance scanning tools
├── stig-tools/          # STIG checklist management utilities
└── misc/                # Miscellaneous utilities
```

## Categories

### System Setup
Scripts for configuring RHEL/AlmaLinux systems with enterprise services and authentication.

- **cac-rhel-setup.sh** - Install CAC middleware and DoD certificates
- **idm-register.sh** - Join systems to Identity Management (IdM)
- **ansible-install.sh** - Install and configure Ansible

[→ View system-setup documentation](./system-setup/README.md)

### Security Scanning
Tools for deploying and running security vulnerability scanners and compliance tools.

- **acas-deploy.sh** - Deploy ACAS (Nessus + SecurityCenter)
- **openscap-setup.sh** - Build and configure OpenSCAP
- **run-stig-scan.sh** - Execute STIG compliance scans

[→ View security-scanning documentation](./security-scanning/README.md)

### STIG Tools
Utilities for managing and processing STIG checklists (.ckl files).

- **automate-ckls.py** - Automate CKL status and comments
- **ckl-search.sh** - Interactive CKL vulnerability search
- **compare-ckls.py** - Compare two CKL files and export deltas

[→ View stig-tools documentation](./stig-tools/README.md)

### Miscellaneous
Other utilities and tools.

- **rickroll.sh** - Systemd-based prank script

[→ View misc documentation](./misc/README.md)

## Requirements

Most scripts require:
- RHEL 8/9 or AlmaLinux
- Root/sudo access
- Network connectivity

Specific requirements are documented in each category's README.

## Usage

Navigate to the appropriate category directory and refer to its README for detailed usage instructions.

## License

These tools are provided as-is for authorized security testing and system administration purposes.

## Contributing

Contributions and improvements are welcome. Please ensure all scripts include proper error handling and documentation.
