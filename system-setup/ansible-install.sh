# setup.sh
#!/usr/bin/env bash
# Detect OS, install Ansible + community.general, configure /etc/ansible/ansible.cfg

set -e

# must be root
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root or via sudo."
  exit 1
fi

# Source OS info
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
else
  echo "Cannot detect OS. /etc/os-release missing."
  exit 1
fi

echo "Detected OS: $ID"

case "$ID" in
  rhel|centos|rocky)
    # Ensure EPEL for ansible & collection packages
    if ! command -v dnf &>/dev/null && command -v yum &>/dev/null; then
      PKG=yum
    else
      PKG=dnf
    fi

    echo "Installing EPEL, Ansible, and ansible-collection-community-general.noarch via $PKG..."
    $PKG install -y epel-release
    $PKG install -y ansible ansible-collection-community-general.noarch
    ;;

  ubuntu|debian)
    echo "Updating apt and installing Ansible..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ansible python3-apt
    echo "Installing community.general via ansible-galaxy..."
    ansible-galaxy collection install community.general
    ;;

  *)
    echo "Unsupported OS: $ID. Exiting."
    exit 1
    ;;
esac

echo "Writing /etc/ansible/ansible.cfg (host_key_checking disabled, inventory pointed at ent_hosts)..."
mkdir -p /etc/ansible/inventory
cat > /etc/ansible/ansible.cfg <<EOF
[defaults]
host_key_checking = False
inventory = /etc/ansible/inventory/ent_hosts
EOF

echo
echo "✔ Setup complete!"
echo "→ Populate /etc/ansible/inventory/ent_hosts with your FQDNs under [EXAMPLE_ENV], [EXAMPLE_ENV2], etc."

