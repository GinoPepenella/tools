#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

##############################
# PREDEFINE SECURITYCENTER VARIABLES
##############################
# (Prevents 'unbound variable' errors if user chooses Nessus-only)
SC_CN=""
SC_OU=""
SC_ORG=""
SC_CITY=""
SC_STATE=""
SC_COUNTRY=""
SC_CERT_PATH=""
LICENSE_PATH=""

##############################
# USER INPUT SECTION
##############################

read -rp "Enter the full FQDN for this scanner (e.g., rcs08acas.pcte.mil): " FQDN
read -rp "Enter the Satellite Server FQDN (e.g., rcs08oobsat01.pcte.mil): " SAT_SERVER
read -rp "Enter the IdM principal to join the domain (e.g., admin): " IDM_PRINCIPAL
read -rp "Select install mode — Enter 1 for SecurityCenter + Nessus, or 2 for Nessus only: " INSTALL_MODE

echo "Path to acas_configure RPM (Tab-complete): "
read -e -i "/root/" ACAS_RPM

echo "Path to Nessus RPM (Tab-complete): "
read -e -i "/root/" NESSUS_RPM

if [[ "$INSTALL_MODE" == "1" ]]; then
  echo "Path to SecurityCenter RPM (Tab-complete): "
  read -e -i "/root/" SC_RPM
fi

##############################
# 1. SYSTEM PREP
##############################

echo "[*] Setting hostname..."
hostnamectl set-hostname "$FQDN"

echo "[*] Registering with Satellite: $SAT_SERVER"
rpm -Uvh --nodigest --nofiledigest "http://$SAT_SERVER/pub/katello-ca-consumer-latest.noarch.rpm" || true

if subscription-manager status &>/dev/null; then
  echo "[!] System is already registered with Satellite."
  read -rp "Do you want to re-register using --force? (y/n): " REREG
  if [[ "$REREG" =~ ^[Yy]$ ]]; then
    subscription-manager register --org="PCTE" --activationkey="rhel8" --force
  else
    echo "[*] Skipping re-registration."
  fi
else
  echo "[*] Registering system with Satellite..."
  subscription-manager register --org="PCTE" --activationkey="rhel8"
fi

##############################
# 1B. IDM JOIN (FAILSAFE)
##############################

echo "[*] Checking if system is already joined to IdM..."
if [ -f /etc/ipa/default.conf ]; then
  echo "[!] System appears to already be enrolled in IdM."
  read -rp "Do you want to skip IdM join and continue? (y/n): " SKIP_IDM
  if [[ "$SKIP_IDM" =~ ^[Yy]$ ]]; then
    echo "[*] Skipping ipa-client-install..."
  else
    echo "[*] Attempting IdM rejoin (force)..."
    set +e
    ipa-client-install --mkhomedir --force --principal="$IDM_PRINCIPAL"
    IPA_JOIN_EXIT=$?
    set -e
    if [[ $IPA_JOIN_EXIT -ne 0 ]]; then
      echo "[!] ipa-client-install failed (code $IPA_JOIN_EXIT). Host may already be joined or there was a credential issue."
      echo "    Skipping IdM join and continuing script..."
    fi
  fi
else
  echo "[*] Attempting IdM join..."
  set +e
  ipa-client-install --mkhomedir --force --principal="$IDM_PRINCIPAL"
  IPA_JOIN_EXIT=$?
  set -e
  if [[ $IPA_JOIN_EXIT -ne 0 ]]; then
    echo "[!] ipa-client-install failed (code $IPA_JOIN_EXIT). Skipping and continuing..."
  fi
fi

##############################
# 2. DISK SETUP
##############################

echo "[*] Wiping and initializing LVM on /dev/sdb..."
set +e
wipefs -a /dev/sdb
WIPEFS_EXIT=$?
if [[ $WIPEFS_EXIT -ne 0 ]]; then
  echo "[!] wipefs failed (code $WIPEFS_EXIT). Device or resource may be busy."
  echo "    Attempting parted to remove any partition labels..."

  parted -s /dev/sdb mklabel gpt 2>/dev/null
  PARTED_EXIT=$?
  if [[ $PARTED_EXIT -ne 0 ]]; then
    echo "[!] parted mklabel gpt also failed. Skipping disk setup..."
    DISK_SETUP_FAILED=1
  else
    echo "[!] parted succeeded. Retrying wipefs..."
    wipefs -a /dev/sdb
    WIPEFS_EXIT=$?
    if [[ $WIPEFS_EXIT -ne 0 ]]; then
      echo "[!] wipefs failed again (code $WIPEFS_EXIT). Skipping disk setup..."
      DISK_SETUP_FAILED=1
    else
      DISK_SETUP_FAILED=0
    fi
  fi
else
  DISK_SETUP_FAILED=0
fi
set -e

if [[ $DISK_SETUP_FAILED -eq 0 ]]; then
  pvcreate -ff -y /dev/sdb
  vgextend rhel /dev/sdb

  if [[ "$INSTALL_MODE" == "1" ]]; then
    lvcreate -L 100G -n opt_sc rhel
    lvcreate -l 100%FREE -n opt_nessus rhel
    mkfs.xfs /dev/mapper/rhel-opt_sc
    mkfs.xfs /dev/mapper/rhel-opt_nessus

    mkdir -p /opt/sc /opt/nessus
    echo '/dev/mapper/rhel-opt_sc     /opt/sc     xfs defaults 0 0' >> /etc/fstab
    echo '/dev/mapper/rhel-opt_nessus /opt/nessus xfs defaults 0 0' >> /etc/fstab
  else
    lvcreate -l 100%FREE -n opt_nessus rhel
    mkfs.xfs /dev/mapper/rhel-opt_nessus
    mkdir -p /opt/nessus
    echo '/dev/mapper/rhel-opt_nessus /opt/nessus xfs defaults 0 0' >> /etc/fstab
  fi

  mount -a
fi

##############################
# 3. DEPENDENCIES
##############################

echo "[*] Installing dependencies..."
yum install -y rsync dialog zip unzip \
  java-1.8.0-openjdk java-1.8.0-openjdk-devel java-1.8.0-openjdk-headless

##############################
# 4. fapolicyd DEBUG SESSION
##############################

echo "[*] Running fapolicyd in permissive debug mode..."
systemctl stop fapolicyd
fapolicyd --permissive --debug 2> /etc/fapolicyd/fapolicy.output &

##############################
# 5. INSTALL acas_configure RPM
##############################

echo "[*] Installing acas_configure..."
dnf install -y "$ACAS_RPM" --nogpgcheck

##############################
# 6. STAGE RPMs
##############################

echo "[*] Staging RPMs..."
mkdir -p /opt/acas/var
cp "$NESSUS_RPM" /opt/acas/var

cd /opt/acas/var
NESSUS_FILE=$(basename "$NESSUS_RPM")
if [[ "$NESSUS_FILE" == *"Nes"* ]]; then
    mv "$NESSUS_FILE" "${NESSUS_FILE//Nes/Nessus}"
fi

if [[ "$INSTALL_MODE" == "1" ]]; then
  cp "$SC_RPM" /opt/acas/var
fi

##############################
# 6A. INSTALL NESSUS + SECURITYCENTER RPMs
##############################

# Install Nessus if not already installed.
if ! rpm -q Nessus >/dev/null 2>&1; then
  echo "[*] Installing Nessus package..."
  rpm -ivh "$NESSUS_FILE" || echo "[!] Could not install Nessus RPM. Continuing..."
else
  echo "[*] Nessus package already installed."
fi

if [[ "$INSTALL_MODE" == "1" ]]; then
  # Install SecurityCenter if not installed
  SC_BASENAME=$(basename "$SC_RPM")
  if ! rpm -q SecurityCenter >/dev/null 2>&1; then
    echo "[*] Installing SecurityCenter package..."
    rpm -ivh "$SC_BASENAME" || echo "[!] Could not install SecurityCenter RPM. Continuing..."
  else
    echo "[*] SecurityCenter package already installed."
  fi
fi

##############################
# 6B. FIREWALL OPEN PORTS
##############################

echo "[*] Checking if firewalld is active..."
if systemctl is-active firewalld >/dev/null 2>&1; then
  echo "[*] Opening 8834/tcp for Nessus..."
  firewall-cmd --permanent --add-port=8834/tcp 2>/dev/null || echo "[!] Could not add port 8834/tcp."
  if [[ "$INSTALL_MODE" == "1" ]]; then
    echo "[*] Opening 443/tcp for SecurityCenter..."
    firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || echo "[!] Could not add port 443/tcp."
  fi
  echo "[*] Reloading firewalld..."
  firewall-cmd --reload 2>/dev/null || echo "[!] Could not reload firewalld."
else
  echo "[!] firewalld not active. If you enable it, be sure to open 8834 (Nessus) and 443 (SecurityCenter)."
fi

##############################
# 7. LAUNCH ACAS SETUP SCRIPT
##############################

echo "[*] Launching ACAS setup script..."
cd /opt/acas
bash ./setup.sh

##############################
# 8. SECURITYCENTER CONFIG (IF SELECTED)
##############################

if [[ "$INSTALL_MODE" == "1" ]]; then
  echo "[*] Configuring SecurityCenter IdM certificate..."

  read -rp "Enter Common Name (CN) for cert (e.g., rcs08acas.pcte.mil): " SC_CN
  read -rp "Enter Organizational Unit (OU) (e.g., PCTE-RCS08): " SC_OU
  read -rp "Enter Org Name (O): " SC_ORG
  read -rp "Enter City (L): " SC_CITY
  read -rp "Enter State (ST): " SC_STATE
  read -rp "Enter Country Code (C): " SC_COUNTRY

  cat > /root/csr_san.conf <<EOF
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
req_extensions = req_ext
prompt = no

[ req_distinguished_name ]
C = $SC_COUNTRY
ST = $SC_STATE
L = $SC_CITY
O = $SC_ORG
OU = $SC_OU
CN = $SC_CN

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $SC_CN
EOF

  openssl req -config /root/csr_san.conf -new -newkey rsa:2048 \
    -keyout /root/SecurityCenter.key -nodes \
    -out /root/SecurityCenter.csr

  echo "[*] Submit the CSR via IdM UI and obtain the signed certificate."
  read -rp "Path to IdM-issued cert (e.g., /root/SecurityCenter.crt): " SC_CERT_PATH

  cp "$SC_CERT_PATH" /opt/sc/support/conf/SecurityCenter.crt
  cp /root/SecurityCenter.key /opt/sc/support/conf/SecurityCenter.key
  chown tns:tns /opt/sc/support/conf/SecurityCenter.*
  chmod 640 /opt/sc/support/conf/SecurityCenter.*

  echo "[*] Restarting SecurityCenter to apply cert..."
  systemctl restart SecurityCenter

  echo "[*] Enter path to Tenable.sc license file:"
  read -rp "Path to license key (e.g., /root/sc.license): " LICENSE_PATH
  cp "$LICENSE_PATH" /opt/sc/support/etc/license.txt
  chown tns:tns /opt/sc/support/etc/license.txt
  chmod 600 /opt/sc/support/etc/license.txt

  echo "[*] Do you want to configure LDAP integration now? (y/n)"
  read -rp "LDAP? " LDAP_ENABLE
  if [[ "$LDAP_ENABLE" =~ ^[Yy]$ ]]; then
    echo "
⚙️  Manual LDAP Setup Steps:
1. Log in to https://$SC_CN
2. Go to: Users > Authentication > LDAP
3. Add the LDAP server:
   - Hostname: rcs01oobidm01.pcte.mil
   - Port: 636
   - Encryption: LDAPS
   - Bind DN: uid=acas_bind.svc,cn=users,cn=accounts,dc=pcte,dc=mil
   - Password: <prompted securely>
   - Base DN: cn=users,cn=accounts,dc=pcte,dc=mil
   - User object filter: (uid=*.adm)
   - Attributes: uid, mail, cn
4. Test and Save.
"
  fi
fi

echo "
=====================================================
✅ Script Complete. Next Steps:
 - If disk setup was skipped due to an error, mount /opt/nessus or /opt/sc manually.
 - If installing Nessus only, proceed to https://$FQDN:8834 for final config.
"
if [[ "$INSTALL_MODE" == "1" ]]; then
  echo " - If installing SC + Nessus, log in to https://$SC_CN for Tenable.sc tasks."
fi
echo "=====================================================
"

##############################
# 9. START SERVICES
##############################

# Always start Nessus
echo "[*] Enabling and starting Nessus service..."
set +e
systemctl enable --now nessus 2>/dev/null
if [[ $? -ne 0 ]]; then
  echo "[!] Could not enable/start nessus (maybe not installed?). Continuing..."
fi
set -e

# Start SecurityCenter if selected
if [[ "$INSTALL_MODE" == "1" ]]; then
  echo "[*] Enabling SecurityCenter service..."
  set +e
  systemctl enable SecurityCenter 2>/dev/null
  systemctl start SecurityCenter 2>/dev/null
  if [[ $? -ne 0 ]]; then
    echo "[!] Could not enable/start SecurityCenter. Maybe it's already running?"
  fi
  set -e
fi

##############################
# 10. FAPOLICYD FINALIZATION (OPTIONAL)
##############################

echo "[*] Would you like to finalize fapolicyd rules now? (y/n)"
read -rp "fapolicyd finalize? " FAPO_CHOICE
if [[ "$FAPO_CHOICE" =~ ^[Yy]$ ]]; then
  echo "[*] Stopping fapolicyd debug..."
  pkill -f fapolicyd

  echo "[*] Creating a 'deny.output' from dec=deny lines..."
  grep 'dec=deny' /etc/fapolicyd/fapolicy.output > /etc/fapolicyd/deny.output || true

  echo "[*] Converting lines to 'allow perm=open' format..."
  sed -i -E 's/.*exe=/exe=/' /etc/fapolicyd/deny.output
  sort -u /etc/fapolicyd/deny.output -o /etc/fapolicyd/deny.output
  sed -i 's/^/allow perm=open /' /etc/fapolicyd/deny.output

  echo "[*] A basic deny.output has been created at /etc/fapolicyd/deny.output."
  echo "    Review & merge relevant lines into /etc/fapolicyd/rules.d/84-acas.rules."

  echo "[*] Adding recommended trust directories for ACAS..."
  fapolicyd-cli --file add /opt/acas/ --trust-file acas || true
  fapolicyd-cli --file add /opt/nessus/ --trust-file nessus || true

  echo "[*] Removing known large plugin directories to avoid DB overflows..."
  fapolicyd-cli --file delete /opt/sc/data/auditFiles/ --trust-file sc || true
  fapolicyd-cli --file delete /opt/sc/data/nasl/ --trust-file sc || true
  fapolicyd-cli --file delete /opt/nessus/lib/nessus/plugins/ --trust-file nessus || true

  echo "[*] Some additional recommended rules for Tenable.sc DB updates."
  echo "    Add them in /etc/fapolicyd/rules.d/84-acas.rules if not present:"
  cat << 'EOF'
allow perm=open exe=/opt/sc/support/bin/httpd : dir=/usr/bin/
allow perm=open exe=/opt/sc/bin/ipv4_importdb : dir=/etc/
allow perm=open exe=/opt/sc/bin/ipv4_importdb : dir=/opt/sc/
allow perm=open exe=/opt/sc/bin/ipv4_importdb : dir=/usr/bin/
allow perm=open exe=/opt/sc/bin/ipv4_importdb : dir=/usr/share/
allow perm=open exe=/opt/sc/bin/ipv4_importdb : dir=/opt/sc/
allow perm=open exe=/opt/sc/support/bin/sqlite3 : dir=/opt/sc/
allow perm=open exe=/opt/sc/support/bin/sqlite3 : dir=/etc/
allow perm=open exe=/opt/sc/support/bin/sqlite3 : dir=/var/tmp/
allow perm=open dir=/opt/sc/bin/ : dir=/etc/
allow perm=open dir=/opt/sc/bin/ : dir=/opt/sc/
allow perm=open dir=/usr/lib/jvm/ : dir=/usr/lib/jvm/
allow perm=open dir=/usr/lib/jvm/ : dir=/usr/
allow perm=open dir=/usr/lib/jvm/ : dir=/etc/
allow perm=open dir=/usr/lib/jvm/ : dir=/usr/share/
allow perm=open dir=/usr/lib/jvm/ : dir=/etc/
allow perm=open dir=/usr/lib/jvm/ : dir=/tmp/
allow perm=open dir=/usr/lib/jvm/ : dir=/var/
allow perm=open  exe=/usr/bin/zip : all
allow perm=open  exe=/usr/bin/unzip : all
allow perm=open  exe=/opt/sc/bin/ipv4_apply_all_risk : dir=/usr/bin/
allow perm=open exe=/usr/bin/pkla-check-authorization : dir=/etc/
allow perm=open exe=/usr/bin/pkla-check-authorization : dir=/usr/
EOF

  echo
  echo "[*] Once done, run 'systemctl start fapolicyd' to re-enable."
  echo "    Or run 'fapolicyd-cli --delete-db && reboot && fapolicyd-cli --update' if errors persist."
fi
