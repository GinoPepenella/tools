#!/usr/bin/env bash
#
# acas_deploy_optimized.sh – Deploy ACAS (Nessus [+SecurityCenter]) on RHEL 8/9
# Optimized: IP-based addressing, error handling, logging, and input validation

set -o errexit
set -o pipefail
set -o nounset
IFS=$'\n\t'
LOGFILE="/var/log/acas_deploy.log"

# Trap errors
trap 'echo "[ERROR] on line $LINENO: $BASH_COMMAND" | tee -a "$LOGFILE"; exit 1' ERR

# Helpers
banner() { echo -e "\n=== $* ===" | tee -a "$LOGFILE"; }
log()    { echo "$(date '+%F %T') [INFO] $*" | tee -a "$LOGFILE"; }
check_cmd() { command -v "$1" &>/dev/null || { echo "[FATAL] '$1' required." | tee -a "$LOGFILE"; exit 1; } }
ensure_root() { [[ $EUID -eq 0 ]] || { echo "[FATAL] Run as root."; exit 1; } }
validate_ip() {
  if [[ ! "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[WARNING] IP '$1' may be invalid." | tee -a "$LOGFILE"
  fi
}

# Ensure root user
ensure_root
banner "Starting ACAS Deployment"; log "Log: $LOGFILE"

# 1) COLLECT INPUT
banner "Collecting user input"
read -rp "Enter scanner IP (e.g., 10.0.0.10): " SCANNER_IP; validate_ip "$SCANNER_IP"
read -rp "Enter Satellite server IP: " SAT_SERVER_IP; validate_ip "$SAT_SERVER_IP"
read -rp "Enter IdM server IP: " IDM_SERVER_IP; validate_ip "$IDM_SERVER_IP"

read -rp "IdM admin principal [admin]: " IDM_PRINCIPAL
IDM_PRINCIPAL=${IDM_PRINCIPAL:-admin}
read -srp "Password for $IDM_PRINCIPAL: " IDM_PASSWORD; echo

read -rp "Install mode — 1) SecurityCenter+Nessus, 2) Nessus only: " INSTALL_MODE
if [[ "$INSTALL_MODE" != "1" && "$INSTALL_MODE" != "2" ]]; then
  echo "[FATAL] Invalid install mode."; exit 1
fi

read -e -p "Path to acas_configure RPM [/root/acas_configure.rpm]: " ACAS_RPM
ACAS_RPM=${ACAS_RPM:-/root/acas_configure.rpm}
read -e -p "Path to Nessus RPM [/root/nessus.rpm]: " NESSUS_RPM
NESSUS_RPM=${NESSUS_RPM:-/root/nessus.rpm}
if [[ "$INSTALL_MODE" == "1" ]]; then
  read -e -p "Path to SecurityCenter RPM [/root/sc.rpm]: " SC_RPM
  SC_RPM=${SC_RPM:-/root/sc.rpm}
fi

# 2) SYSTEM PREP: Satellite Registration
banner "Satellite registration (non-fatal)"
check_cmd rpm
if ! rpm -q katello-ca-consumer-latest &>/dev/null; then
  rpm -Uvh --nodigest --nofiledigest \
      "http://$SAT_SERVER_IP/pub/katello-ca-consumer-latest.noarch.rpm" &>> "$LOGFILE" || log "CA consumer RPM install failed"
fi

set +e
check_cmd subscription-manager
subscription-manager status &>/dev/null || \
    subscription-manager register --org="PCTE" --activationkey="rhel8" --force &>> "$LOGFILE"
STATUS=$?
set -e
[[ $STATUS -eq 0 ]] && log "Satellite registered" || log "Satellite registration failed ($STATUS), continuing"

# 3) IDM JOIN (non-fatal)
banner "IdM join (non-fatal)"
check_cmd ipa-client-install
if [[ -f /etc/ipa/default.conf ]]; then
  log "Already enrolled in IdM. Skipping join."
else
  set +e
  ipa-client-install --mkhomedir --force --principal="$IDM_PRINCIPAL" \
      --password="$IDM_PASSWORD" --server="$IDM_SERVER_IP" --domain="${IDM_SERVER_IP//./}-idm.local" --no-ntp &>> "$LOGFILE"
  IPA_EXIT=$?
  set -e
  [[ $IPA_EXIT -eq 0 ]] && log "IdM join succeeded" || log "IdM join failed ($IPA_EXIT)"
fi

# 4) DISK SETUP
banner "LVM disk setup on /dev/sdb"
check_cmd wipefs; check_cmd parted; check_cmd pvcreate; check_cmd vgextend; check_cmd lvcreate; check_cmd mkfs.xfs
wipefs -a /dev/sdb &>/dev/null || {
  log "wipefs failed, attempting parted..."
  parted -s /dev/sdb mklabel gpt &>/dev/null || { log "parted failed, skipping disk setup"; DISK_SKIP=1; }
}
if [[ ${DISK_SKIP:-0} -eq 0 ]]; then
  pvcreate -ff -y /dev/sdb &>> "$LOGFILE"
  vgextend rhel /dev/sdb &>> "$LOGFILE" || log "VG extend failed"
  if [[ "$INSTALL_MODE" == "1" ]]; then
    lvcreate -L100G -n opt_sc rhel &>> "$LOGFILE"
    lvcreate -l100%FREE -n opt_nessus rhel &>> "$LOGFILE"
    for lv in opt_sc opt_nessus; do mkfs.xfs /dev/rhel/$lv &>> "$LOGFILE"; done
    mkdir -p /opt/sc /opt/nessus
    echo "/dev/rhel/opt_sc /opt/sc xfs defaults 0 0" >> /etc/fstab
    echo "/dev/rhel/opt_nessus /opt/nessus xfs defaults 0 0" >> /etc/fstab
  else
    lvcreate -l100%FREE -n opt_nessus rhel &>> "$LOGFILE"
    mkfs.xfs /dev/rhel/opt_nessus &>> "$LOGFILE"
    mkdir -p /opt/nessus
    echo "/dev/rhel/opt_nessus /opt/nessus xfs defaults 0 0" >> /etc/fstab
  fi
  mount -a
  log "Disk setup complete"
fi

# 5) DEPENDENCIES
banner "Installing dependencies"
check_cmd dnf
dnf install -y rsync dialog zip unzip java-1.8.0-openjdk java-1.8.0-openjdk-devel java-1.8.0-openjdk-headless &>> "$LOGFILE"

# 6) fapolicyd DEBUG
banner "Starting fapolicyd in permissive debug mode"
check_cmd systemctl; check_cmd fapolicyd
systemctl stop fapolicyd &>/dev/null
fapolicyd --permissive --debug 2> /etc/fapolicyd/fapolicy.output &

# 7) INSTALL acas_configure
banner "Installing acas_configure RPM"
check_cmd dnf
dnf install -y "$ACAS_RPM" --nogpgcheck &>> "$LOGFILE"

# 8) STAGE RPMs
banner "Staging RPMs"
mkdir -p /opt/acas/var
cp "$NESSUS_RPM" /opt/acas/var/
NESSUS_FILE=$(basename "$NESSUS_RPM")
mv "/opt/acas/var/$NESSUS_FILE" "/opt/acas/var/${NESSUS_FILE//Nes/Nessus}" || true
if [[ "$INSTALL_MODE" == "1" ]]; then cp "$SC_RPM" /opt/acas/var/; fi

# 9) INSTALL Nessus (+SC)
banner "Installing Nessus (+SecurityCenter if selected)"
if ! rpm -q Nessus &>/dev/null; then rpm -ivh "/opt/acas/var/${NESSUS_FILE//Nes/Nessus}" || log "Nessus install failed"; else log "Nessus already installed"; fi
if [[ "$INSTALL_MODE" == "1" ]]; then
  SC_FILE=$(basename "$SC_RPM")
  if ! rpm -q SecurityCenter &>/dev/null; then rpm -ivh "/opt/acas/var/$SC_FILE" || log "SC install failed"; else log "SC already installed"; fi
fi

# 10) FIREWALL
banner "Configuring firewalld ports"
check_cmd firewall-cmd
if systemctl is-active firewalld &>/dev/null; then
  firewall-cmd --permanent --add-port=8834/tcp || log "Failed to open 8834"
  [[ "$INSTALL_MODE" == "1" ]] && firewall-cmd --permanent --add-port=443/tcp || true
  firewall-cmd --reload || log "Failed to reload firewalld"
else
  log "firewalld inactive. Ensure ports 8834 (Nessus) and 443 (SC) manually."
fi

# 11) RUN ACAS SETUP
banner "Running ACAS setup script"
cd /opt/acas && bash ./setup.sh &>> "$LOGFILE"

# 12) START SERVICES
banner "Starting services"
systemctl enable --now nessus || log "Could not enable Nessus"
[[ "$INSTALL_MODE" == "1" ]] && { systemctl enable --now SecurityCenter || log "Could not start SC"; }

# 13) FINAL MESSAGE
echo -e "\n============================================================"
echo "✅ ACAS deployment script completed"
echo " - Access Nessus at https://$SCANNER_IP:8834"
[[ "$INSTALL_MODE" == "1" ]] && echo " - Access SecurityCenter at https://<SecurityCenter-FQDN>" || true
echo " - Logs available at $LOGFILE"
echo "============================================================"
