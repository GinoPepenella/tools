#!/usr/bin/env bash
#
# idm_register_optimized.sh – join a RHEL 8/9 VM to IdM; Satellite optional / non‑fatal
#
# Optimized with enhanced error handling, logging, and IP‑based server addressing

set -o errexit -o pipefail -o nounset
IFS=$'\n\t'
LOGFILE="/var/log/idm_register.log"

# Trap errors
trap 'echo "[ERROR] on line $LINENO: $BASH_COMMAND" | tee -a "$LOGFILE"; exit 1' ERR

# Helpersanner() { echo -e "\n=== $* ===" | tee -a "$LOGFILE"; }
log()    { echo "$(date '+%F %T') [INFO] $*" | tee -a "$LOGFILE"; }
check_cmd() { command -v "$1" &>/dev/null || { echo "[FATAL] Command '$1' not found." | tee -a "$LOGFILE"; exit 1; } }
enable_root() { [[ $EUID -eq 0 ]] || { echo "[FATAL] Run as root."; exit 1; } }

# Ensure root
enable_root
banner "Starting IdM Registration"; log "Log: $LOGFILE"

# 1) COLLECT INPUT
banner "Collecting user input"
read -rp "🖥️  FQDN for VM hostname (e.g. vm01.example.com): " FQDN
[[ -n "$FQDN" ]] || { echo "[FATAL] FQDN required."; exit 1; }

read -rp "🌐 IdM realm (e.g. example.com): " REALM
REALM=${REALM^^}
[[ -n "$REALM" ]] || { echo "[FATAL] Realm required."; exit 1; }

read -rp "🔢 IdM server IP (e.g. 10.0.0.5): " IDM_SERVER_IP
[[ "$IDM_SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || log "Warning: IP format may be invalid."

read -rp "🆔  IdM admin principal [admin]: " IDM_PRINCIPAL
IDM_PRINCIPAL=${IDM_PRINCIPAL:-admin}
read -srp "🔑  Password for ${IDM_PRINCIPAL}: " IDM_PASSWORD; echo

read -rp "📡 Also register with Satellite? (y/N): " SAT_CHOICE; SAT_CHOICE=${SAT_CHOICE,,}
if [[ "$SAT_CHOICE" == "y" ]]; then
    read -rp "   Satellite server IP (e.g. 10.0.0.6): " SAT_SERVER_IP
    read -rp "   Activation key: " SAT_KEY
    read -rp "   Org name     : " SAT_ORG
fi

# 2) SET HOSTNAME
banner "Configuring hostname"
check_cmd hostnamectl
hostnamectl set-hostname "$FQDN"
grep -qF "$FQDN" /etc/hosts || echo "127.0.0.1  $FQDN" >> /etc/hosts
log "Hostname set to $FQDN"

# 3) SATELLITE REGISTRATION (optional)
if [[ "$SAT_CHOICE" == "y" ]]; then
    banner "Satellite registration (non-fatal)"
    check_cmd rpm
    if ! rpm -q katello-ca-consumer-latest &>/dev/null; then
        rpm -Uvh --nodigest --nofiledigest \
            "http://$SAT_SERVER_IP/pub/katello-ca-consumer-latest.noarch.rpm" \
          &>> "$LOGFILE" || log "CA RPM install failed"
    fi
    set +e
    subscription-manager status &>/dev/null || \
        subscription-manager register --org="$SAT_ORG" --activationkey="$SAT_KEY" &>> "$LOGFILE"
    STATUS=$?
    set -e
    [[ $STATUS -eq 0 ]] && log "Satellite registration OK" || log "Satellite registration failed ($STATUS), continuing"
fi

# 4) INSTALL PACKAGES
banner "Installing prerequisites"
check_cmd dnf
dnf install -y ipa-client sssd chrony &>> "$LOGFILE"
log "Packages installed"

# 5) CONFIGURE CHRONY
banner "Configuring chrony to ${IDM_SERVER_IP}"
check_cmd cp; check_cmd sed; check_cmd systemctl; check_cmd chronyc
bak="/etc/chrony.conf.bak.$(date +%F_%T)"
cp /etc/chrony.conf "$bak"; log "Backup chrony.conf to $bak"
sed -i '/^pool /d' /etc/chrony.conf
grep -qF "$IDM_SERVER_IP" /etc/chrony.conf || \
    echo "server $IDM_SERVER_IP iburst" >> /etc/chrony.conf
systemctl enable --now chronyd &>> "$LOGFILE"
chronyc -a 'burst 4/4' &>/dev/null || log "chronyc burst failed"
chronyc -a makestep &>/dev/null || log "chronyc makestep failed"
log "Chrony sync set to $IDM_SERVER_IP"

# 6) JOIN IdM
banner "Running ipa-client-install against $IDM_SERVER_IP"
check_cmd ipa-client-install
ipa-client-install --mkhomedir --force --unattended \
    --principal="$IDM_PRINCIPAL" --password="$IDM_PASSWORD" \
    --server="$IDM_SERVER_IP" --domain="$REALM" --no-ntp &>> "$LOGFILE"
log "ipa-client-install done"

# 7) SMOKE TESTS
banner "Post-join smoke tests"
check_cmd id; check_cmd kinit; check_cmd kdestroy
id "$IDM_PRINCIPAL" &>/dev/null && log "id lookup OK" || { log "id lookup failed"; exit 1; }
if echo "$IDM_PASSWORD" | kinit "$IDM_PRINCIPAL" &>/dev/null; then
    log "Kerberos ticket acquired"; kdestroy
else
    log "kinit failed – check DNS/time/password"; exit 1
fi

# 8) COMPLETION
cat <<EOF | tee -a "$LOGFILE"
============================================================
✅  VM enrolled in IdM realm $REALM
    • Log in with domain credentials to verify.
    • Ensure UDP 123 open for NTP.
    • Logs: $LOGFILE
============================================================
EOF
