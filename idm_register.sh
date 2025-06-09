#!/usr/bin/env bash
#
# idm_register.sh – join a RHEL 8/9 VM to IdM; Satellite optional / non‑fatal
#

set -o errexit -o pipefail -o nounset
IFS=$'\n\t'
banner() { printf '\n=== %s ===\n' "$*"; }

###############################################################################
# 1) COLLECT INPUT
###############################################################################
banner "User input"
read -rp "🖥️  FQDN for this VM (e.g. vm01.example.mil): " FQDN
read -rp "🌐 IdM realm (e.g. EXAMPLE.MIL): "            REALM
read -rp "🆔  IdM admin principal [admin]: "             IDM_PRINCIPAL
IDM_PRINCIPAL=${IDM_PRINCIPAL:-admin}
read -srp "🔑  Password for ${IDM_PRINCIPAL}: "          IDM_PASSWORD
echo

read -rp "📡 Also register with Satellite? (y/N): " SAT_CHOICE
if [[ $SAT_CHOICE =~ ^[Yy]$ ]]; then
    read -rp "   Satellite FQDN: "   SAT_SERVER
    read -rp "   Activation‑key : "  SAT_KEY
    read -rp "   Org name       : "  SAT_ORG
fi
echo

###############################################################################
# 2) HOSTNAME
###############################################################################
banner "Setting hostname"
hostnamectl set-hostname "$FQDN"
grep -q "$FQDN" /etc/hosts || echo "127.0.0.1  $FQDN" >> /etc/hosts

###############################################################################
# 3) OPTIONAL: SATELLITE  (NON‑FATAL)
###############################################################################
if [[ $SAT_CHOICE =~ ^[Yy]$ ]]; then
  banner "Satellite registration (will continue even if it fails)"
  rpm -q katello-ca-consumer-latest &>/dev/null || \
      rpm -Uvh --nodigest --nofiledigest \
      "http://${SAT_SERVER}/pub/katello-ca-consumer-latest.noarch.rpm" || true

  set +e
  subscription-manager status &>/dev/null
  STATUS=$?
  if [[ $STATUS -ne 0 ]]; then
      subscription-manager register \
          --org="$SAT_ORG" --activationkey="$SAT_KEY"
      STATUS=$?
  fi
  set -e

  [[ $STATUS -eq 0 ]] \
    && echo "✔ Satellite registration OK" \
    || echo "⚠ Satellite registration failed (code $STATUS) – continuing"
fi

###############################################################################
# 4) INSTALL NEEDED PACKAGES
###############################################################################
banner "Installing ipa‑client / sssd / chrony"
dnf install -y ipa-client sssd chrony

###############################################################################
# 5) CHRONY: POINT TO IdM AND SYNC TIME
###############################################################################
IDM_HOST="idm.${REALM,,}"
banner "Configuring chrony to use ${IDM_HOST}"
sed -i '/^pool /d' /etc/chrony.conf
grep -q "$IDM_HOST" /etc/chrony.conf || \
    echo "server ${IDM_HOST} iburst" >> /etc/chrony.conf
systemctl enable --now chronyd
chronyc -a 'burst 4/4' || true
chronyc -a makestep    || true

###############################################################################
# 6) JOIN IdM  (fixed — removed --ntp-server)
###############################################################################
banner "Running ipa-client-install"
ipa-client-install \
    --mkhomedir --force --unattended \
    --principal="$IDM_PRINCIPAL" \
    --password="$IDM_PASSWORD" \
    --no-ntp        # rely on chrony config above

###############################################################################
# 7) SMOKE TESTS
###############################################################################
banner "Post‑join smoke tests"
id "$IDM_PRINCIPAL" &>/dev/null && echo "✔ id lookup works"
echo "$IDM_PASSWORD" | kinit "$IDM_PRINCIPAL" && { echo "✔ Kerberos ticket acquired"; kdestroy; } \
    || echo "⚠ kinit failed – check DNS/time/password"

###############################################################################
# 8) DONE
###############################################################################
cat <<EOF

============================================================
✅  VM successfully enrolled in IdM realm  $REALM
    • Log out / log in with domain credentials to verify.
    • Ensure UDP 123 remains open for NTP.
    • Logs: /var/log/sssd/, /var/log/ipaclient-install.log
============================================================
EOF
