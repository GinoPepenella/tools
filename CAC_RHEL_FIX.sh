#!/bin/bash
set -euo pipefail

# -------------------------------------------------------------------
#
# Installs CAC middleware and DoD root CAs on AlmaLinux (RHEL-compatible),
# ensures pcscd group exists, then enables pcscd so that a CAC reader is recognized.
# --------------------------------------------------------------------

# 1) Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: this script must be run as root. Exiting."
  exit 1
fi

# 2) Install basic certificate management tools (nss-tools, OpenSSL) and utilities
echo "[+] Installing certificate tools and dependencies..."
dnf install -y nss-tools openssl wget unzip

# 3) Enable EPEL repository (needed for opensc/pcsc packages)
echo "[+] Enabling EPEL repository..."
dnf install -y epel-release

# 4) Install CAC middleware and PC/SC stack
echo "[+] Installing CAC middleware (OpenSC, PC/SC)..."
dnf install -y esc opensc pcsc-lite pcsc-tools

# 5) Ensure 'pcscd' group exists (some installs don’t auto-create it)
if ! getent group pcscd >/dev/null; then
  echo "[!] 'pcscd' group not found—creating it now..."
  groupadd --system pcscd
fi

# 6) Enable and start pcscd so that the smart-card reader is recognized
echo "[+] Enabling and starting pcscd service..."
systemctl enable --now pcscd.service

# 7) Add current non-root login to 'pcscd' group so they can access the reader
USER_TO_ADD=$(logname 2>/dev/null || echo "$SUDO_USER")
if id "$USER_TO_ADD" &>/dev/null; then
  echo "[+] Adding user '$USER_TO_ADD' to pcscd group..."
  usermod -aG pcscd "$USER_TO_ADD"
else
  echo "[!] Could not detect non-root user to add to 'pcscd' group. Please add manually:"
  echo "    sudo usermod -aG pcscd <your-username>"
fi

# 8) Download the DoD root-CA bundle (PKCS#7 ZIP) and extract
TMPDIR=$(mktemp -d)
echo "[+] Downloading DoD PKI CA bundle..."
pushd "$TMPDIR" >/dev/null

DOD_ZIP_URL="https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip"
wget -O dod_certs.zip "$DOD_ZIP_URL"

echo "[+] Unzipping DoD CA bundle..."
unzip -q dod_certs.zip

# Find the primary DER-encoded PKCS#7 file
P7B_FILE=$(ls *.p7b 2>/dev/null | head -n1)
if [ -z "$P7B_FILE" ]; then
  echo "ERROR: Could not find any .p7b file inside the ZIP. Exiting."
  popd >/dev/null
  exit 1
fi

# 9) Convert the PKCS#7 bundle into a PEM chain and install it system-wide
echo "[+] Converting PKCS#7 to PEM and installing into /etc/pki/ca-trust/source/anchors/DoD_Certs.pem..."
openssl pkcs7 \
  -print_certs \
  -inform der \
  -in "$P7B_FILE" \
  -out /etc/pki/ca-trust/source/anchors/DoD_Certs.pem

echo "[+] Updating system trust store..."
update-ca-trust extract

# 10) Populate the NSS database (for Firefox/Chrome), per-user and system-wide
echo "[+] Importing DoD root CAs into NSS databases..."
USER_NSSDB="$HOME/.pki/nssdb"
mkdir -p "$USER_NSSDB"
chmod 700 "$USER_NSSDB"
SYSTEM_NSSDB="/etc/pki/nssdb"
mkdir -p "$SYSTEM_NSSDB"

for CERTFILE in *.p7b; do
  CERT_NAME="DOD_CA_${CERTFILE%.p7b}"
  echo "    Importing ${CERTFILE} as ${CERT_NAME}..."

  # Per-user NSS DB (so browsers running as your user will trust DoD CAs)
  certutil -A -d "sql:$USER_NSSDB" \
           -t TC \
           -n "$CERT_NAME" \
           -i "$CERTFILE" || true

  # System NSS DB (so system-wide tools like Chrome also see them)
  certutil -A -d "sql:$SYSTEM_NSSDB" \
           -t TC \
           -n "$CERT_NAME" \
           -i "$CERTFILE" || true
done

popd >/dev/null
rm -rf "$TMPDIR"

# 11) Final instructions
cat << 'EOF'

=====================================================
 CAC PREP IS COMPLETE — PLEASE READ THE NEXT STEPS
=====================================================

1) Reboot the VM:

     sudo reboot

2) After reboot, insert your CAC into the reader and run:

     pcsc_scan

   It should display something like:

     Reader 0: … [Contacted SmartCard] …
     Card state: Card inserted, Shared Mode, ATR: XX XX …

   If pcsc_scan shows your card, the middleware is functioning.

3) To use your CAC inside a browser (Firefox/Chrome) you must load the OpenSC PKCS#11 module:

   • Firefox:
       1. Go to ⚙️ Preferences → Privacy & Security → Certificates → Security Devices.
       2. Click “Load”.
       3. Module Name: OpenSC CAC
       4. Module Filename: /usr/lib64/opensc-pkcs11.so
       5. Click OK, then restart Firefox.

   • Google Chrome:
       1. Go to ⋮ menu → Settings → Privacy and security → Security → Manage Certificates.
       2. Select the “Authorities” tab → Import.
       3. Import the chain file you installed: /etc/pki/ca-trust/source/anchors/DoD_Certs.pem.
       4. Then, to enable hardware token support:
          – In the address bar, navigate to chrome://settings/security, scroll to “Manage Certificates” → Security Devices.
          – Click “Load” and point to /usr/lib64/opensc-pkcs11.so as a PKCS#11 module.
       5. Restart Chrome.

4) When prompted for a PIN, use your CAC PIN to authenticate on DoD/CAC-enabled sites.

=====================================================
EOF

