#!/usr/bin/env bash
# Prompt for group or host(s), creds, then run Evaluate-STIG.yml

set -e
cd "$(dirname "$0")"

echo
read -rp "Inventory group or host(s) to scan (e.g. ENT1 or idm1.ent1.pcte.mil,idm2.ent1.pcte.mil)
: " LIMIT
# remove all spaces in case they did "idm1.com, idm2.com"
LIMIT="${LIMIT//[[:space:]]/}"
if [[ -z "$LIMIT" ]]; then
  echo "You must specify at least one group or host."
  exit 1
fi

read -rp "SSH username: " USERNAME
if [[ -z "$USERNAME" ]]; then
  echo "Username cannot be empty."
  exit 1
fi

read -rs -p "Password for $USERNAME: " PASS
echo
if [[ -z "$PASS" ]]; then
  echo "Password cannot be empty."
  exit 1
fi

echo
echo "Running STIG scan against '$LIMIT' as user '$USERNAME'..."
ansible-playbook \
  -i /etc/ansible/inventory/ent_hosts \
  -l "$LIMIT" \
  -u "$USERNAME" \
  --extra-vars "ansible_password=$PASS ansible_become_password=$PASS" \
  -b \
  Evaluate-STIG.yml

