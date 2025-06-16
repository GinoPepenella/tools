#!/usr/bin/env bash
#
# deltas.sh — compare_ckl.sh with CRLF-fix bootstrap
#

# ───────────────────────────────────────────────────────────────────────────────
# 0) ENSURE UNIX LINE ENDINGS
#    If this script was checked out with Windows CRLF, strip the CRs and
#    re-exec itself under bash with the corrected contents.
# ───────────────────────────────────────────────────────────────────────────────
if grep -q $'\r' "$0"; then
  echo "[INFO] Converting CRLF → LF in script and re-executing..."
  sed -i 's/\r$//' "$0"
  exec bash "$0" "$@
fi

# ───────────────────────────────────────────────────────────────────────────────
# 1) CHECK FOR DEPENDENCIES
# ───────────────────────────────────────────────────────────────────────────────
if ! command -v xmlstarlet &>/dev/null; then
  echo "[ERROR] 'xmlstarlet' is not installed or not in PATH."
  echo "Please install it, e.g.: sudo yum install -y xmlstarlet"
  exit 1
fi

# ───────────────────────────────────────────────────────────────────────────────
# 2) GLOBAL ARRAY
#    We'll store merges as: "host|stig|vuln|ckl1_status|ckl2_status|comment"
# ───────────────────────────────────────────────────────────────────────────────
declare -a ALL_ROWS=()

# ───────────────────────────────────────────────────────────────────────────────
# 3) EVALUATE-STIG HELPER LOGIC
# ───────────────────────────────────────────────────────────────────────────────
extract_xml_value() {
  file="$1"; xpath_expr="$2"
  xmlstarlet sel -T -t -m "$xpath_expr" -v . -n "$file" 2>/dev/null
}
extract_stig_identifier() {
  file="$1"
  xmlstarlet sel -T -t \
    -m "//STIG_INFO/SI_DATA[SID_NAME='filename']/SID_DATA" \
    -v . -n "$file" 2>/dev/null
}
get_entire_fdetails() {
  file="$1"; vuln_id="$2"
  xmlstarlet sel -T -t \
    -m "//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA='$vuln_id']" \
    -v "FINDING_DETAILS" -n "$file" 2>/dev/null
}
get_fdetails_between_dashes() {
  file="$1"; vuln_id="$2"
  all_fdetails="$(get_entire_fdetails "$file" "$vuln_id")"
  echo "$all_fdetails" | awk '
    BEGIN { in_block=0 }
    /-{8,}/ {
      if (in_block == 0) { in_block=1; next }
      else              { in_block=2; next }
    }
    in_block == 1 { print }
  '
}
get_comments() {
  file="$1"; vuln_id="$2"
  xmlstarlet sel -T -t \
    -m "//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA='$vuln_id']" \
    -v "COMMENTS" -n "$file" 2>/dev/null
}
get_finding_or_rationale() {
  file="$1"; vuln_id="$2"
  comments="$(get_comments "$file" "$vuln_id")"
  IFS=$'\n' read -rd '' -a lines <<< "$comments"
  # 1) Finding:
  for i in "${!lines[@]}"; do
    if [[ "${lines[$i]}" =~ [Ff][Ii][Nn][Dd][Ii][Nn][Gg]: ]]; then
      find_text="${lines[$i]#*}:"
      [[ -z "$find_text" && $((i+1)) -lt ${#lines[@]} ]] && find_text="${lines[$((i+1))]}"
      [[ -n "$find_text" ]] && { echo "$find_text"; return; }
    fi
  done
  # 2) Rationale:
  for i in "${!lines[@]}"; do
    if [[ "${lines[$i]}" =~ [Rr][Aa][Tt][Ii][Oo][Nn][Aa][Ll][Ee]: ]]; then
      rat_text="${lines[$i]#*}:"
      [[ -z "$rat_text" && $((i+1)) -lt ${#lines[@]} ]] && rat_text="${lines[$((i+1))]}"
      [[ -n "$rat_text" ]] && { echo "$rat_text"; return; }
    fi
  done
  echo "No relevant text found."
}
normal_explanation() {
  file="$1"; vuln_id="$2"
  find_rat="$(get_finding_or_rationale "$file" "$vuln_id")"
  [[ "$find_rat" != "No relevant text found." ]] && { echo "$find_rat"; return; }
  b_lines="$(get_fdetails_between_dashes "$file" "$vuln_id")"
  [[ -n "$b_lines" ]] && { echo "$b_lines"; return; }
  cdata="$(get_comments "$file" "$vuln_id")"
  [[ -n "$cdata" ]] && { echo "$cdata"; return; }
  echo "No relevant text found."
}
extract_reason_text() {
  file="$1"; vuln_id="$2"
  details="$(get_entire_fdetails "$file" "$vuln_id")"
  shopt -s nocasematch
  if [[ "$details" =~ Evaluate-STIG ]]; then
    b_lines="$(get_fdetails_between_dashes "$file" "$vuln_id")"
    if [[ -n "$b_lines" ]]; then
      line_count=$(grep -c '^' <<<"$b_lines")
      if (( line_count <= 3 )); then
        echo "$b_lines"; shopt -u nocasematch; return
      else
        echo "$(get_finding_or_rationale "$file" "$vuln_id")"; shopt -u nocasematch; return
      fi
    else
      echo "No relevant text found."; shopt -u nocasematch; return
    fi
  else
    shopt -u nocasematch
    normal_explanation "$file" "$vuln_id"
  fi
}

# (Remaining functions do_compare, filter_relevant_rows, sort_all_rows,
#  write_excel_html and the MAIN loop are unchanged from your original script.)
