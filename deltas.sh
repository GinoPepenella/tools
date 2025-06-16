#!/usr/bin/env bash
#
# compare_ckl.sh
#
# FINAL SCRIPT:
#   - Recursively searches for .ckl
#   - Lets user pick 2 from a list each time
#   - Merges them with Evaluate-STIG logic or "Finding"/"Rationale"
#   - Filters to only (O,Manual vs NF,Manual) pairs
#   - Exports as an HTML table (renamed to .xls) with alternating row colors
#
###############################################################################

#######################################
# 0) CHECK FOR DEPENDENCIES
#######################################
if ! command -v xmlstarlet &>/dev/null; then
  echo "[ERROR] 'xmlstarlet' is not installed or not in PATH."
  echo "Please install it, e.g.: sudo yum install -y xmlstarlet"
  exit 1
fi

#######################################
# GLOBAL ARRAY
# We'll store merges as: "host|stig|vuln|ckl1_status|ckl2_status|comment"
#######################################
declare -a ALL_ROWS=()

#######################################
# EVALUATE-STIG HELPER LOGIC
#######################################

extract_xml_value() {
  file="$1"
  xpath_expr="$2"
  xmlstarlet sel -T -t -m "$xpath_expr" -v . -n "$file" 2>/dev/null
}

extract_stig_identifier() {
  file="$1"
  xmlstarlet sel -T -t \
    -m "//STIG_INFO/SI_DATA[SID_NAME='filename']/SID_DATA" \
    -v . -n "$file" 2>/dev/null
}

get_entire_fdetails() {
  file="$1"
  vuln_id="$2"
  xmlstarlet sel -T -t \
    -m "//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA='$vuln_id']" \
    -v "FINDING_DETAILS" -n "$file" 2>/dev/null
}

get_fdetails_between_dashes() {
  file="$1"
  vuln_id="$2"
  all_fdetails="$(get_entire_fdetails "$file" "$vuln_id")"

  echo "$all_fdetails" | awk '
    BEGIN { in_block=0 }
    /-{8,}/ {
      if (in_block == 0) {
        in_block=1; next
      } else {
        in_block=2; next
      }
    }
    in_block == 1 { print }
  '
}

get_comments() {
  file="$1"
  vuln_id="$2"
  xmlstarlet sel -T -t \
    -m "//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA='$vuln_id']" \
    -v "COMMENTS" -n "$file" 2>/dev/null
}

# If there's "Finding:" or "Rationale:" text, return it; else "No relevant text found."
get_finding_or_rationale() {
  file="$1"
  vuln_id="$2"

  comments="$(get_comments "$file" "$vuln_id")"
  IFS=$'\n' read -rd '' -a lines <<< "$comments"

  # 1) Finding:
  i=0
  while [ $i -lt ${#lines[@]} ]; do
    if [[ "${lines[$i]}" =~ [Ff][Ii][Nn][Dd][Ii][Nn][Gg]: ]]; then
      find_text="$(echo "${lines[$i]}" | sed -E 's/.*[Ff][Ii][Nn][Dd][Ii][Nn][Gg]:[[:space:]]*//')"
      if [ -z "$find_text" ]; then
        next_idx=$((i+1))
        if [ $next_idx -lt ${#lines[@]} ]; then
          find_text="${lines[$next_idx]}"
        fi
      fi
      if [ -n "$find_text" ]; then
        echo "$find_text"
        return
      fi
    fi
    i=$((i+1))
  done

  # 2) Rationale:
  i=0
  while [ $i -lt ${#lines[@]} ]; do
    if [[ "${lines[$i]}" =~ [Rr][Aa][Tt][Ii][Oo][Nn][Aa][Ll][Ee]: ]]; then
      rat_text="$(echo "${lines[$i]}" | sed -E 's/.*[Rr][Aa][Tt][Ii][Oo][Nn][Aa][Ll][Ee]:[[:space:]]*//')"
      if [ -z "$rat_text" ]; then
        next_idx=$((i+1))
        if [ $next_idx -lt ${#lines[@]} ]; then
          rat_text="${lines[$next_idx]}"
        fi
      fi
      if [ -n "$rat_text" ]; then
        echo "$rat_text"
        return
      fi
    fi
    i=$((i+1))
  done

  echo "No relevant text found."
}

# "normal_explanation": prefer "Finding"/"Rationale," else lines-between-dashes, else entire <COMMENTS>
normal_explanation() {
  file="$1"
  vuln_id="$2"

  # try "Finding:" or "Rationale:"
  find_rat="$(get_finding_or_rationale "$file" "$vuln_id")"
  if [ "$find_rat" != "No relevant text found." ]; then
    echo "$find_rat"
    return
  fi

  # else lines between dashes
  b_lines="$(get_fdetails_between_dashes "$file" "$vuln_id")"
  if [ -n "$b_lines" ]; then
    echo "$b_lines"
    return
  fi

  # else entire <COMMENTS>
  cdata="$(get_comments "$file" "$vuln_id")"
  if [ -n "$cdata" ]; then
    echo "$cdata"
    return
  fi

  echo "No relevant text found."
}

# Evaluate-STIG => lines between dashes => if <=3 => them; else fallback
extract_reason_text() {
  file="$1"
  vuln_id="$2"

  details="$(get_entire_fdetails "$file" "$vuln_id")"
  shopt -s nocasematch
  if [[ "$details" =~ Evaluate-STIG ]]; then
    b_lines="$(get_fdetails_between_dashes "$file" "$vuln_id")"
    if [ -n "$b_lines" ]; then
      line_count=0
      while read -r _line; do
        line_count=$((line_count+1))
      done <<< "$b_lines"

      if [ $line_count -le 3 ]; then
        echo "$b_lines"
        shopt -u nocasematch
        return
      else
        find_rat="$(get_finding_or_rationale "$file" "$vuln_id")"
        echo "$find_rat"
        shopt -u nocasematch
        return
      fi
    else
      echo "No relevant text found."
      shopt -u nocasematch
      return
    fi
  else
    shopt -u nocasematch
    normal_explanation "$file" "$vuln_id"
  fi
  shopt -u nocasematch
}

# Extract "VulnID|STATUS"
extract_vuln_statuses_to_file() {
  file="$1"
  out_file="$2"
  > "$out_file"

  xmlstarlet sel -T -t \
    -m "//VULN" \
    -v "STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA" -o "|" \
    -v "STATUS" -n \
    "$file" 2>/dev/null >> "$out_file"
}


#######################################
# do_compare => merges 2 CKLs into ALL_ROWS
#######################################
do_compare() {
  ckl1="$1"
  ckl2="$2"

  host_name="$(extract_xml_value "$ckl1" "//CHECKLIST/ASSET/HOST_NAME")"
  short_stig="$(extract_stig_identifier "$ckl1")"

  tmp1="$(mktemp)"
  tmp2="$(mktemp)"
  extract_vuln_statuses_to_file "$ckl1" "$tmp1"
  extract_vuln_statuses_to_file "$ckl2" "$tmp2"

  declare -A ckl1_map=()
  declare -A ckl2_map=()

  while IFS= read -r line; do
    vid="$(echo "$line" | cut -d'|' -f1)"
    st="$(echo "$line" | cut -d'|' -f2-)"
    ckl1_map["$vid"]="$st"
  done < "$tmp1"

  while IFS= read -r line; do
    vid="$(echo "$line" | cut -d'|' -f1)"
    st="$(echo "$line" | cut -d'|' -f2-)"
    ckl2_map["$vid"]="$st"
  done < "$tmp2"

  rm -f "$tmp1" "$tmp2"

  declare -A union_vulns=()
  for v in "${!ckl1_map[@]}"; do union_vulns["$v"]=1; done
  for v in "${!ckl2_map[@]}"; do union_vulns["$v"]=1; done

  for vuln_id in "${!union_vulns[@]}"; do
    s1="${ckl1_map[$vuln_id]}"
    s2="${ckl2_map[$vuln_id]}"

    # skip if both missing or both same
    if [ -z "$s1" ] && [ -z "$s2" ]; then
      continue
    fi
    if [ -n "$s1" ] && [ -n "$s2" ] && [ "$s1" = "$s2" ]; then
      continue
    fi

    ckl1_status=""
    ckl2_status=""
    comment=""

    # interpret "Open" => "O,Manual"; "NotAFinding" => "NF,Manual"
    if [ -n "$s1" ]; then
      short_s1=""
      if [[ "$s1" =~ [Oo]pen ]]; then
        short_s1="O,Manual"
      elif [[ "$s1" =~ [Nn]ot[Aa]?[Ff]inding ]]; then
        short_s1="NF,Manual"
      fi
      ckl1_status="$short_s1"

      # if open => parse Evaluate-STIG or "Finding"/"Rationale"
      if [ "$short_s1" = "O,Manual" ]; then
        reason1="$(extract_reason_text "$ckl1" "$vuln_id")"
        comment="CKL1 - $reason1"
      fi
    fi

    if [ -n "$s2" ]; then
      short_s2=""
      if [[ "$s2" =~ [Oo]pen ]]; then
        short_s2="O,Manual"
      elif [[ "$s2" =~ [Nn]ot[Aa]?[Ff]inding ]]; then
        short_s2="NF,Manual"
      fi
      ckl2_status="$short_s2"

      if [ "$short_s2" = "O,Manual" ]; then
        reason2="$(extract_reason_text "$ckl2" "$vuln_id")"
        if [ -n "$comment" ]; then
          comment+="; CKL2 - $reason2"
        else
          comment="CKL2 - $reason2"
        fi
      fi
    fi

    [ -z "$ckl1_status" ] && ckl1_status="Vul_ID not found."
    [ -z "$ckl2_status" ] && ckl2_status="Vul_ID not found."

    ALL_ROWS+=("$host_name|$short_stig|$vuln_id|$ckl1_status|$ckl2_status|$comment")
  done
}

#######################################
# filter => only keep (O,Manual vs NF,Manual) or (NF,Manual vs O,Manual),
#           skip "Vul_ID not found."
#######################################
filter_relevant_rows() {
  filtered=()
  for row in "${ALL_ROWS[@]}"; do
    c1="$(echo "$row" | cut -d'|' -f4)"
    c2="$(echo "$row" | cut -d'|' -f5)"
    # skip if c1 or c2 = Vul_ID not found.
    if [ "$c1" = "Vul_ID not found." ] || [ "$c2" = "Vul_ID not found." ]; then
      continue
    fi
    # keep only (O,Manual,NF,Manual) or (NF,Manual,O,Manual)
    if [ "$c1" = "O,Manual" ] && [ "$c2" = "NF,Manual" ]; then
      filtered+=("$row")
    elif [ "$c1" = "NF,Manual" ] && [ "$c2" = "O,Manual" ]; then
      filtered+=("$row")
    fi
  done
  ALL_ROWS=( "${filtered[@]}" )
}

#######################################
# sort => bubble by ckl1_status
#######################################
ckl1_status_priority() {
  s="$1"
  case "$s" in
    "O,Manual") echo 1 ;;
    "NF,Manual") echo 2 ;;
    *) echo 4 ;;
  esac
}

sort_all_rows() {
  n=${#ALL_ROWS[@]}
  if [ $n -lt 2 ]; then
    return
  fi

  swapped=1
  while [ $swapped -eq 1 ]; do
    swapped=0
    for (( i=0; i<n-1; i++ )); do
      rowA="${ALL_ROWS[$i]}"
      rowB="${ALL_ROWS[$((i+1))]}"
      a_ckl1="$(echo "$rowA" | cut -d'|' -f4)"
      b_ckl1="$(echo "$rowB" | cut -d'|' -f4)"
      pa="$(ckl1_status_priority "$a_ckl1")"
      pb="$(ckl1_status_priority "$b_ckl1")"
      if [ "$pa" -gt "$pb" ]; then
        temp="${ALL_ROWS[$i]}"
        ALL_ROWS[$i]="${ALL_ROWS[$((i+1))]}"
        ALL_ROWS[$((i+1))]="$temp"
        swapped=1
      fi
    done
  done
}

#######################################
# produce an HTML table => rename to .xls
# with ALTERNATING ROW COLORS
#######################################
write_excel_html() {
  out_html="deltas.html"
  out_xls="deltas.xls"

  cat <<EOF > "$out_html"
<html>
<head>
<meta charset="UTF-8">
<style>
table {
  border-collapse: collapse;
}
th, td {
  border: 1px solid #888;
  padding: 6px;
  vertical-align: top;
}
/* Title */
h2 {
  margin-bottom: 12px;
}
/* Alternate row colors */
tbody tr:nth-child(even) {
  background-color: #F7F7F7;
}
tbody tr:nth-child(odd) {
  background-color: #FFFFFF;
}
</style>
</head>
<body>
<h2>Deltas</h2>
<table>
<thead>
<tr>
  <th>Host</th>
  <th>STIG</th>
  <th>SV to discuss</th>
  <th>CKL1 Status</th>
  <th>CKL2 Status</th>
  <th>Comment</th>
</tr>
</thead>
<tbody>
EOF

  for row in "${ALL_ROWS[@]}"; do
    host="$(echo "$row" | cut -d'|' -f1 | sed 's/&/&amp;/g; s/\"/&quot;/g')"
    stig="$(echo "$row" | cut -d'|' -f2 | sed 's/&/&amp;/g; s/\"/&quot;/g')"
    vuln="$(echo "$row" | cut -d'|' -f3 | sed 's/&/&amp;/g; s/\"/&quot;/g')"
    c1="$(echo "$row"   | cut -d'|' -f4 | sed 's/&/&amp;/g; s/\"/&quot;/g')"
    c2="$(echo "$row"   | cut -d'|' -f5 | sed 's/&/&amp;/g; s/\"/&quot;/g')"
    cmt="$(echo "$row"  | cut -d'|' -f6- | sed 's/&/&amp;/g; s/\"/&quot;/g')"

    echo "<tr>" >> "$out_html"
    echo "  <td>$host</td>" >> "$out_html"
    echo "  <td>$stig</td>" >> "$out_html"
    echo "  <td>$vuln</td>" >> "$out_html"
    echo "  <td>$c1</td>"   >> "$out_html"
    echo "  <td>$c2</td>"   >> "$out_html"
    echo "  <td>$cmt</td>"  >> "$out_html"
    echo "</tr>" >> "$out_html"
  done

  cat <<EOF >> "$out_html"
</tbody>
</table>
</body>
</html>
EOF

  mv "$out_html" "$out_xls"
  echo
  echo "==== EXCEL EXPORT ===="
  echo "[INFO] Renamed HTML table to '$out_xls' - open in Excel for alternating row colors."
}

#######################################
# MAIN
#######################################
echo
echo "[INFO] Searching recursively for .ckl files..."
mapfile -t ckl_files < <(find . -type f -iname '*.ckl' 2>/dev/null)
if [ ${#ckl_files[@]} -eq 0 ]; then
  echo "[ERROR] No CKL files found. Exiting."
  exit 1
fi
echo "[INFO] Found ${#ckl_files[@]} .ckl file(s)."

while true; do
  echo
  echo "AVAILABLE CKLs (recursive search):"
  i=0
  while [ $i -lt ${#ckl_files[@]} ]; do
    num=$((i+1))
    echo "  $num) ${ckl_files[$i]}"
    i=$((i+1))
  done

  echo
  echo "Select the number for the FIRST .ckl file:"
  read -r NUM1
  if ! [[ "$NUM1" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] Invalid numeric choice. Try again."
    continue
  fi
  if [ $NUM1 -lt 1 ] || [ $NUM1 -gt ${#ckl_files[@]} ]; then
    echo "[ERROR] Out of range. Try again."
    continue
  fi
  CKL1="${ckl_files[$((NUM1-1))]}"

  echo
  echo "Select the number for the SECOND .ckl file:"
  read -r NUM2
  if ! [[ "$NUM2" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] Invalid numeric choice. Try again."
    continue
  fi
  if [ $NUM2 -lt 1 ] || [ $NUM2 -gt ${#ckl_files[@]} ]; then
    echo "[ERROR] Out of range. Try again."
    continue
  fi
  CKL2="${ckl_files[$((NUM2-1))]}"

  echo
  echo "[INFO] Merging '$CKL1' vs. '$CKL2'..."
  do_compare "$CKL1" "$CKL2"
  echo "[INFO] Differences appended in memory."

  echo
  echo "Compare another pair? (y/n):"
  read -r AGAIN
  if [[ "$AGAIN" != [Yy]* ]]; then
    echo
    echo "===== DONE MERGING: Filtering & Exporting to Excel ====="
    # 1) keep only (O,Manual vs NF,Manual) or (NF,Manual vs O,Manual)
    filter_relevant_rows
    # 2) sort so CKL1=O first, then CKL1=NF
    sort_all_rows
    # 3) produce an HTML table => rename to .xls
    write_excel_html
    exit 0
  fi
done
