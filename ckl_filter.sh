#!/bin/bash

# Check if xmlstarlet is installed; if not, install it
if ! command -v xmlstarlet >/dev/null 2>&1; then
    if [ -f /etc/redhat-release ]; then
        sudo yum install -y xmlstarlet >/dev/null 2>&1
    else
        echo "Unsupported OS. Please install xmlstarlet manually."
        exit 1
    fi
fi

# Base directory to search
DIRECTORY="."  # you can change this to any path

# Ask user whether to filter only 'Open' STIGs
while true; do
    read -p "Search only STIGs with status 'Open'? (y/n, default n): " choice
    case "${choice,,}" in
        y|yes) OPEN_ONLY=1; break;;
        n|no|"") OPEN_ONLY=0; break;;
        exit|quit) echo "Exiting."; exit 0;;
        *) echo "Please answer y or n.";;
    esac
done

# Field selection loop
while true; do
    echo
    echo "Where would you like to search?"
    echo "  1) FINDING_DETAILS"
    echo "  2) COMMENTS"
    echo "Type 'exit' or 'quit' to leave."
    read -p "Enter choice: " field_choice

    if [[ "$field_choice" =~ ^(exit|quit)$ ]]; then
        echo "Exiting."
        break
    fi

    while [[ "$field_choice" != "1" && "$field_choice" != "2" ]]; do
        read -p "Invalid choice. Enter 1 or 2 (or 'exit'): " field_choice
        [[ "$field_choice" =~ ^(exit|quit)$ ]] && { echo "Exiting."; exit 0; }
    done

    if [ "$field_choice" == "1" ]; then
        field_name="FINDING_DETAILS"
    else
        field_name="COMMENTS"
    fi

    # Main search loop
    while true; do
        read -p $'\n'"Enter a V-number (e.g., 230224), any text to search, or 'exit': " input
        [[ "$input" =~ ^(exit|quit)$ ]] && { echo "Returning to field menu."; break; }

        input="${input##+([[:space:]])}"
        input="${input%%+([[:space:]])}"

        found=0
        if [[ "$input" =~ ^[0-9]{6}$ ]]; then
            v_number="V-$input"
            search_type="vuln_num"
        elif [[ "$input" =~ ^V-[0-9]{6}$ ]]; then
            v_number="$input"
            search_type="vuln_num"
        else
            search_string="$(echo "$input" | tr '[:upper:]' '[:lower:]')"
            search_type="search_string"
        fi

        # Recursively iterate .ckl files
        while IFS= read -r -d '' file; do
            ns=$(xmlstarlet sel -t -m "/*" -v "namespace-uri()" -n "$file" 2>/dev/null)
            if [ -n "$ns" ]; then
                ns_prefix="ns"
                namespace_option="-N ${ns_prefix}=${ns}"
            else
                ns_prefix=""
                namespace_option=""
            fi

            # Build XPaths
            if [ "$search_type" == "vuln_num" ]; then
                if [ -n "$ns_prefix" ]; then
                    vuln_xpath="//${ns_prefix}:VULN[${ns_prefix}:STIG_DATA[${ns_prefix}:VULN_ATTRIBUTE='Vuln_Num']/${ns_prefix}:ATTRIBUTE_DATA='$v_number']"
                else
                    vuln_xpath="//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num']/ATTRIBUTE_DATA='$v_number']"
                fi
            else
                esc=$(printf '%s' "$search_string" | sed 's/"/\\"/g')
                if [ -n "$ns_prefix" ]; then
                    vuln_xpath="//${ns_prefix}:VULN[( ${ns_prefix}:STIG_DATA/${ns_prefix}:ATTRIBUTE_DATA[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), \"$esc\")] or ${ns_prefix}:${field_name}[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), \"$esc\")] )]"
                else
                    vuln_xpath="//VULN[( STIG_DATA/ATTRIBUTE_DATA[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), \"$esc\")] or ${field_name}[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), \"$esc\")] )]"
                fi
            fi

            count=$(xmlstarlet sel $namespace_option -t -v "count($vuln_xpath)" "$file" 2>/dev/null)
            (( count == 0 )) && continue

            for i in $(seq 1 $count); do
                # Extract fields
                if [ -n "$ns_prefix" ]; then
                    base="${ns_prefix}:"
                else
                    base=""
                fi

                vuln_num=$(xmlstarlet sel $namespace_option -t -v "($vuln_xpath/${base}STIG_DATA[${base}VULN_ATTRIBUTE='Vuln_Num']/${base}ATTRIBUTE_DATA)[$i]" "$file")
                status=$(xmlstarlet sel $namespace_option -t -v "($vuln_xpath/${base}STATUS)[$i]" "$file")
                detail=$(xmlstarlet sel $namespace_option -t -v "($vuln_xpath/${base}${field_name})[$i]" "$file")
                status=${status:-"[No STATUS provided]"}

                # If filtering only Open, skip others
                if [ "$OPEN_ONLY" -eq 1 ] && [[ "$status" != "Open" ]]; then
                    continue
                fi

                # Print output
                echo
                echo "================================================================================"
                echo "$vuln_num  (file: $file)"
                echo "--------------------------------------------------------------------------------"
                echo "|----------------------------|"
                echo "| STATUS                     |"
                echo "|----------------------------|"
                printf "| %-26s|\n" "$status"
                echo "|----------------------------|"
                echo
                echo "$field_name:"
                if [ -n "$detail" ]; then
                    echo "$detail"
                else
                    echo "[No $field_name provided]"
                fi
                echo
                found=1
            done
        done < <(find "$DIRECTORY" -type f -name '*.ckl' -print0)

        if [ $found -eq 0 ]; then
            if [ "$search_type" == "vuln_num" ]; then
                echo "Vulnerability $v_number not found."
            else
                echo "No vulnerabilities found containing \"$input\"."
            fi
        fi
    done
done
