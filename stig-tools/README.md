# STIG Checklist Tools

Utilities for managing, searching, and processing STIG checklist (.ckl) files.

## Scripts

### automate-ckls.py

Globally applies STATUS and COMMENTS from source CKL files to target CKL files with host-aware indexing.

**What it does:**
- Indexes all vulnerabilities from source (Enclave1) CKL files
- Extracts STATUS and COMMENTS for each Vuln_Num
- Uses host-aware matching (prefers same hostname, falls back to global)
- Updates target (Enclave2) CKL files in-place
- Creates automatic backups before modification
- Supports: Open, Not_Reviewed, NotAFinding, Not_Applicable statuses

**Use Case:**
When you have completed CKL files in one environment and need to apply those findings to CKL files in another environment (e.g., promoting from dev to prod).

**Requirements:**
- Python 3.6+
- Source and target directories with .ckl files

**Usage:**
```bash
python3 automate-ckls.py -s /path/to/source/ckls -t /path/to/target/ckls
```

**Arguments:**
- `-s, --source` - Directory containing completed source CKL files
- `-t, --target` - Directory containing target CKL files to update

**Output:**
- Backup created: `backup_<dirname>_<timestamp>.tar.gz`
- Log file: `apply_ckl_comments.log`
- Progress bar showing update progress
- Summary: files scanned, updates applied, missing entries

**Example:**
```bash
# Apply findings from Enclave1 to Enclave2
python3 automate-ckls.py \
  -s /home/user/Enclave1/ckls \
  -t /home/user/Enclave2/ckls
```

---

### ckl-search.sh

Interactive search tool for finding and displaying vulnerabilities within CKL files.

**What it does:**
- Recursively searches all .ckl files in a directory
- Search by V-number or free text
- Filter by status (Open only or all statuses)
- Search in FINDING_DETAILS or COMMENTS fields
- Displays formatted results with status and details

**Requirements:**
- Bash
- xmlstarlet (auto-installs on RHEL if missing)
- CKL files in current directory or subdirectories

**Usage:**
```bash
./ckl-search.sh
```

**Interactive workflow:**
1. Choose to filter only 'Open' STIGs (y/n)
2. Select search field: FINDING_DETAILS or COMMENTS
3. Enter search term:
   - V-number: `V-230224` or `230224`
   - Free text: any string to search for
4. View formatted results
5. Type 'exit' to return to field selection or quit

**Example queries:**
- Search for specific vuln: `V-230224`
- Search for keyword: `password`
- Search for partial match: `ssh`

**Output format:**
```
================================================================================
V-230224  (file: /path/to/file.ckl)
--------------------------------------------------------------------------------
|----------------------------|
| STATUS                     |
|----------------------------|
| Open                       |
|----------------------------|

FINDING_DETAILS:
[Details text here...]
```

---

### compare-ckls.py

Compares two CKL files and exports status mismatches to Excel.

**What it does:**
- Recursively discovers CKL files
- Prompts user to select two files by number
- Compares STATUS for each vulnerability
- Exports mismatches (Open vs NotAFinding) to Excel
- Auto-adjusts column widths for readability

**Use Case:**
When comparing findings between two scans of the same system or between two assessors' reviews.

**Requirements:**
- Python 3
- pandas (auto-installs if missing)
- openpyxl (auto-installs if missing)
- Two or more CKL files in directory tree

**Usage:**
```bash
python3 compare-ckls.py
```

**Interactive workflow:**
1. Script lists all .ckl files found
2. Select first CKL by number
3. Select second CKL by number
4. Script generates Excel file with deltas

**Output:**
- Excel file: `deltas.xlsx`
- Columns:
  - Host - hostname from CKL
  - STIG - STIG title and version
  - SV to discuss - Vulnerability ID
  - CKL1 Status - Status from first file
  - CKL2 Status - Status from second file

**Delta criteria:**
- Only shows Open vs NotAFinding mismatches
- Ignores matching statuses
- Ignores NotApplicable entries
- Sorts with Open items first

---

## Workflow Examples

### Scenario 1: Propagating Findings

You've completed STIGs in Enclave1 and need to apply them to Enclave2:

```bash
# Backup your target CKLs first (optional, script does this)
cp -r Enclave2/ckls Enclave2/ckls.backup

# Apply findings
python3 automate-ckls.py \
  -s Enclave1/ckls \
  -t Enclave2/ckls

# Review log for any missing entries
less apply_ckl_comments.log
```

### Scenario 2: Quick Vulnerability Lookup

You need to find all instances of a specific vulnerability:

```bash
./ckl-search.sh
# Select: Filter Open only? y
# Select field: 1 (FINDING_DETAILS)
# Enter: V-230224
# Review all instances across CKL files
```

### Scenario 3: Comparing Assessments

Two assessors reviewed the same system - compare their findings:

```bash
python3 compare-ckls.py
# Select first assessor's CKL
# Select second assessor's CKL
# Open deltas.xlsx to review discrepancies
```

## File Formats

All tools work with DISA STIG Viewer .ckl files (XML format).

**Supported CKL structure:**
- Standard CHECKLIST schema
- ASSET/HOST_NAME for host identification
- VULN elements with Vuln_Num in STIG_DATA
- STATUS and COMMENTS fields

## Logging

- **automate-ckls.py**: `apply_ckl_comments.log`
- **ckl-search.sh**: stdout only
- **compare-ckls.py**: stdout only

## Troubleshooting

**automate-ckls.py:**
- "No commits yet" errors: Not related to this script
- Missing entries in log: Source CKL doesn't have that Vuln_Num completed
- Backup location: Same directory as script execution

**ckl-search.sh:**
- xmlstarlet errors: Script auto-installs on RHEL
- No results found: Check V-number format or search term
- Namespace issues: Script handles both namespaced and non-namespaced CKLs

**compare-ckls.py:**
- "No deltas found": CKL files have matching statuses
- Excel formatting issues: Ensure openpyxl is installed
- File selection errors: Ensure CKL files exist in directory tree

## Tips

- Always backup CKL files before bulk operations
- Use host-aware features in automate-ckls.py for multi-host environments
- Filter by "Open" status in ckl-search.sh to focus on active findings
- Compare CKLs from same STIG version for accurate deltas
