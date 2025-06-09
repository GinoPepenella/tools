#!/usr/bin/env python3
"""
automate.py

Globally index all STATUS & COMMENTS from Enclave1 .CKLs by Vuln_Num,
then apply them to every matching VULN in Enclave2, touching only
<STATUS> and <COMMENTS> in place (so schema/formatting never breaks).

– Strips namespaces when indexing.
– Matches <VULN ...> tags with attributes.
– Shows a 40-char progress bar.
"""

import os, sys
import argparse
import datetime
import tarfile
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

LOGFILE = "apply_ckl_comments.log"
INDEX_STATUSES = {"Open", "Not_Reviewed", "NotAFinding"}
UPDATE_STATUSES = {"Open", "Not_Reviewed", "NotAFinding"}

def log(msg):
    with open(LOGFILE, "a") as f:
        f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")

def find_ckl_files(root):
    for dp, _, files in os.walk(root):
        for fn in files:
            if fn.lower().endswith(".ckl"):
                yield os.path.join(dp, fn)

def strip_ns(elem):
    """Remove all namespace prefixes in-place so we can do tag searches."""
    for e in elem.iter():
        if isinstance(e.tag, str) and '}' in e.tag:
            e.tag = e.tag.split('}',1)[1]
    return elem

def build_global_index(src_dir):
    status_map = {}
    comment_map = {}

    for path in find_ckl_files(src_dir):
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            strip_ns(root)
        except Exception as e:
            log(f"[ERROR] parsing source {path}: {e}")
            continue

        for vuln in root.findall(".//VULN"):
            # find the Vuln_Num
            sv = None
            for sd in vuln.findall("STIG_DATA"):
                if sd.findtext("VULN_ATTRIBUTE","").strip() == "Vuln_Num":
                    sv = sd.findtext("ATTRIBUTE_DATA","").strip()
                    break
            if not sv:
                continue

            st = vuln.findtext("STATUS","").strip()
            if st not in INDEX_STATUSES:
                continue

            cm = vuln.findtext("COMMENTS","").strip()
            status_map[sv]  = st
            comment_map[sv] = cm

    log(f"[INDEX] {len(status_map)} total Vuln_Num mappings")
    return status_map, comment_map

def backup_target(tgt):
    ts   = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.basename(os.path.abspath(tgt.rstrip("/")))
    arc  = f"backup_{base}_{ts}.tar.gz"
    with tarfile.open(arc,"w:gz") as tar:
        tar.add(tgt, arcname=base)
    print(f"Backup of '{tgt}' → ./{arc}")
    log(f"[BACKUP] {arc}")

def print_progress(current, total, bar_len=40):
    filled = int(round(bar_len * current / float(total)))
    bar = "=" * filled + "-" * (bar_len - filled)
    perc = round(100.0 * current / float(total), 1)
    print(f"\r[{bar}] {current}/{total} ({perc}%)", end="", flush=True)

def update_vuln_block(block, new_status, new_comment):
    nc = escape(new_comment)
    # replace STATUS
    block = re.sub(
        r'(<STATUS>)(.*?)(</STATUS>)',
        lambda m: f"{m.group(1)}{new_status}{m.group(3)}",
        block, count=1, flags=re.DOTALL
    )
    # replace or insert COMMENTS
    if re.search(r'<COMMENTS\s*/\s*>', block):
        block = re.sub(
            r'<COMMENTS\s*/\s*>',
            lambda m: f"<COMMENTS>{nc}</COMMENTS>",
            block, count=1
        )
    elif re.search(r'<COMMENTS>.*?</COMMENTS>', block, flags=re.DOTALL):
        block = re.sub(
            r'(<COMMENTS>)(.*?)(</COMMENTS>)',
            lambda m: f"{m.group(1)}{nc}{m.group(3)}",
            block, count=1, flags=re.DOTALL
        )
    else:
        block = re.sub(
            r'(</STATUS>)',
            lambda m: f"{m.group(1)}<COMMENTS>{nc}</COMMENTS>",
            block, count=1
        )
    return block

def apply_updates(target_dir, status_map, comment_map):
    files_list = list(find_ckl_files(target_dir))
    total_files = len(files_list)
    total_updates = total_missing = 0

    # match any <VULN ...> ... </VULN> block
    vuln_block_re = re.compile(r'(<VULN\b[^>]*>.*?</VULN>)', flags=re.DOTALL)
    # find Vuln_Num in a block
    sv_re  = re.compile(
        r'<VULN_ATTRIBUTE>\s*Vuln_Num\s*</VULN_ATTRIBUTE>\s*'
        r'<ATTRIBUTE_DATA>\s*(V-\d+)\s*</ATTRIBUTE_DATA>',
        flags=re.DOTALL
    )
    # find current STATUS
    old_re = re.compile(r'<STATUS>\s*(\S+)\s*</STATUS>')

    print(f"Updating {total_files} CKLs:")
    for idx, path in enumerate(files_list, start=1):
        text = open(path, "r", encoding="utf-8").read()
        orig = text

        def repl(m):
            nonlocal total_updates, total_missing
            blk = m.group(1)

            msv = sv_re.search(blk)
            if not msv:
                return blk
            sv = msv.group(1)

            mold = old_re.search(blk)
            if not mold or mold.group(1) not in UPDATE_STATUSES:
                return blk

            if sv not in status_map:
                total_missing += 1
                log(f"[MISS] {sv} in {path}")
                return blk

            new_st = status_map[sv]
            new_cm = comment_map[sv]
            new_blk = update_vuln_block(blk, new_st, new_cm)
            if new_blk != blk:
                total_updates += 1
            return new_blk

        text = vuln_block_re.sub(repl, text)
        if text != orig:
            with open(path, "w", encoding="utf-8") as w:
                w.write(text)

        print_progress(idx, total_files)

    print()  # newline
    return total_files, total_updates, total_missing

def main():
    if sys.version_info < (3,6):
        print("ERROR: requires Python 3.6+"); sys.exit(1)

    p = argparse.ArgumentParser(
        description="Globally apply CKL COMMENTS/STATUS from Enclave1 → Enclave2"
    )
    p.add_argument("-s","--source", required=True, help="Enclave1 CKL directory")
    p.add_argument("-t","--target", required=True, help="Enclave2 CKL directory")
    args = p.parse_args()

    open(LOGFILE, "w").close()
    log(f"START source={args.source} target={args.target}")

    sm, cm = build_global_index(args.source)
    backup_target(args.target)
    f,u,m = apply_updates(args.target, sm, cm)

    summary = f"Files scanned: {f}; Total updates: {u}; Missing entries: {m} (see {LOGFILE})"
    print(summary)
    log(f"[END] {summary}")

if __name__ == "__main__":
    main()
