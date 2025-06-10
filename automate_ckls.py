#!/usr/bin/env python3
"""
automate_ckls.py
Globally index all STATUS & COMMENTS from Enclave1 .CKLs by Vuln_Num (with host-aware indexing), then apply them to every matching VULN in Enclave2, touching only <STATUS> and <COMMENTS> in place (so schema/formatting never breaks).

Features:
 - Strips namespaces when indexing.
 - Matches <VULN> tags with attributes.
 - Host-aware indexing: prefer comments from matching HOST_NAME, fallback to other sources if missing.
 - Shows a 40-char progress bar.
 - Now supports Not_Applicable status for indexing and updating.
"""

import os
import sys
import argparse
import datetime
import tarfile
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

LOGFILE = "apply_ckl_comments.log"
# Include Not_Applicable in statuses to index and update
INDEX_STATUSES = {"Open", "Not_Reviewed", "NotAFinding", "Not_Applicable"}
UPDATE_STATUSES = {"Open", "Not_Reviewed", "NotAFinding", "Not_Applicable"}


def log(msg):
    """Append a timestamped message to the log file."""
    with open(LOGFILE, "a") as f:
        f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")


def find_ckl_files(root):
    """Yield all .ckl files under the given root directory."""
    for dp, _, files in os.walk(root):
        for fn in files:
            if fn.lower().endswith(".ckl"):
                yield os.path.join(dp, fn)


def strip_ns(elem):
    """Remove all namespace prefixes in-place so we can do tag searches."""
    for e in elem.iter():
        if isinstance(e.tag, str) and '}' in e.tag:
            e.tag = e.tag.split('}', 1)[1]
    return elem


def build_global_index(src_dir):
    """
    Build host-aware and global indices of VULN comments and statuses.

    Returns:
      host_status_map: dict of {hostname: {Vuln_Num: status}}
      host_comment_map: dict of {hostname: {Vuln_Num: comment}}
      global_status_map: dict of {Vuln_Num: status} (first-seen)
      global_comment_map: dict of {Vuln_Num: comment} (first-seen)
    """
    host_status_map = {}
    host_comment_map = {}
    global_status_map = {}
    global_comment_map = {}

    for path in find_ckl_files(src_dir):
        try:
            tree = ET.parse(path)
            root = strip_ns(tree.getroot())
        except Exception as e:
            log(f"[ERROR] parsing source {path}: {e}")
            continue

        # Extract HOST_NAME for this CKL
        host = root.findtext("ASSET/HOST_NAME", default="").strip() or "UNKNOWN"
        host_status_map.setdefault(host, {})
        host_comment_map.setdefault(host, {})

        for vuln in root.findall(".//VULN"):
            # find the Vuln_Num
            sv = None
            for sd in vuln.findall("STIG_DATA"):
                if sd.findtext("VULN_ATTRIBUTE", default="").strip() == "Vuln_Num":
                    sv = sd.findtext("ATTRIBUTE_DATA", default="").strip()
                    break
            if not sv:
                continue

            st = vuln.findtext("STATUS", default="").strip()
            if st not in INDEX_STATUSES:
                continue

            cm = vuln.findtext("COMMENTS", default="").strip()

            # Store host-specific mapping
            host_status_map[host][sv] = st
            host_comment_map[host][sv] = cm

            # Store global mapping if first-seen
            if sv not in global_status_map:
                global_status_map[sv] = st
                global_comment_map[sv] = cm

    log(f"[INDEX] Indexed hosts: {list(host_status_map.keys())}")
    log(f"[INDEX] Total unique Vuln_Num: {len(global_status_map)}")
    return host_status_map, host_comment_map, global_status_map, global_comment_map


def backup_target(tgt):
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.basename(os.path.abspath(tgt.rstrip("/")))
    arc = f"backup_{base}_{ts}.tar.gz"
    with tarfile.open(arc, "w:gz") as tar:
        tar.add(tgt, arcname=base)
    print(f"Backup of '{tgt}' → ./{arc}")
    log(f"[BACKUP] {arc}")


def print_progress(current, total, bar_len=40):
    filled = int(round(bar_len * current / float(total)))
    bar = "=" * filled + "-" * (bar_len - filled)
    perc = round(100.0 * current / float(total), 1)
    print(f"\r[{bar}] {current}/{total} ({perc}%)", end="", flush=True)


def update_vuln_block(block, new_status, new_comment):
    """Replace STATUS and COMMENTS in the XML block string."""
    nc = escape(new_comment)
    # update STATUS
    block = re.sub(
        r'(<STATUS>)(.*?)(</STATUS>)',
        lambda m: f"{m.group(1)}{new_status}{m.group(3)}",
        block,
        count=1,
        flags=re.DOTALL,
    )
    # update or insert COMMENTS
    if re.search(r'<COMMENTS>.*?</COMMENTS>', block, flags=re.DOTALL):
        block = re.sub(
            r'(<COMMENTS>)(.*?)(</COMMENTS>)',
            lambda m: f"{m.group(1)}{nc}{m.group(3)}",
            block,
            count=1,
            flags=re.DOTALL,
        )
    else:
        # insert COMMENTS after STATUS
        block = re.sub(
            r'(</STATUS>)',
            lambda m: f"{m.group(1)}<COMMENTS>{nc}</COMMENTS>",
            block,
            count=1,
            flags=re.DOTALL,
        )
    return block


def apply_updates(target_dir, host_status_map, host_comment_map, global_status_map, global_comment_map):
    """
    Update each CKL in target_dir, using host-aware mappings first, then fallback to global mappings.

    Returns: total files, total updates, total missing
    """
    files_list = list(find_ckl_files(target_dir))
    total_files = len(files_list)
    total_updates = 0
    total_missing = 0

    # regex to extract each VULN block
    vuln_block_re = re.compile(r'(<VULN[\s\S]*?</VULN>)', flags=re.DOTALL)
    sv_re = re.compile(r'<STIG_DATA>\s*<VULN_ATTRIBUTE>\s*Vuln_Num\s*</VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>(V-\d+)</ATTRIBUTE_DATA>', flags=re.DOTALL)
    old_re = re.compile(r'<STATUS>(.*?)</STATUS>', flags=re.DOTALL)

    print(f"Updating {total_files} CKLs:")
    for idx, path in enumerate(files_list, start=1):
        text = open(path, "r", encoding="utf-8").read()
        orig = text

        # Extract target host
        try:
            root = strip_ns(ET.fromstring(text))
            cur_host = root.findtext("ASSET/HOST_NAME", default="").strip() or "UNKNOWN"
        except Exception:
            cur_host = "UNKNOWN"

        def repl(m):
            nonlocal total_updates, total_missing
            blk = m.group(1)
            msv = sv_re.search(blk)
            if not msv:
                return blk
            sv = msv.group(1)

            mold = old_re.search(blk)
            if not mold or mold.group(1).strip() not in UPDATE_STATUSES:
                return blk

            # Determine new status/comment (host-aware)
            new_st = None
            new_cm = None
            # try host-specific
            if sv in host_status_map.get(cur_host, {}):
                new_st = host_status_map[cur_host][sv]
                new_cm = host_comment_map[cur_host][sv]
            # fallback to others if host-specific missing or empty
            if (new_cm is None or new_cm == "") and sv in global_comment_map:
                new_st = new_st or global_status_map.get(sv)
                new_cm = global_comment_map.get(sv)

            if new_st is None or new_cm is None:
                total_missing += 1
                log(f"[MISS] {sv} in {path} (host={cur_host})")
                return blk

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
    if sys.version_info < (3, 6):
        print("ERROR: requires Python 3.6+")
        sys.exit(1)

    p = argparse.ArgumentParser(
        description="Globally apply CKL COMMENTS/STATUS from Enclave1 → Enclave2 (host-aware)"
    )
    p.add_argument(
        "-s", "--source", required=True, help="Enclave1 CKL directory"
    )
    p.add_argument(
        "-t", "--target", required=True, help="Enclave2 CKL directory"
    )
    args = p.parse_args()

    # clear previous log
    open(LOGFILE, "w").close()
    log(f"START source={args.source} target={args.target}")

    hs_map, hc_map, gs_map, gc_map = build_global_index(args.source)
    backup_target(args.target)
    f, u, m = apply_updates(args.target, hs_map, hc_map, gs_map, gc_map)

    summary = (
        f"Files scanned: {f}; Total updates: {u}; Missing entries: {m} (see {LOGFILE})"
    )
    print(summary)
    log(f"[END] {summary}")


if __name__ == "__main__":
    main()
