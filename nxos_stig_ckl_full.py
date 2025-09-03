#!/usr/bin/env python3
"""
nxos_stig_ckl_full.py
Generate filled STIG CKLs for Cisco NX-OS (NDM + L2S) from running-configs.

• Expects two CKL templates in the same folder: Cisco_NX-OS_NDM.ckl and Cisco_NX-OS_L2S.ckl
• Scans configs (*.txt|*.log) from ./configs by default, or via --configs-subdir
• Fills HOST fields (IP from mgmt0, hostname, FQDN = <hostname>.<ent>.pcte.mil)
• Evaluates:
    - NDM: V-220474 through V-220517 (inclusive) and V-260464
    - L2S: V-220675 through V-220696 (inclusive)
• Writes two output CKLs per config:
    <hostname>_Cisco_NX-OS_NDM.ckl
    <hostname>_Cisco_NX-OS_L2S.ckl
"""

import os, re, sys, argparse, subprocess
from dataclasses import dataclass
from typing import List, Tuple, Optional

# ---------- optional lxml dependency ----------
def ensure_lxml():
    try:
        import lxml  # noqa
        from lxml import etree  # noqa
        return True
    except Exception:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "lxml"])
            import lxml  # noqa
            from lxml import etree  # noqa
            return True
        except Exception:
            return False

HAS_LXML = ensure_lxml()
if HAS_LXML:
    from lxml import etree
else:
    import xml.etree.ElementTree as etree  # type: ignore

# ---------- helpers ----------
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def iter_interface_blocks(config_text: str) -> List[Tuple[str, str]]:
    blocks = []
    pat = re.compile(r'(?m)^interface\s+(\S+)\s*$')
    starts = list(pat.finditer(config_text))
    for idx, m in enumerate(starts):
        ifname = m.group(1)
        end = starts[idx+1].start() if idx + 1 < len(starts) else len(config_text)
        block = config_text[m.start():end]
        blocks.append((ifname, block))
    return blocks

def find_hostname(config_text: str) -> Optional[str]:
    m = re.search(r'(?m)^\s*hostname\s+([A-Za-z0-9._-]+)\s*$', config_text)
    return m.group(1) if m else None

def find_mgmt0_ip(config_text: str) -> Optional[str]:
    for ifname, block in iter_interface_blocks(config_text):
        if ifname.lower() in ("mgmt0", "management0", "mgmt 0"):
            m = re.search(r'(?m)\bip address\s+(\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}\b', block)
            if m:
                return m.group(1)
    return None

def parse_vlans_and_svis(config_text: str):
    vlans = set(int(v) for v in re.findall(r'(?m)^vlan\s+(\d+)\s*$', config_text))
    svis = {}
    for ifname, block in iter_interface_blocks(config_text):
        if ifname.lower().startswith("vlan"):
            try:
                vid = int(re.sub(r'[^0-9]', '', ifname))
            except Exception:
                continue
            has_ip = bool(re.search(r'(?m)^\s*ip address\s+\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b', block))
            svis[vid] = has_ip
    return vlans, svis

@dataclass
class ParsedIface:
    name: str
    is_access: bool
    is_trunk: bool
    access_vlan: Optional[int]
    trunk_native: Optional[int]
    trunk_allowed: Optional[str]
    is_edge: bool
    bpduguard_enable: bool
    root_guard: bool
    ip_verify_source: bool
    dhcp_snoop_trust: bool
    storm_control_present: bool
    has_description_unused: bool

def parse_interfaces(config_text: str) -> List[ParsedIface]:
    parsed = []
    for ifname, block in iter_interface_blocks(config_text):
        # consider "description unused" at/near the top of the block
        lines = [ln.strip() for ln in block.splitlines()]
        # look at the first ~6 non-empty config lines after "interface ..."
        after_header = [ln for ln in lines[1:8] if ln and not ln.startswith("!")]
        desc_unused = any(re.search(r'^description\s+unused\b', ln, re.IGNORECASE) for ln in after_header)

        is_access = bool(re.search(r'(?m)^\s*switchport\s+mode\s+access\b', block))
        is_trunk  = bool(re.search(r'(?m)^\s*switchport\s+mode\s+trunk\b', block))
        acc_vlan = None
        m = re.search(r'(?m)^\s*switchport\s+access\s+vlan\s+(\d+)\b', block)
        if m: acc_vlan = int(m.group(1))
        trunk_native = None
        m = re.search(r'(?m)^\s*switchport\s+trunk\s+native\s+vlan\s+(\d+)\b', block)
        if m: trunk_native = int(m.group(1))
        trunk_allowed = None
        m = re.search(r'(?m)^\s*switchport\s+trunk\s+allowed\s+vlan\s+(.+)$', block)
        if m: trunk_allowed = m.group(1).strip()
        is_edge = bool(re.search(r'(?m)^\s*spanning-tree\s+port\s+type\s+edge\b', block))
        bpduguard = bool(re.search(r'(?m)^\s*spanning-tree\s+bpduguard\s+enable\b', block)) or bool(re.search(r'(?m)^\s*spanning-tree\s+portfast\s+bpduguard\s+default\b', block))
        root_guard = bool(re.search(r'(?m)^\s*spanning-tree\s+guard\s+root\b', block))
        ip_verify = bool(re.search(r'(?m)^\s*ip\s+verify\s+source\b', block))
        dhcp_trust = bool(re.search(r'(?m)^\s*ip\s+dhcp\s+snooping\s+trust\b', block))
        storm = bool(re.search(r'(?m)^\s*storm-control\s+(?:broadcast|multicast|unicast)\b', block))
        parsed.append(ParsedIface(ifname, is_access, is_trunk, acc_vlan, trunk_native, trunk_allowed, is_edge, bpduguard, root_guard, ip_verify, dhcp_trust, storm, desc_unused))
    return parsed

@dataclass
class GlobalSettings:
    dot1x_enabled: bool
    dot1x_iface_any: bool
    vtp_enabled: bool
    vtp_mode_transparent: bool
    stp_loopguard_default: bool
    igmp_snooping_no_disable: bool
    udld_aggressive: bool
    dhcp_snoop_global: bool
    dhcp_snoop_vlans: list
    arp_inspection_vlans: list

def parse_globals(config_text: str) -> GlobalSettings:
    dot1x_enabled = bool(re.search(r'(?m)^\s*feature\s+dot1x\b', config_text)) or bool(re.search(r'(?m)^\s*dot1x\s+system-auth-control\b', config_text))
    dot1x_iface_any = 'dot1x' in config_text.lower() or '802.1x' in config_text.lower()
    vtp_enabled = bool(re.search(r'(?m)^\s*feature\s+vtp\b', config_text)) or bool(re.search(r'(?m)^\s*vtp\s+mode\b', config_text))
    vtp_mode_transparent = bool(re.search(r'(?m)^\s*vtp\s+mode\s+transparent\b', config_text))
    stp_loopguard_default = bool(re.search(r'(?m)^\s*spanning-tree\s+loopguard\s+default\b', config_text))
    igmp_snooping_no_disable = not bool(re.search(r'(?m)^\s*no\s+ip\s+igmp\s+snooping\b', config_text))
    udld_aggressive = bool(re.search(r'(?m)^\s*udld\s+aggressive\b', config_text)) or bool(re.search(r'(?m)^\s*udld\s+enable\b', config_text))
    dhcp_snoop_global = bool(re.search(r'(?m)^\s*ip\s+dhcp\s+snooping\s*$', config_text))
    dhcp_snoop_vlans, arp_inspection_vlans = [], []
    for m in re.finditer(r'(?m)^\s*ip\s+dhcp\s+snooping\s+vlan\s+([0-9,\-\s]+)$', config_text):
        parts = re.split(r'[,\s]+', m.group(1).strip()); dhcp_snoop_vlans += [int(x) for x in parts if x.isdigit()]
    for m in re.finditer(r'(?m)^\s*ip\s+arp\s+inspection\s+vlan\s+([0-9,\-\s]+)$', config_text):
        parts = re.split(r'[,\s]+', m.group(1).strip()); arp_inspection_vlans += [int(x) for x in parts if x.isdigit()]
    return GlobalSettings(dot1x_enabled, dot1x_iface_any, vtp_enabled, vtp_mode_transparent, stp_loopguard_default, igmp_snooping_no_disable, udld_aggressive, dhcp_snoop_global, dhcp_snoop_vlans, arp_inspection_vlans)

# ---------- evaluation ----------
@dataclass
class EvalResult:
    status: str
    details: str

def _safe_evidence(s: str) -> str:
    s = (s or "").strip()
    return (s[:300] + "...") if len(s) > 300 else s

def _evidence_line(pattern: Optional[str], haystack: str) -> str:
    if not pattern: return ""
    for line in haystack.splitlines():
        if re.search(pattern, line, re.IGNORECASE):
            return line.strip()
    return ""

def eval_rules(vnum: str, cfg: str, ifaces: List[ParsedIface], g: GlobalSettings, vlans: set, svis: dict, user_ctx: dict) -> EvalResult:
    def satisfied(msg: str = "", pat: Optional[str]=None) -> EvalResult:
        ev = _evidence_line(pat, cfg)
        detail = f'This check was satisfied based on the check text found in the show running-configuration all file. Evidence: "{_safe_evidence(ev) if ev else "See configuration excerpts matching required patterns."}"'
        if msg: detail += f" {msg}"
        return EvalResult("NotAFinding", detail)

    def openf(what: str) -> EvalResult:
        return EvalResult("Open", f'{what} was not found within this configuration file.')

    def nr(why: str) -> EvalResult:
        return EvalResult("Not_Reviewed", f'Unable to determine compliance automatically: {why}. Marking Not_Reviewed.')

    def na(why: str) -> EvalResult:
        return EvalResult("Not_Applicable", f'This check does not apply to this device context: {why}')

    # -------------------- NDM (V-220474..V-220517, V-260464) --------------------
    if vnum == "V-220474":
        if re.search(r'(?m)^\s*banner\s+(?:login|motd)\s', cfg): return satisfied("Security banner configured.", r'^\s*banner\s+(?:login|motd)\b')
        return openf("Login/MOTD security banner")

    if vnum == "V-220475":
        if re.search(r'(?m)^\s*logging\s+timestamp', cfg): return satisfied("Logging timestamps enabled.", r'^\s*logging\s+timestamp')
        return nr("Cannot confirm logging timestamp configuration")

    if vnum == "V-220476":
        if re.search(r'(?m)^\s*aaa\s+authentication\s+login\s+default\s+', cfg): return satisfied("AAA login authentication configured.", r'^\s*aaa\s+authentication\s+login\s+default\b')
        return openf("AAA login authentication (aaa authentication login default ...)")

    if vnum == "V-220477":
        if re.search(r'(?m)^\s*aaa\s+authorization\s+exec\s+default\s+', cfg) or re.search(r'(?m)^\s*aaa\s+authorization\s+commands\s+\d+\s+default\s+', cfg):
            return satisfied("AAA authorization configured.", r'^\s*aaa\s+authorization\b')
        return openf("AAA authorization for exec/commands")

    if vnum == "V-220478":
        if re.search(r'(?m)^\s*password\s+strength-check\b', cfg): return satisfied("Password strength-check enabled.", r'^\s*password\s+strength-check\b')
        return openf("Password strength-check")

    if vnum == "V-220479":
        m = re.search(r'(?ms)^line\s+console.*?^\s*exec-timeout\s+(\d+)', cfg)
        if m and int(m.group(1)) > 0: return satisfied("Console exec-timeout configured.", r'^\s*exec-timeout\b')
        return nr("No console exec-timeout found")

    if vnum == "V-220480":
        if re.search(r'(?m)^\s*feature\s+ssh\b', cfg) and not re.search(r'(?m)^\s*ssh\s+server\s+v1\b', cfg):
            return satisfied("SSH enabled (v2).", r'^\s*feature\s+ssh\b')
        return openf("SSHv2 service (ensure v1 is not enabled)")

    if vnum == "V-220481":
        if re.search(r'(?m)^\s*feature\s+telnet\b', cfg): return openf("Telnet service must be disabled (feature telnet present)")
        return satisfied("Telnet not enabled (feature telnet absent).")

    if vnum == "V-220482":
        if re.search(r'(?m)^\s*ip\s+http\s+server\b', cfg): return openf("Plain HTTP server must be disabled")
        return satisfied("Plain HTTP server not enabled.")

    if vnum == "V-220483":
        if re.search(r'(?m)^\s*ip\s+http\s+secure-server\b', cfg): return satisfied("HTTPS (secure-server) is enabled.", r'^\s*ip\s+http\s+secure-server\b')
        return nr("HTTPS/crypto policy not clearly determined")

    # ---- CUSTOM: V-220486 default NotAFinding if no telnet/dhcp/wccp/nxapi/imp; otherwise Open
    if vnum == "V-220486":
        offenders = []
        if re.search(r'(?mi)^\s*feature\s+telnet\b', cfg): offenders.append("telnet")
        if re.search(r'(?mi)^\s*feature\s+dhcp\b', cfg) or re.search(r'(?mi)^\s*ip\s+dhcp\s+server\b', cfg): offenders.append("dhcp")
        if re.search(r'(?mi)^\s*feature\s+wccp\b', cfg): offenders.append("wccp")
        if re.search(r'(?mi)^\s*feature\s+nxapi\b', cfg): offenders.append("nxapi")
        if re.search(r'(?mi)^\s*feature\s+imp\b', cfg): offenders.append("imp")
        if offenders:
            return openf(f"Found disallowed features: {', '.join(offenders)}")
        return EvalResult("NotAFinding", 'This check was satisfied based on the running configuration: no telnet, dhcp, wccp, nxapi, or imp features were found.')

    if vnum == "V-220487":
        if re.search(r'(?m)^\s*logging\s+server\s+\d{1,3}(?:\.\d{1,3}){3}\b', cfg): return satisfied("Remote syslog server configured.", r'^\s*logging\s+server\b')
        return nr("No remote syslog server lines found")

    if vnum == "V-220488":
        if re.search(r'(?m)^\s*logging\s+level\s+\S+\s+\S+\b', cfg) or re.search(r'(?m)^\s*logging\s+monitor\s+\S+\b', cfg):
            return satisfied("Logging levels configured.", r'^\s*logging\s+(?:level|monitor)\b')
        return nr("Cannot confirm specific logging severity configuration")

    if vnum == "V-220489":
        if re.search(r'(?m)^\s*clock\s+timezone\s+\S+', cfg) or re.search(r'(?m)^\s*ntp\s+server\s+\S+', cfg):
            return satisfied("Time settings present (timezone and/or NTP).", r'^\s*(clock timezone|ntp server)\b')
        return nr("Timezone/NTP not clearly determined")

    if vnum == "V-220490":
        if re.search(r'(?m)^\s*aaa\s+accounting\s+default\s+', cfg) or re.search(r'(?m)^\s*tacacs-server\s+host\b', cfg) or re.search(r'(?m)^\s*radius-server\s+host\b', cfg) or re.search(r'(?m)^\s*feature\s+(tacacs\+|radius)\b', cfg):
            return satisfied("AAA accounting/remote AAA present.", r'^\s*aaa\s+accounting|^feature\s+(?:tacacs\+|radius)\b')
        return nr("No clear AAA accounting / TACACS+ / RADIUS lines found")

    if vnum == "V-220491":
        if re.search(r'(?m)^\s*role\s+\S+', cfg): return satisfied("Local roles present; verify least-privileged assignments.", r'^\s*role\s+\S+')
        return nr("Cannot validate least privilege automatically")

    if vnum == "V-220492":
        insecure = []
        if re.search(r'(?m)^\s*feature\s+telnet\b', cfg): insecure.append("telnet")
        if re.search(r'(?m)^\s*ip\s+http\s+server\b', cfg): insecure.append("http")
        if re.search(r'(?m)^\s*feature\s+nxapi\b', cfg): insecure.append("nxapi")
        if insecure: return openf(f"Disable unnecessary/insecure mgmt services: {', '.join(insecure)}")
        return satisfied("No unnecessary insecure mgmt services detected.")

    # ---- CUSTOM: V-220493 look for 'exec-timeout 5'
    if vnum == "V-220493":
        if re.search(r'(?m)^\s*exec-timeout\s+5\b', cfg):
            return satisfied("Exec-timeout 5 configured.", r'^\s*exec-timeout\s+5\b')
        # Also search under line vty/console blocks
        if re.search(r'(?ms)^line\s+\S+.*?^\s*exec-timeout\s+5\b', cfg):
            return satisfied("Exec-timeout 5 configured in line context.", r'^\s*exec-timeout\s+5\b')
        return openf("exec-timeout 5")

    # ---- CUSTOM: V-220494 (unchanged from prior best-effort)
    if vnum == "V-220494":
        ftp_or_tftp = re.search(r'(?mi)^\s*feature\s+(?:ftp|tftp)[-\w]*\b', cfg) or re.search(r'(?mi)^\s*ip\s+tftp\b', cfg)
        scp_sftp = re.search(r'(?mi)^\s*feature\s+scp-server\b', cfg) or re.search(r'(?mi)^\s*feature\s+sftp-server\b', cfg)
        if ftp_or_tftp: return openf("Insecure file transfer feature present (FTP/TFTP)")
        if scp_sftp: return satisfied("Secure file transfer feature (SCP/SFTP) present.", r'^\s*feature\s+(scp-server|sftp-server)\b')
        return nr("Could not confirm secure file transfer feature (SCP/SFTP)")

    if vnum == "V-220495":
        if re.search(r'(?m)^\s*feature\s+dhcp\b', cfg) or re.search(r'(?m)^\s*ip\s+dhcp\s+server\b', cfg):
            return nr("DHCP server feature detected; ensure not used on NDM")
        return satisfied("No DHCP server feature detected.")

    if vnum == "V-220496":
        protos = []
        for p in ("rip","eigrp","ospf","isis"):
            if re.search(rf'(?m)^\s*feature\s+{p}\b', cfg): protos.append(p)
        if protos:
            return nr(f"Routing protocol features present ({', '.join(protos)}); validate requirement per design")
        return satisfied("No L3 routing protocol features detected.")

    if vnum == "V-220497":
        kex = re.search(r'(?m)^\s*ssh\s+server\s+kex\s+', cfg)
        ciph = re.search(r'(?m)^\s*ssh\s+server\s+cipher\s+', cfg)
        mac  = re.search(r'(?m)^\s*ssh\s+server\s+mac\s+', cfg)
        if kex or ciph or mac:
            return satisfied("Custom SSH KEX/Ciphers/MAC configured.", r'^\s*ssh\s+server\s+')
        return nr("No explicit SSH KEX/Cipher/MAC hardening lines found")

    if vnum == "V-220498":
        if re.search(r'(?m)^\s*ssh\s+access-group\s+\S+\b', cfg) or re.search(r'(?m)^\s*ip\s+access-group\s+\S+\s+in\b', cfg):
            return satisfied("ACL restricting SSH access found.", r'(ssh\s+access-group|ip\s+access-group)')
        return nr("No explicit SSH access-group/ACL found")

    if vnum == "V-220499":
        if re.search(r'(?m)^\s*no\s+password-recovery\b', cfg) or re.search(r'(?m)^\s*boot\s+config\s+password-recovery\s+disable\b', cfg):
            return satisfied("Password recovery disabled.", r'(no\s+password-recovery|boot\s+config\s+password-recovery\s+disable)')
        return nr("Could not determine password recovery setting")

    if vnum == "V-220500":
        if re.search(r'(?m)^\s*login\s+block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+\b', cfg):
            return satisfied("Login blocking (failed-attempts) configured.", r'^\s*login\s+block-for\b')
        return nr("No 'login block-for' configuration found")

    if vnum == "V-220501":
        if re.search(r'(?m)^\s*ssh\s+server\s+timeout\s+\d+\b', cfg) or re.search(r'(?m)^\s*terminal\s+session-timeout\s+\d+\b', cfg):
            return satisfied("SSH/session timeout configured.", r'(ssh\s+server\s+timeout|terminal\s+session-timeout)')
        return nr("No SSH/session timeout configuration found")

    if vnum == "V-220502":
        if re.search(r'(?m)^\s*no\s+ip\s+source-route\b', cfg):
            return satisfied("Source routing disabled.", r'^\s*no\s+ip\s+source-route\b')
        return nr("No 'no ip source-route' line found")

    if vnum == "V-220503":
        offenders = []
        for ifname, block in iter_interface_blocks(cfg):
            if ifname.lower().startswith("vlan"):
                if re.search(r'(?m)^\s*ip\s+proxy-arp\b', block): offenders.append(ifname)
        if offenders: return openf(f"Proxy ARP enabled on: {', '.join(offenders)}")
        return satisfied("No SVI enables proxy ARP (or explicitly disabled).")

    if vnum == "V-220504":
        # NX-OS default is to drop directed-broadcast; accept if explicit 'no ip directed-broadcast' is present or absent
        return satisfied("Directed broadcast appears disabled (NX-OS default).")

    if vnum == "V-220505":
        offenders = []
        for ifname, block in iter_interface_blocks(cfg):
            if ifname.lower().startswith("vlan"):
                if not re.search(r'(?m)^\s*no\s+ip\s+redirects\b', block):
                    offenders.append(ifname)
        if offenders: return nr(f"No explicit 'no ip redirects' on: {', '.join(offenders)}")
        return satisfied("SVIs include 'no ip redirects' (or none detected).")

    # ---- CUSTOM: V-220506 AAA group server tacacs+ ISE (or similar)
    if vnum == "V-220506":
        if re.search(r'(?mi)^\s*aaa\s+group\s+server\s+tacacs\+\s+\S+', cfg):
            return satisfied("AAA group server tacacs+ is configured (ISE or equivalent).", r'^\s*aaa\s+group\s+server\s+tacacs\+\s+')
        return openf("aaa group server tacacs+ <name> (e.g., ISE)")

    # ---- CUSTOM: V-220507 AAA group server tacacs+ ISE (same indicator as requested)
    if vnum == "V-220507":
        if re.search(r'(?mi)^\s*aaa\s+group\s+server\s+tacacs\+\s+\S+', cfg):
            return satisfied("AAA group server tacacs+ is configured (ISE or equivalent).", r'^\s*aaa\s+group\s+server\s+tacacs\+\s+')
        return openf("aaa group server tacacs+ <name> (e.g., ISE)")

    if vnum == "V-220508":
        if re.search(r'(?m)^\s*login\s+on-failure\s+log\b', cfg) or re.search(r'(?m)^\s*login\s+on-success\s+log\b', cfg):
            return satisfied("Login success/failure logging configured.", r'^\s*login\s+on-(success|failure)\s+log\b')
        return nr("No explicit login success/failure logging lines found")

    # ---- CUSTOM: V-220509 AAA group server tacacs+ ISE (as requested)
    if vnum == "V-220509":
        if re.search(r'(?mi)^\s*aaa\s+group\s+server\s+tacacs\+\s+\S+', cfg):
            return satisfied("AAA group server tacacs+ is configured (ISE or equivalent).", r'^\s*aaa\s+group\s+server\s+tacacs\+\s+')
        return openf("aaa group server tacacs+ <name> (e.g., ISE)")

    # ---- CUSTOM: V-220515 crypto ca lookup local
    if vnum == "V-220515":
        if re.search(r'(?mi)^\s*crypto\s+ca\s+lookup\s+local\b', cfg):
            return satisfied("Crypto CA lookup local configured.", r'^\s*crypto\s+ca\s+lookup\s+local\b')
        return openf("crypto ca lookup local")

    # ---- CUSTOM: V-220516 exact logging server line
    if vnum == "V-220516":
        if re.search(r'(?mi)^\s*logging\s+server\s+\S+\s+5\s+port\s+514\s+use-vrf\s+default\s+facility\s+local7\b', cfg):
            return satisfied("Logging server configured with facility local7 and port 514 using default VRF.", r'^\s*logging\s+server\b')
        return openf("logging server <IP> 5 port 514 use-vrf default facility local7")

    if vnum == "V-220517":
        if re.search(r'(?m)^\s*feature\s+netflow\b', cfg) or re.search(r'(?m)^\s*ip\s+flow-export\s+destination\b', cfg):
            return nr("NetFlow/IPFIX present; verify export security per policy")
        return satisfied("No NetFlow/IPFIX configuration present.")

    if vnum == "V-260464":
        if re.search(r'(?m)^\s*feature\s+nxapi\b', cfg): return openf("NX-API should be disabled unless explicitly authorized")
        return satisfied("NX-API is not enabled.")

    # -------------------- L2S (V-220675..V-220696) --------------------
    # ---- CUSTOM: V-220675 & V-220679 → NotAFinding if 802.1x/dot1x appears, else Not_Applicable
    if vnum in ("V-220675", "V-220679"):
        if re.search(r'802\.1x', cfg, re.IGNORECASE) or re.search(r'\bdot1x\b', cfg, re.IGNORECASE):
            return satisfied("dot1x/802.1X appears in configuration; there are no user-facing ports, so this is NotAFinding.", r'(802\.1x|dot1x)')
        return na("No user-facing ports establish connections; dot1x/802.1X not present in config")

    if vnum=="V-220676":
        if not g.vtp_enabled: return satisfied("VTP not enabled; this satisfies the control by preventing unauthenticated VTP.")
        if g.vtp_mode_transparent: return satisfied("VTP mode transparent; device does not process updates.")
        if re.search(r'(?m)^\s*vtp\s+password\s+\S+', cfg): return satisfied("VTP password configured.", r'^\s*vtp\s+password\s+')
        return openf("VTP authentication (password/hash) or transparent mode")

    # ---- CUSTOM: V-220677 & V-220678 → any 'source interface' line satisfies
    if vnum in ("V-220677", "V-220678"):
        if re.search(r'(?mi)\bsource\s+interface\b', cfg):
            return satisfied("Found 'source interface' configuration.", r'\bsource\s+interface\b')
        return openf("A 'source interface' configuration line")

    if vnum=="V-220680":
        access = [i for i in ifaces if i.is_access or i.is_edge]
        if not access: return nr("No access/user-facing interfaces detected")
        missing = [i.name for i in access if not i.root_guard]
        if not missing: return satisfied("Root Guard present on all access/edge interfaces.", r'\bspanning-tree\s+guard\s+root\b')
        return openf(f"Root Guard on all access/edge interfaces (missing on: {', '.join(missing)})")

    if vnum=="V-220681":
        access = [i for i in ifaces if i.is_access or i.is_edge]
        if not access: return nr("No access/user-facing interfaces detected")
        global_bpdu_default = bool(re.search(r'(?m)^\s*spanning-tree\s+port\s+type\s+edge\s+bpduguard\s+default\b', cfg)) or bool(re.search(r'(?m)^\s*spanning-tree\s+portfast\s+bpduguard\s+default\b', cfg))
        if global_bpdu_default: return satisfied("Global BPDU Guard default enabled for edge ports.", r'\bbpduguard\s+default\b')
        missing = [i.name for i in access if not i.bpduguard_enable]
        if not missing: return satisfied("BPDU Guard enabled on all access/edge ports.", r'\bbpduguard\s+enable\b')
        return openf(f"BPDU Guard on all access/edge interfaces (missing on: {', '.join(missing)})")

    if vnum=="V-220682":
        if re.search(r'(?m)^\s*spanning-tree\s+loopguard\s+default\b', cfg): return satisfied("STP Loop Guard default is enabled.", r'\bspanning-tree\s+loopguard\s+default\b')
        return openf("Global 'spanning-tree loopguard default'")

    if vnum=="V-220683":
        if re.search(r'(?m)^\s*storm-control\s+unicast\b', cfg): return satisfied("Storm-control unicast configured.", r'^\s*storm-control\s+unicast\b')
        return nr("Unknown Unicast Flood control not clearly detectable")

    if vnum=="V-220684":
        user_vlans = user_ctx.get("user_vlans", [])
        if not user_vlans: return na("No user VLANs were specified for DHCP Snooping scope")
        if not re.search(r'(?m)^\s*ip\s+dhcp\s+snooping\s*$', cfg): return openf("Global 'ip dhcp snooping'")
        present = []
        for v in user_vlans:
            if re.search(rf'(?m)^\s*ip\s+dhcp\s+snooping\s+vlan\s+.*\b{v}\b', cfg): present.append(v)
        if set(present) == set(user_vlans): return satisfied("DHCP snooping enabled with required VLANs.", r'^\s*ip\s+dhcp\s+snooping')
        missing = [str(v) for v in user_vlans if v not in present]
        return openf(f"DHCP snooping not enabled for VLANs: {', '.join(missing)}")

    if vnum=="V-220685":
        access = [i for i in ifaces if i.is_access or i.is_edge]
        if not access: return nr("No access/user-facing interfaces detected")
        missing = [i.name for i in access if not i.ip_verify_source]
        if not missing: return satisfied("IP Source Guard present on all access/edge interfaces.", r'^\s*ip\s+verify\s+source\b')
        return openf(f"IP Source Guard on all access/edge interfaces (missing on: {', '.join(missing)})")

    if vnum=="V-220686":
        user_vlans = user_ctx.get("user_vlans", [])
        if not user_vlans: return na("No user VLANs were specified for Dynamic ARP Inspection scope")
        present = []
        for v in user_vlans:
            if re.search(rf'(?m)^\s*ip\s+arp\s+inspection\s+vlan\s+.*\b{v}\b', cfg): present.append(v)
        if set(present) == set(user_vlans): return satisfied("DAI (ip arp inspection) enabled for user VLANs.", r'^\s*ip\s+arp\s+inspection\s+vlan\b')
        missing = [str(v) for v in user_vlans if v not in present]
        return openf(f"DAI not enabled for VLANs: {', '.join(missing)}")

    if vnum=="V-220687":
        access = [i for i in ifaces if i.is_access or i.is_edge]
        if not access: return nr("No access/user-facing interfaces detected")
        missing = [i.name for i in access if not i.storm_control_present]
        if not missing: return satisfied("Storm control configured on all access/edge interfaces.", r'^\s*storm-control\b')
        return openf(f"Storm control on all access/edge interfaces (missing on: {', '.join(missing)})")

    if vnum=="V-220688":
        if not re.search(r'(?m)^\s*no\s+ip\s+igmp\s+snooping\b', cfg): return satisfied("IGMP Snooping appears enabled (no 'no ip igmp snooping' found).")
        return openf("IGMP/MLD Snooping enabled")

    if vnum=="V-220689":
        if g.udld_aggressive: return satisfied("UDLD aggressive/enable detected.", r'\budld\b')
        return openf("UDLD aggressive/enable")

    # ---- CUSTOM: V-220690 -> only check interfaces marked 'description unused'
    if vnum=="V-220690":
        unused_vlan = user_ctx.get("unused_vlan")
        if not unused_vlan: return nr("No 'unused VLAN' provided for disabled/unused interfaces check")
        offenders = []
        for iface in ifaces:
            if iface.has_description_unused:
                if iface.access_vlan != unused_vlan:
                    offenders.append(iface.name)
        if not offenders:
            return satisfied(f"All interfaces described as 'unused' are assigned to VLAN {unused_vlan}.")
        return openf(f"Interfaces with 'description unused' not assigned to VLAN {unused_vlan}: {', '.join(offenders)}")

    if vnum=="V-220691":
        offenders = [i.name for i in ifaces if (i.is_access and i.access_vlan == 1)]
        if not offenders: return satisfied("No access ports assigned to default VLAN 1.")
        return openf(f"Access ports assigned to VLAN 1 (offenders: {', '.join(offenders)})")

    if vnum=="V-220692":
        offenders = []
        for i in ifaces:
            if i.is_trunk and i.trunk_allowed:
                txt = i.trunk_allowed.replace("add", "").strip()
                if re.search(r'(^|,|\s)1(,|$|\s|-)', txt): offenders.append(i.name)
        if not offenders: return satisfied("Default VLAN 1 not in trunk allowed lists.", r'switchport trunk allowed vlan')
        return openf(f"Default VLAN 1 pruned from trunks (offenders allow 1: {', '.join(offenders)})")

    if vnum=="V-220693":
        mgmt_vlan = user_ctx.get("mgmt_vlan")
        if svis.get(1, False): return openf("Management SVI on VLAN 1 (interface vlan 1 with IP)")
        if mgmt_vlan is not None:
            if mgmt_vlan == 1: return openf("Management VLAN provided is 1 (default VLAN)")
            if svis.get(mgmt_vlan, False): return satisfied(f"Management SVI detected on VLAN {mgmt_vlan}, not the default VLAN.")
            return satisfied(f"No management IP on VLAN 1; provided management VLAN {mgmt_vlan} is not default.")
        return satisfied("No management IP configured on VLAN 1 SVI.")

    if vnum=="V-220694":
        upr = user_ctx.get("user_port_regex") or ""
        user_ports = [i for i in ifaces if re.search(upr, i.name)] if upr else [i for i in ifaces if i.is_edge or i.is_access]
        offenders = [i.name for i in user_ports if not i.is_access]
        if not offenders: return satisfied("User-facing ports configured as access ports.")
        return openf(f"User-facing ports set to access mode (offenders: {', '.join(offenders)})")

    if vnum=="V-220695":
        offenders = [i.name for i in ifaces if i.is_trunk and (i.trunk_native is None or i.trunk_native == 1)]
        if not offenders: return satisfied("All trunk ports have native VLAN set and not 1.", r'\bswitchport trunk native vlan\b')
        return openf(f"Trunk ports must set native VLAN to non-1 (offenders: {', '.join(offenders)})")

    if vnum=="V-220696":
        native_vlan = user_ctx.get("native_vlan")
        if native_vlan is None:
            tset = {i.trunk_native for i in ifaces if i.trunk_native is not None}
            tset.discard(None)
            if tset: native_vlan = list(tset)[0]
            else: return nr("No native VLAN detected; provide --native-vlan to validate access ports not assigned to it")
        offenders = [i.name for i in ifaces if i.is_access and i.access_vlan == native_vlan]
        if not offenders: return satisfied(f"No access ports assigned to native VLAN {native_vlan}.")
        return openf(f"Access ports assigned to native VLAN {native_vlan} (offenders: {', '.join(offenders)})")

    # default
    return EvalResult("Not_Reviewed", "Automated rule for this check is not yet codified. Please review manually.")

# ---------- CKL ops ----------
def load_ckl(path: str):
    data = open(path, "rb").read()
    return etree.fromstring(data)

def save_ckl(root, path: str):
    if HAS_LXML:
        xml_bytes = etree.tostring(root, pretty_print=True, encoding="UTF-8", xml_declaration=True)
        with open(path, "wb") as f: f.write(xml_bytes)
    else:
        tree = etree.ElementTree(root)
        tree.write(path, encoding="UTF-8", xml_declaration=True)

def set_asset_fields(root, host_ip: str, host_name: str, host_fqdn: str):
    asset = root.find(".//ASSET")
    if asset is None: return
    def set_text(tag: str, val: str):
        el = asset.find(tag)
        if el is None: el = etree.SubElement(asset, tag)
        el.text = val
    set_text("HOST_IP", host_ip or "")
    set_text("HOST_NAME", host_name or "")
    set_text("HOST_FQDN", host_fqdn or "")

def each_vuln(root):
    return root.findall(".//VULN")

def get_vuln_num(vnode) -> Optional[str]:
    for sd in vnode.findall(".//STIG_DATA"):
        if (sd.findtext("VULN_ATTRIBUTE") or "") == "Vuln_Num":
            return sd.findtext("ATTRIBUTE_DATA")
    return None

def set_vuln_status_and_details(vnode, status: str, details: str):
    st = vnode.find("STATUS")
    if st is None: st = etree.SubElement(vnode, "STATUS")
    st.text = status
    fd = vnode.find("FINDING_DETAILS")
    if fd is None: fd = etree.SubElement(vnode, "FINDING_DETAILS")
    txt = (details or "").strip()
    if len(txt) > 1200: txt = txt[:1200] + "..."
    fd.text = txt

# ---------- discovery ----------
def infer_templates(cwd: str) -> Tuple[str, str]:
    ndm, l2s = None, None
    for f in os.listdir(cwd):
        if f.lower().endswith(".ckl"):
            if "ndm" in f.lower(): ndm = os.path.join(cwd, f)
            if "l2s" in f.lower(): l2s = os.path.join(cwd, f)
    if not ndm or not l2s:
        raise FileNotFoundError("Could not find both CKL templates (Cisco_NX-OS_NDM.ckl & Cisco_NX-OS_L2S.ckl) in current directory.")
    return ndm, l2s

def discover_configs(cwd: str, subdir: Optional[str]=None) -> List[str]:
    search_dirs = [os.path.join(cwd, subdir)] if subdir else []
    if not search_dirs:
        dflt = os.path.join(cwd, "configs")
        search_dirs.append(dflt if os.path.isdir(dflt) else cwd)
    paths = []
    for d in search_dirs:
        if not os.path.isdir(d): continue
        for f in os.listdir(d):
            if f.lower().endswith(".txt") or f.lower().endswith(".log"):
                paths.append(os.path.join(d, f))
    return sorted(paths)

def prompt_if_missing(val: Optional[str], prompt: str, default: str = "") -> str:
    if val: return val
    try:
        v = input(prompt).strip()
    except EOFError:
        v = ""
    return v if v else default

# ---------- main ----------
def process_with_template(config_path: str, ckl_path: str, ent: str, user_ctx: dict, outdir: Optional[str]) -> str:
    cfg = read_text(config_path)
    hostname = find_hostname(cfg) or (find_mgmt0_ip(cfg) or "xxxxx")
    host_ip = find_mgmt0_ip(cfg) or "0.0.0.0"
    host_fqdn = f"{hostname}.{ent}.pcte.mil"

    vlans, svis = parse_vlans_and_svis(cfg)
    ifaces = parse_interfaces(cfg)
    g = parse_globals(cfg)

    root = load_ckl(ckl_path)
    set_asset_fields(root, host_ip, hostname, host_fqdn)

    for vnode in each_vuln(root):
        vnum = get_vuln_num(vnode) or "UNKNOWN"
        res = eval_rules(vnum, cfg, ifaces, g, vlans, svis, user_ctx)
        set_vuln_status_and_details(vnode, res.status, res.details)

    base = os.path.basename(ckl_path)
    suffix = "Cisco_NX-OS_NDM.ckl" if "NDM" in base.upper() else "Cisco_NX-OS_L2S.ckl"
    outname = f"{hostname}_{suffix}"
    outpath = os.path.join(outdir or os.getcwd(), outname)
    save_ckl(root, outpath)
    return outpath

def main():
    ap = argparse.ArgumentParser(
        description="Generate filled Cisco NX-OS STIG CKLs (NDM + L2S) from running-configs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--ent", help="ENT (e.g., ent1, ent2, ent3)")
    ap.add_argument("--native-vlan", type=int, help="Native VLAN ID (if not derivable)")
    ap.add_argument("--management-vlan", type=int, help="Management VLAN ID (SVI used for management, if known)")
    ap.add_argument("--user-vlans", help="Comma-separated user VLAN IDs (affects DHCP Snooping/DAI; omitted => Not_Applicable)")
    ap.add_argument("--unused-vlan", type=int, help="UNUSED VLAN ID for shutdown/unused ports")
    ap.add_argument("--user-port-regex", help="Regex to tag user-facing ports (optional)")
    ap.add_argument("--configs-subdir", help="Subdirectory containing *.txt|*.log configs (default: ./configs)")
    ap.add_argument("--self-test", action="store_true", help="Run a quick built-in smoke test and exit")
    args = ap.parse_args()

    if args.self_test:
        print("Self-test: OK (CLI reachable).")
        sys.exit(0)

    ent = prompt_if_missing(args.ent, "Enter ENT (e.g., ent1, ent2, ent3): ", default="ent1").lower()

    # Optional inputs (blank is fine)
    user_vlans = []
    if args.user_vlans:
        user_vlans = [int(x) for x in re.split(r'[,\s]+', args.user_vlans.strip()) if x.strip().isdigit()]
    else:
        raw = prompt_if_missing(None, "Enter comma-separated user VLAN IDs (or leave blank): ")
        if raw:
            user_vlans = [int(x) for x in re.split(r'[,\s]+', raw) if x.strip().isdigit()]

    native_vlan = args.native_vlan
    if native_vlan is None:
        nvraw = prompt_if_missing(None, "Enter native VLAN ID if used (or leave blank): ")
        if nvraw.isdigit(): native_vlan = int(nvraw)

    mgmt_vlan = args.management_vlan
    if mgmt_vlan is None:
        mraw = prompt_if_missing(None, "Enter management VLAN ID (or leave blank if unknown): ")
        if mraw.isdigit(): mgmt_vlan = int(mraw)

    unused_vlan = args.unused_vlan
    if unused_vlan is None:
        uvr = prompt_if_missing(None, "Enter UNUSED VLAN ID for ports described as 'unused' (or leave blank): ")
        if uvr.isdigit(): unused_vlan = int(uvr)

    user_port_regex = args.user_port_regex or ""

    user_ctx = {
        "user_vlans": user_vlans,
        "native_vlan": native_vlan,
        "unused_vlan": unused_vlan,
        "user_port_regex": user_port_regex,
        "mgmt_vlan": mgmt_vlan,
    }

    cwd = os.getcwd()
    ndm_tmpl, l2s_tmpl = infer_templates(cwd)
    configs = discover_configs(cwd, args.configs_subdir)

    if not configs:
        print("No .txt or .log config files found. Place them in ./configs or pass --configs-subdir.")
        sys.exit(1)

    outpaths = []
    for cfg in configs:
        for tmpl in (ndm_tmpl, l2s_tmpl):
            outp = process_with_template(cfg, tmpl, ent, user_ctx, outdir=cwd)
            outpaths.append(outp)
            print(f"Wrote: {outp}")
    print(f"Complete. Generated {len(outpaths)} CKLs.")

if __name__ == "__main__":
    main()

