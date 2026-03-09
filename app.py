import os
import sys
import csv
import json
import socket
import queue
import threading
import logging
import time
import glob
import hashlib
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import ldap3
import winrm

WMI_AVAILABLE = False
PYTHONCOM_AVAILABLE = False
try:
    import wmi as wmi_module
    WMI_AVAILABLE = True
except ImportError:
    pass
try:
    import pythoncom
    PYTHONCOM_AVAILABLE = True
except ImportError:
    pass

logger = logging.getLogger("scanner")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
fh = RotatingFileHandler("scan.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
fh.setFormatter(formatter)
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
ch.setLevel(logging.INFO)
logger.addHandler(ch)

BUILTIN_ADMINS = {
    "administrator", "администратор",
    "domain admins", "администраторы домена",
    "enterprise admins", "администраторы предприятия",
    "schema admins", "администраторы схемы",
}

LOCAL_GROUP_PRESETS = {
    "S-1-5-32-544": {"key": "administrators", "name": "Administrators"},
    "S-1-5-32-555": {"key": "remote_desktop_users", "name": "Remote Desktop Users"},
    "S-1-5-32-562": {"key": "distributed_com_users", "name": "Distributed COM Users"},
    "S-1-5-32-580": {"key": "remote_management_users", "name": "Remote Management Users"},
}

app = FastAPI()

if getattr(sys, "frozen", False):
    _base_path = sys._MEIPASS
else:
    _base_path = os.path.dirname(os.path.abspath(__file__))

templates_dir = os.path.join(_base_path, "templates")
os.makedirs(templates_dir, exist_ok=True)
templates = Jinja2Templates(directory=templates_dir)


def smart_decode(raw_bytes):
    if not raw_bytes:
        return ""
    for enc in ["utf-8-sig", "utf-8", "cp1251", "cp866"]:
        try:
            text = raw_bytes.decode(enc)
            if "\ufffd" not in text:
                return text
        except (UnicodeDecodeError, ValueError):
            pass
    return raw_bytes.decode("utf-8", errors="replace")


PS_ENCODING_PREFIX = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
"""


# ═══════════════════════════════════════
#  DNS CACHE
# ═══════════════════════════════════════

class DNSCache:
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def resolve(self, host):
        with self._lock:
            if host in self._cache:
                return self._cache[host]
        try:
            ip = socket.gethostbyname(host)
        except socket.error:
            ip = None
        with self._lock:
            self._cache[host] = ip
        return ip

    def clear(self):
        with self._lock:
            self._cache.clear()


dns_cache = DNSCache()


# ═══════════════════════════════════════
#  METRICS
# ═══════════════════════════════════════

class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.scan_start = None
        self.scan_end = None
        self.total_scans = 0
        self.last_scan_duration = 0
        self.hosts_per_second = 0
        self.method_timings = defaultdict(list)

    def start(self):
        with self._lock:
            self.scan_start = time.time()
            self.scan_end = None

    def finish(self, total_hosts):
        with self._lock:
            self.scan_end = time.time()
            self.total_scans += 1
            if self.scan_start:
                self.last_scan_duration = round(self.scan_end - self.scan_start, 2)
                if self.last_scan_duration > 0:
                    self.hosts_per_second = round(total_hosts / self.last_scan_duration, 2)

    def add_method_timing(self, method, duration):
        with self._lock:
            self.method_timings[method].append(duration)

    def get_stats(self):
        with self._lock:
            avg_timings = {}
            for m, times in self.method_timings.items():
                if times:
                    avg_timings[m] = round(sum(times) / len(times), 3)
            return {
                "total_scans": self.total_scans,
                "last_duration_sec": self.last_scan_duration,
                "hosts_per_second": self.hosts_per_second,
                "avg_method_timings": avg_timings,
            }


metrics = Metrics()


# ═══════════════════════════════════════
#  SEVERITY / RISK SCORING
# ═══════════════════════════════════════

def calc_risk_score(members, allowed_admins=None):
    """
    Risk score per machine:
    - Each non-builtin admin: +10
    - Each non-allowed admin: +20
    - Local admin account enabled: +5
    - Domain admin present: -5 (expected)
    """
    if allowed_admins is None:
        allowed_admins = set()
    allowed_lower = set(a.lower() for a in allowed_admins)

    score = 0
    reasons = []

    for m in members:
        name = m.get("name", "")
        lower = name.lower()
        short = lower.split("\\")[-1] if "\\" in lower else lower
        is_builtin = m.get("is_builtin", False)

        if not is_builtin:
            score += 10
            if lower not in allowed_lower and short not in allowed_lower:
                score += 20
                reasons.append("unauthorized: " + name)
            else:
                reasons.append("custom but allowed: " + name)

    if score == 0:
        severity = "clean"
    elif score <= 20:
        severity = "low"
    elif score <= 50:
        severity = "medium"
    elif score <= 100:
        severity = "high"
    else:
        severity = "critical"

    return {"score": score, "severity": severity, "reasons": reasons}


# ═══════════════════════════════════════
#  SCANNER
# ═══════════════════════════════════════

class Scanner:

    def __init__(self):
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()
        self._results_dir = os.path.join(os.getcwd(), "results")
        self._last_summary = None
        self._last_summary_file = None
        self._reset_state()
        self._load_last_summary()

    def _reset_state(self):
        self.running = False
        self.cancelled = False
        self._progress = 0
        self.total = 0
        self._current = ""
        self._found_members = 0
        self._error_count = 0
        self._start_time = None
        self.ldap_conn = None
        self.executor = None
        self.config = {}

    def _load_last_summary(self):
        try:
            pattern = os.path.join(self._results_dir, "summary_*.json")
            files = glob.glob(pattern)
            if files:
                latest = max(files, key=os.path.getmtime)
                with open(latest, "r", encoding="utf-8") as f:
                    self._last_summary = json.load(f)
                self._last_summary_file = os.path.basename(latest)
                logger.info("Loaded previous summary: %s", latest)
        except Exception as e:
            logger.debug("No previous summary: %s", e)

    def reset(self):
        self._reset_state()
        while True:
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break

    @property
    def progress(self):
        with self._lock:
            return self._progress

    @property
    def current(self):
        with self._lock:
            return self._current

    @property
    def found_members(self):
        with self._lock:
            return self._found_members

    @property
    def error_count(self):
        with self._lock:
            return self._error_count

    @property
    def eta_seconds(self):
        with self._lock:
            p = self._progress
            t = self.total
            st = self._start_time
        if not st or p == 0 or t == 0:
            return 0
        elapsed = time.time() - st
        rate = p / elapsed
        remaining = t - p
        if rate > 0:
            return round(remaining / rate)
        return 0

    def _inc_progress(self):
        with self._lock:
            self._progress += 1

    def _set_current(self, val):
        with self._lock:
            self._current = val

    def _add_members(self, n):
        with self._lock:
            self._found_members += n

    def _inc_errors(self):
        with self._lock:
            self._error_count += 1

    @staticmethod
    def port_open(host, port, timeout=2.0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
            return True
        except (socket.error, OSError):
            return False

    def ensure_ldap(self):
        if self.ldap_conn and self.ldap_conn.bound:
            return
        cfg = self.config.get("ad_config", {})
        server = ldap3.Server(cfg["server"], get_info=ldap3.ALL)
        user = cfg["username"]
        if "@" not in user:
            user = user + "@" + cfg["domain"]
        self.ldap_conn = ldap3.Connection(
            server, user=user, password=cfg["password"],
            authentication=ldap3.SIMPLE, auto_bind=True,
        )
        logger.info("LDAP connected to %s", cfg["server"])

    def get_computers(self, ou_dn):
        if not ou_dn:
            return []
        self.ensure_ldap()
        filt = "(&(objectClass=computer)(objectCategory=computer))"
        attrs = ["cn", "dNSHostName", "operatingSystem"]
        computers = []
        self.ldap_conn.search(
            search_base=ou_dn, search_filter=filt,
            search_scope=ldap3.SUBTREE, attributes=attrs, paged_size=1000,
        )
        while True:
            for entry in self.ldap_conn.entries:
                h = str(entry.dNSHostName) if entry.dNSHostName else str(entry.cn)
                os_name = ""
                if hasattr(entry, "operatingSystem") and entry.operatingSystem:
                    os_name = str(entry.operatingSystem)
                if h:
                    computers.append({"hostname": h, "os": os_name})
            cookie = (
                self.ldap_conn.result
                .get("controls", {})
                .get("1.2.840.113556.1.4.319", {})
                .get("value", {})
                .get("cookie")
            )
            if not cookie:
                break
            self.ldap_conn.search(
                search_base=ou_dn, search_filter=filt,
                search_scope=ldap3.SUBTREE, attributes=attrs,
                paged_size=1000, paged_cookie=cookie,
            )
        logger.info("LDAP: %d computers from %s", len(computers), ou_dn)
        return computers
    # ── LDAP Group Expansion ──

    def _expand_domain_groups(self, members_list):
        """
        Для каждого участника проверяет — является ли он доменной группой.
        Если да — рекурсивно разворачивает через LDAP.
        Возвращает расширенный список с полем 'via_group'.
        """
        cfg = self.config.get("ad_config", {})
        domain = cfg.get("domain", "")
        netbios = cfg.get("netbios_domain", "")

        if not domain:
            return members_list

        expanded = []
        seen_groups = set()  # защита от циклов

        for member in members_list:
            name = member.get("name", "")
            obj_type = member.get("type", "unknown")

            # Определяем — это доменная учётка или локальная
            is_domain = False
            account_name = name
            domain_part = ""

            if "\\" in name:
                parts = name.split("\\", 1)
                domain_part = parts[0]
                account_name = parts[1]
                # Доменная если domain_part совпадает с netbios или не является именем компьютера
                if domain_part.lower() == netbios.lower():
                    is_domain = True
            elif "@" in name:
                is_domain = True
                account_name = name.split("@")[0]

            # Если тип Group и доменная — разворачиваем
            is_group = obj_type.lower() in ("group", "группа")

            # Если тип unknown но доменная — проверяем через LDAP
            if is_domain and (is_group or obj_type.lower() == "unknown"):
                try:
                    group_members = self._resolve_group_members(
                        account_name, domain_part, seen_groups
                    )
                    if group_members is not None:
                        # Это группа — добавляем саму группу + развёрнутых
                        member["type"] = "Group"
                        member["expanded_members"] = group_members
                        member["expanded_count"] = len(group_members)
                        expanded.append(member)

                        for gm in group_members:
                            gm["via_group"] = name
                            expanded.append(gm)
                        continue
                except Exception as e:
                    logger.debug("Group expand failed for %s: %s", name, e)

            # Не группа или не удалось развернуть — добавляем как есть
            expanded.append(member)

        return expanded

    def _resolve_group_members(self, group_name, domain_part, seen_groups, depth=0):
        """
        Рекурсивно разворачивает доменную группу через LDAP.
        Возвращает список участников или None если это не группа.
        Максимальная глубина рекурсии — 5.
        """
        if depth > 5:
            return []

        group_key = (group_name.lower(), domain_part.lower())
        if group_key in seen_groups:
            return []  # цикл
        seen_groups.add(group_key)

        try:
            self.ensure_ldap()
        except Exception:
            return None

        cfg = self.config.get("ad_config", {})
        domain = cfg.get("domain", "")
        base_dn = ",".join("DC=" + p for p in domain.split("."))

        # Ищем группу по sAMAccountName
        search_filter = (
            "(&(objectClass=group)(sAMAccountName=" +
            group_name.replace("(", "\\28").replace(")", "\\29") +
            "))"
        )

        try:
            self.ldap_conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=["distinguishedName", "member", "cn"],
            )
        except Exception as e:
            logger.debug("LDAP search failed for group %s: %s", group_name, e)
            return None

        if not self.ldap_conn.entries:
            return None  # не найдена — значит не группа или другой домен

        entry = self.ldap_conn.entries[0]
        members_dn = entry.member.values if hasattr(entry, "member") and entry.member else []

        if not members_dn:
            return []

        result = []
        for member_dn in members_dn:
            member_info = self._resolve_dn(member_dn, seen_groups, depth + 1)
            if member_info:
                result.extend(member_info)

        return result

    def _resolve_dn(self, dn, seen_groups, depth):
        """
        По DN определяет — пользователь или группа.
        Если группа — рекурсивно разворачивает.
        """
        try:
            self.ldap_conn.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=[
                    "objectClass", "sAMAccountName", "cn",
                    "userPrincipalName", "member", "objectCategory"
                ],
            )
        except Exception:
            # DN может быть из другого домена
            return [{"name": dn, "type": "unknown (cross-domain)"}]

        if not self.ldap_conn.entries:
            return [{"name": dn, "type": "unknown"}]

        entry = self.ldap_conn.entries[0]
        obj_classes = [str(c).lower() for c in entry.objectClass.values] if entry.objectClass else []
        sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") and entry.sAMAccountName else ""

        cfg = self.config.get("ad_config", {})
        netbios = cfg.get("netbios_domain", "")
        full_name = netbios + "\\" + sam if sam else str(entry.cn)

        if "group" in obj_classes:
            # Рекурсия — разворачиваем вложенную группу
            nested = self._resolve_group_members(sam, netbios, seen_groups, depth)
            items = [{"name": full_name, "type": "Group (nested)"}]
            if nested:
                for nm in nested:
                    nm["via_group"] = full_name
                items.extend(nested)
            return items

        elif "user" in obj_classes or "person" in obj_classes:
            return [{"name": full_name, "type": "User"}]

        elif "computer" in obj_classes:
            return [{"name": full_name, "type": "Computer"}]

        else:
            return [{"name": full_name, "type": "unknown"}]
    def _make_session(self, computer, use_ssl=False):
        cfg = self.config["ad_config"]
        if cfg.get("netbios_domain"):
            username = cfg["netbios_domain"] + "\\" + cfg["username"]
        else:
            username = cfg["username"] + "@" + cfg["domain"]
        port = 5986 if use_ssl else 5985
        scheme = "https" if use_ssl else "http"
        target = scheme + "://" + computer + ":" + str(port)

        host_timeout = int(self.config.get("host_timeout", 40))

        return winrm.Session(
            target=target, auth=(username, cfg["password"]),
            transport="ntlm", server_cert_validation="ignore",
            read_timeout_sec=host_timeout + 5,
            operation_timeout_sec=host_timeout,
        )

    def _run_ps(self, session, script, computer=""):
        full_script = PS_ENCODING_PREFIX + "\n" + script
        try:
            resp = session.run_ps(full_script)
        except Exception as e:
            raise RuntimeError("WinRM connect: " + str(e)[:200])
        if resp.status_code != 0:
            stderr = smart_decode(resp.std_err or b"").strip()
            raise RuntimeError("PS rc=%d: %s" % (resp.status_code, stderr[:300]))
        raw = (resp.std_out or b"").strip()
        if not raw:
            return []
        decoded = smart_decode(raw)
        try:
            data = json.loads(decoded)
        except (json.JSONDecodeError, ValueError):
            lines = decoded.splitlines()
            return [l.strip() for l in lines if l.strip()]
        if isinstance(data, str):
            return [data]
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return []

    def _extract_names(self, raw_list):
        names = []
        for item in raw_list:
            if isinstance(item, dict):
                name = item.get("Name") or item.get("name") or ""
                obj_type = item.get("Type") or item.get("ObjectClass") or item.get("type") or "unknown"
            else:
                name = str(item)
                obj_type = "unknown"
            name = name.strip()
            if name and "command completed" not in name.lower() and "команда выполнена" not in name.lower() and "успешно завершена" not in name.lower():
                names.append({"name": name, "type": obj_type})
        return names

    def _classify_member(self, name, obj_type, via_group=None):
        lower = name.lower()
        short = lower.split("\\")[-1] if "\\" in lower else lower
        is_builtin = short in BUILTIN_ADMINS
        result = {
            "name": name,
            "type": obj_type,
            "is_builtin": is_builtin,
        }
        if via_group:
            result["via_group"] = via_group
        return result

    def _normalize_group_targets(self):
        selected = self.config.get("group_targets")
        if not selected:
            return ["S-1-5-32-544"]

        normalized = []
        for sid in selected:
            sid_str = str(sid).strip()
            if sid_str in LOCAL_GROUP_PRESETS:
                normalized.append(sid_str)

        if not normalized:
            return ["S-1-5-32-544"]
        return normalized

    def _get_local_groups(self):
        groups = []
        for sid in self._normalize_group_targets():
            preset = LOCAL_GROUP_PRESETS.get(sid)
            if preset:
                groups.append({
                    "sid": sid,
                    "key": preset["key"],
                    "name": preset["name"],
                })
        return groups

    def _expand_with_domain_aliases(self, members, aliases):
        if not aliases:
            return members

        alias_set = set()
        for alias in aliases:
            a = str(alias).strip().lower()
            if a:
                alias_set.add(a)

        if not alias_set:
            return members

        expanded = []
        for m in members:
            expanded.append(m)
            name = (m.get("name") or "").strip()
            obj_type = m.get("type") or "unknown"
            if "\\" not in name:
                continue
            domain, short = name.split("\\", 1)
            if not short:
                continue
            domain_lower = domain.strip().lower()
            if domain_lower in alias_set:
                for alias in sorted(alias_set):
                    if alias == domain_lower:
                        continue
                    alt_name = alias.upper() + "\\" + short
                    expanded.append({"name": alt_name, "type": obj_type})
        return expanded

    def _try_winrm_methods(self, computer, use_ssl=False):
        session = self._make_session(computer, use_ssl=use_ssl)
        selected_groups = self._get_local_groups()
        all_members = []
        method_labels = []
        errors = []

        for group in selected_groups:
            sid = group["sid"]
            group_name = group["name"]
            group_members = None
            group_method = None
            last_error = None

            try:
                script = r"""
$targetSid = "__GROUP_SID__"
$group = [ADSI]("WinNT://./" + $targetSid + ",group")
$result = @()
foreach ($member in $group.psbase.Invoke("Members")) {
    $cls  = $member.GetType().InvokeMember("Class",  'GetProperty', $null, $member, $null)
    $name = $member.GetType().InvokeMember("Name",   'GetProperty', $null, $member, $null)
    $path = $member.GetType().InvokeMember("ADsPath",'GetProperty', $null, $member, $null)
    $domain = ""
    if ($path -match "WinNT://([^/]+)/") { $domain = $matches[1] }
    if ($domain -and $domain -ne $env:COMPUTERNAME) {
        # Keep a single backslash in DOMAIN\user for downstream parsing.
        $fullname = "{0}\{1}" -f $domain, $name
    } else {
        $fullname = $name
    }
    $result += @{ Name = $fullname; Type = $cls }
}
$result | ConvertTo-Json -Compress -Depth 3
""".replace("__GROUP_SID__", sid)
                raw = self._run_ps(session, script, computer)
                members = self._extract_names(raw)
                if members:
                    group_method = "WinRM-ADSI"
                    group_members = members
            except Exception as e:
                last_error = e

            if group_members is None:
                try:
                    script = r"""
$targetSid = "__GROUP_SID__"
$sid = New-Object System.Security.Principal.SecurityIdentifier($targetSid)
$group = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\\')[-1]
Get-LocalGroupMember -Group $group |
    Select-Object @{N='Name';E={$_.Name}}, @{N='Type';E={$_.ObjectClass}} |
    ConvertTo-Json -Compress
""".replace("__GROUP_SID__", sid)
                    raw = self._run_ps(session, script, computer)
                    members = self._extract_names(raw)
                    if members:
                        group_method = "WinRM-GLGM"
                        group_members = members
                except Exception as e:
                    last_error = e

            if group_members is None:
                try:
                    script = r"""
$targetSid = "__GROUP_SID__"
$sid = New-Object System.Security.Principal.SecurityIdentifier($targetSid)
$groupName = $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\\')[-1]
$raw = net localgroup $groupName 2>&1
$started = $false; $res = @()
foreach ($line in $raw) {
    $s = "$line".Trim()
    if ($s -match '^-{3,}$') { $started = $true; continue }
    if ($started -and $s -and $s -notmatch 'command completed' -and $s -notmatch 'команда выполнена' -and $s -notmatch 'успешно завершена') { $res += $s }
}
$res | ConvertTo-Json -Compress
""".replace("__GROUP_SID__", sid)
                    raw = self._run_ps(session, script, computer)
                    members = self._extract_names(raw)
                    if members:
                        group_method = "WinRM-NET-SID"
                        group_members = members
                except Exception as e:
                    last_error = e

            if group_members is None:
                errors.append(group_name + ": " + str(last_error)[:120])
                continue

            for member in group_members:
                member["source_group"] = group_name
            all_members.extend(group_members)
            method_labels.append(group_method + "[" + group_name + "]")

        if all_members:
            method = ",".join(method_labels) if method_labels else "WinRM"
            return (method, all_members)

        if errors:
            return (None, "; ".join(errors))
        return (None, "No data returned")

    def _try_wmi(self, computer):
        if not WMI_AVAILABLE:
            return (None, "WMI not installed")
        com_init = False
        try:
            if PYTHONCOM_AVAILABLE:
                pythoncom.CoInitialize()
                com_init = True
        except Exception:
            pass
        try:
            cfg = self.config["ad_config"]
            # Resolve WMI username for both domain-joined and local-account scenarios.
            if cfg.get("netbios_domain"):
                wmi_user = cfg["netbios_domain"] + "\\" + cfg["username"]
            else:
                wmi_user = cfg["username"]
            c = wmi_module.WMI(computer=computer, user=wmi_user, password=cfg["password"])
            members = []
            scanned_groups = []
            seen_members = set()
            for target_group in self._get_local_groups():
                sid = target_group["sid"]
                group_name = target_group["name"]
                for group in c.Win32_Group(SID=sid):
                    scanned_groups.append(group_name)

                    # 1) Standard user/group/system account association paths
                    for rclass, rtype in [
                        ("Win32_UserAccount", "User"),
                        ("Win32_Group", "Group"),
                        ("Win32_SystemAccount", "WellKnownGroup"),
                        ("Win32_SID", "SID"),
                    ]:
                        try:
                            assoc_items = group.associators(wmi_result_class=rclass)
                        except Exception:
                            assoc_items = []
                        for a in assoc_items:
                            name = getattr(a, "Caption", None) or getattr(a, "Name", None) or getattr(a, "SID", None) or ""
                            name = str(name).strip()
                            if not name:
                                continue
                            key = (name.lower(), rtype, group_name)
                            if key in seen_members:
                                continue
                            seen_members.add(key)
                            members.append({"name": name, "type": rtype, "source_group": group_name})

                    # 2) Raw association fallback: catches unresolved SIDs / foreign principals
                    try:
                        raw_assoc = group.associators()
                    except Exception:
                        raw_assoc = []
                    for a in raw_assoc:
                        name = getattr(a, "Caption", None) or getattr(a, "Name", None) or getattr(a, "SID", None) or ""
                        name = str(name).strip()
                        if not name:
                            continue
                        obj_type = getattr(a, "Path_", None)
                        if obj_type:
                            obj_type = str(obj_type)
                            if "Win32_Group" in obj_type:
                                typ = "Group"
                            elif "Win32_UserAccount" in obj_type:
                                typ = "User"
                            elif "Win32_SystemAccount" in obj_type:
                                typ = "WellKnownGroup"
                            elif "Win32_SID" in obj_type:
                                typ = "SID"
                            else:
                                typ = "unknown"
                        else:
                            typ = "unknown"
                        key = (name.lower(), typ, group_name)
                        if key in seen_members:
                            continue
                        seen_members.add(key)
                        members.append({"name": name, "type": typ, "source_group": group_name})
            if members:
                suffix = "[" + ",".join(sorted(set(scanned_groups))) + "]" if scanned_groups else ""
                return ("WMI" + suffix, members)
            return (None, "WMI: empty")
        except Exception as e:
            return (None, "WMI: " + str(e))
        finally:
            if com_init and PYTHONCOM_AVAILABLE:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    def scan_machine(self, comp_info):
        computer = comp_info["hostname"]
        os_name = comp_info.get("os", "")
        self._set_current(computer)
        t0 = time.time()
        result = {
            "computer": computer, "os": os_name, "method": None,
            "members": [], "error": None, "ip": None, "ports": {},
            "scan_time_sec": 0, "risk": None,
        }
        try:
            if self.cancelled:
                raise RuntimeError("Cancelled")

            ip = dns_cache.resolve(computer)
            result["ip"] = ip
            target = ip if ip else computer

            p5985 = self.port_open(target, 5985, 2.0)
            p5986 = self.port_open(target, 5986, 2.0) if not p5985 else False
            p445 = self.port_open(target, 445, 1.5)
            p3389 = self.port_open(target, 3389, 1.5)
            result["ports"] = {
                "5985_winrm": p5985, "5986_winrm_ssl": p5986,
                "445_smb": p445, "3389_rdp": p3389,
            }

            members = None
            method = None
            details = []

            if p5985:
                for attempt in range(2):
                    mt0 = time.time()
                    m, r = self._try_winrm_methods(computer, False)
                    if m:
                        method = m
                        members = r
                        metrics.add_method_timing(m, time.time() - mt0)
                        break
                    else:
                        if attempt == 0 and r and "timeout" in str(r).lower():
                            time.sleep(1)
                            continue
                        details.append("WinRM: " + str(r)[:200])
                        break

            if members is None and p5986:
                mt0 = time.time()
                m, r = self._try_winrm_methods(computer, True)
                if m:
                    method = m
                    members = r
                    metrics.add_method_timing(m + "-SSL", time.time() - mt0)
                else:
                    details.append("WinRM-SSL: " + str(r)[:200])

            if members is None:
                mt0 = time.time()
                m, r = self._try_wmi(computer)
                if m:
                    method = m
                    members = r
                    metrics.add_method_timing(m, time.time() - mt0)
                else:
                    details.append(str(r)[:200])

            if members is not None:
                result["method"] = method
                classified = []
                for entry in members:
                    if isinstance(entry, dict):
                        name = entry.get("name", "")
                        ot = entry.get("type", "unknown")
                        src_group = entry.get("source_group")
                    else:
                        name = str(entry)
                        ot = "unknown"
                        src_group = None
                    name = name.strip()
                    if name:
                        cm = self._classify_member(name, ot)
                        if src_group:
                            cm["source_group"] = src_group
                        classified.append(cm)

                classified = self._expand_with_domain_aliases(
                    classified,
                    self.config.get("domain_aliases", []),
                )

                # Разворачиваем доменные группы
                try:
                    if self.config.get("expand_groups", True):
                        classified = self._expand_domain_groups(classified)
                except Exception as e:
                    logger.debug("Group expansion error on %s: %s", computer, e)

                result["members"] = classified
                self._add_members(len(result["members"]))

                # Risk scoring
                allowed = set(self.config.get("allowed_admins", []))
                result["risk"] = calc_risk_score(result["members"], allowed)
            else:
                if not ip:
                    msg = "DNS failed"
                elif not p5985 and not p5986 and not p445 and not p3389:
                    msg = "Host OFFLINE. IP: " + str(ip)
                elif not p5985 and not p5986 and p445:
                    msg = "Host ALIVE (SMB), WinRM CLOSED"
                elif not p5985 and not p5986 and p3389:
                    msg = "Host ALIVE (RDP), WinRM CLOSED"
                else:
                    msg = "All methods failed"
                if details:
                    msg += " | " + "; ".join(details)
                raise RuntimeError(msg)
        except Exception as e:
            if str(e) != "Cancelled":
                result["error"] = str(e)
                self._inc_errors()
                logger.warning("FAIL %s: %s", computer, e)

        result["scan_time_sec"] = round(time.time() - t0, 2)
        self.result_queue.put({"type": "machine", "data": result})
        return result

    def run(self, config):
        self.reset()
        self.running = True
        self.config = config
        self._start_time = time.time()

        dns_cache.clear()
        metrics.start()

        save_path = config.get("save_path", "results")
        if os.path.isabs(save_path):
            self._results_dir = save_path
        else:
            self._results_dir = os.path.abspath(save_path)
        os.makedirs(self._results_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(self._results_dir, "scan_" + ts + ".json")
        csv_path = os.path.join(self._results_dir, "scan_" + ts + ".csv")
        summary_path = os.path.join(self._results_dir, "summary_" + ts + ".json")

        all_results = []
        cf = None

        try:
            cf = open(csv_path, "w", newline="", encoding="utf-8-sig")
            cw = csv.writer(cf, delimiter=";")
            cw.writerow([
                "Computer", "OS", "IP", "Member", "MemberType",
                "IsBuiltin", "Method", "ScanTime", "RiskScore",
                "Severity", "Ports", "Error"
            ])

            comp_list = []
            try:
                if config.get("workstations_ou"):
                    comp_list += self.get_computers(config["workstations_ou"])
                if config.get("servers_ou"):
                    comp_list += self.get_computers(config["servers_ou"])
            except Exception as e:
                logger.error("LDAP: %s", e)
                self.result_queue.put({"type": "error", "message": "LDAP: " + str(e)})
                return

            seen = set()
            unique = []
            for c in comp_list:
                h = c["hostname"].lower()
                if h not in seen:
                    seen.add(h)
                    unique.append(c)
            unique.sort(key=lambda x: x["hostname"].lower())
            self.total = len(unique)
            logger.info("Targets: %d", self.total)

            if not unique:
                self.result_queue.put({
                    "type": "completed",
                    "json": os.path.basename(json_path),
                    "csv": os.path.basename(csv_path),
                    "summary": os.path.basename(summary_path),
                })
                return

            # Adaptive threads
            max_cfg = int(config.get("max_threads", 20))
            if self.total < max_cfg:
                max_w = max(1, self.total)
            else:
                max_w = min(max_cfg, 100)

            self.executor = ThreadPoolExecutor(max_workers=max_w)
            futs = {}
            for c in unique:
                futs[self.executor.submit(self.scan_machine, c)] = c["hostname"]

            for fut in as_completed(futs):
                if self.cancelled:
                    break
                try:
                    res = fut.result()
                    all_results.append(res)

                    ports_str = json.dumps(res.get("ports", {}))
                    risk = res.get("risk") or {}
                    risk_score = risk.get("score", "")
                    severity = risk.get("severity", "")

                    if res.get("error"):
                        cw.writerow([
                            res["computer"], res.get("os", ""),
                            res.get("ip", ""), "", "", "", "",
                            res.get("scan_time_sec", 0), "", "",
                            ports_str, res["error"],
                        ])
                    else:
                        if not res["members"]:
                            cw.writerow([
                                res["computer"], res.get("os", ""),
                                res.get("ip", ""), "<EMPTY>", "", "",
                                res.get("method", ""),
                                res.get("scan_time_sec", 0),
                                risk_score, severity, ports_str, "",
                            ])
                        for m in res["members"]:
                            cw.writerow([
                                res["computer"], res.get("os", ""),
                                res.get("ip", ""), m["name"], m.get("type", ""),
                                "YES" if m.get("is_builtin") else "NO",
                                res.get("method", ""),
                                res.get("scan_time_sec", 0),
                                risk_score, severity, ports_str, "",
                            ])
                except Exception as exc:
                    logger.error("Future: %s: %s", futs[fut], exc)
                finally:
                    self._inc_progress()

            metrics.finish(self.total)

            summary = self._build_summary(all_results)
            self._last_summary = summary

            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump({
                    "scan_date": ts,
                    "total_targets": self.total,
                    "scanned": self.progress,
                    "total_members_found": self.found_members,
                    "total_errors": self.error_count,
                    "results": all_results,
                }, jf, ensure_ascii=False, indent=2)

            with open(summary_path, "w", encoding="utf-8") as sf:
                json.dump(summary, sf, ensure_ascii=False, indent=2)

            self._last_summary_file = os.path.basename(summary_path)

        except Exception as e:
            logger.exception("Fatal: %s", e)
        finally:
            if cf:
                try:
                    cf.close()
                except Exception:
                    pass
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)
            if self.ldap_conn:
                try:
                    self.ldap_conn.unbind()
                except Exception:
                    pass

            # Clear password from memory
            if self.config.get("ad_config"):
                self.config["ad_config"]["password"] = "***CLEARED***"

            self.running = False
            self.result_queue.put({
                "type": "completed",
                "json": os.path.basename(json_path),
                "csv": os.path.basename(csv_path),
                "summary": os.path.basename(summary_path),
            })

    def _build_summary(self, all_results):
        member_to_computers = defaultdict(list)
        member_via_groups = defaultdict(set)      # НОВОЕ: какие группы привели этого участника
        via_group_counts = defaultdict(int)        # НОВОЕ: сколько раз каждая группа встречается
        method_counts = defaultdict(int)
        error_types = defaultdict(int)
        os_counts = defaultdict(int)
        port_stats = {
            "winrm_open": 0, "winrm_ssl_open": 0,
            "smb_open": 0, "rdp_open": 0, "all_closed": 0
        }
        severity_counts = defaultdict(int)
        clean_machines = []
        risky_machines = []
        risky_details = {}
        machine_risks = {}
        scan_times = []
        success_count = 0
        error_count = 0

        for res in all_results:
            os_name = res.get("os", "") or "Unknown"
            os_counts[os_name] += 1

            ports = res.get("ports", {})
            if ports.get("5985_winrm"):
                port_stats["winrm_open"] += 1
            if ports.get("5986_winrm_ssl"):
                port_stats["winrm_ssl_open"] += 1
            if ports.get("445_smb"):
                port_stats["smb_open"] += 1
            if ports.get("3389_rdp"):
                port_stats["rdp_open"] += 1
            if not any(ports.values()):
                port_stats["all_closed"] += 1

            if res.get("scan_time_sec"):
                scan_times.append(res["scan_time_sec"])

            if res.get("error"):
                error_count += 1
                err = res["error"]
                if "DNS failed" in err:
                    error_types["DNS failed"] += 1
                elif "OFFLINE" in err:
                    error_types["Host offline"] += 1
                elif "WinRM CLOSED" in err:
                    error_types["WinRM closed"] += 1
                elif "Access" in err or "401" in err:
                    error_types["Access denied"] += 1
                else:
                    error_types["Other"] += 1
                continue

            success_count += 1
            method = res.get("method", "unknown")
            method_counts[method] += 1

            risk = res.get("risk") or {}
            sev = risk.get("severity", "clean")
            severity_counts[sev] += 1
            machine_risks[res["computer"]] = risk

            has_nonbuiltin = False
            nonbuiltin_names = []

            # ═══════════════════════════════════════
            #  ОБРАБОТКА MEMBERS с учётом via_group
            # ═══════════════════════════════════════
            for m in res.get("members", []):
                name = m.get("name", "")
                if not name:
                    continue

                # Добавляем в маппинг member -> computers
                member_to_computers[name].append(res["computer"])

                # Если участник пришёл через группу — запоминаем
                via = m.get("via_group", "")
                if via:
                    member_via_groups[name].add(via)
                    via_group_counts[via] += 1

                if not m.get("is_builtin", False):
                    has_nonbuiltin = True
                    nonbuiltin_names.append(name)

            if has_nonbuiltin:
                risky_machines.append(res["computer"])
                risky_details[res["computer"]] = nonbuiltin_names
            else:
                clean_machines.append(res["computer"])

        # ═══════════════════════════════════════
        #  ФОРМИРУЕМ top_admins — ВСЕ аккаунты
        # ═══════════════════════════════════════
        all_admins_sorted = sorted(
            member_to_computers.items(),
            key=lambda x: len(x[1]),
            reverse=True,
        )

        avg_time = round(sum(scan_times) / len(scan_times), 2) if scan_times else 0
        max_time = round(max(scan_times), 2) if scan_times else 0
        min_time = round(min(scan_times), 2) if scan_times else 0

        top_admins_list = []
        for name, machines in all_admins_sorted:
            lower = name.lower()
            short = lower.split("\\")[-1] if "\\" in lower else lower
            is_builtin = short in BUILTIN_ADMINS
            is_local_admin = short in (
                "administrator",
                "\u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440",
            )

            # Собираем через какие группы этот аккаунт попал
            via_groups = sorted(member_via_groups.get(name, set()))

            top_admins_list.append({
                "account": name,
                "machine_count": len(set(machines)),
                "is_builtin": is_builtin,
                "is_local_admin": is_local_admin,
                "via_group": ", ".join(via_groups) if via_groups else "",
                "type": "User",  # по умолчанию
                "machines": sorted(set(machines)),
            })

        # ═══════════════════════════════════════
        #  Статистика по группам (топ-20 групп)
        # ═══════════════════════════════════════
        top_groups = sorted(
            via_group_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:20]

        return {
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "total_scanned": len(all_results),
            "success": success_count,
            "errors": error_count,
            "error_breakdown": dict(error_types),
            "method_breakdown": dict(method_counts),
            "os_breakdown": dict(os_counts),
            "port_statistics": port_stats,
            "severity_breakdown": dict(severity_counts),
            "unique_admin_accounts": len(member_to_computers),
            "avg_scan_time_sec": avg_time,
            "max_scan_time_sec": max_time,
            "min_scan_time_sec": min_time,
            "top_admins": top_admins_list,
            "top_groups": [
                {"group": name, "member_entries": count}
                for name, count in top_groups
            ],
            "clean_machines_count": len(clean_machines),
            "clean_machines": sorted(clean_machines),
            "risky_machines_count": len(risky_machines),
            "risky_machines": sorted(risky_machines),
            "risky_details": risky_details,
            "machine_risks": machine_risks,
            "metrics": metrics.get_stats(),
        }
    def stop(self):
        self.cancelled = True
        logger.info("Cancel requested")


scanner = Scanner()

def _rebuild_admins_from_scan(summary_filename, summary_data):
    """
    Находит scan_*.json и пересчитывает всё из сырых данных.
    """
    ts = summary_filename.replace("summary_", "").replace(".json", "")
    scan_filename = "scan_" + ts + ".json"
    scan_path = os.path.join(scanner._results_dir, scan_filename)

    if not os.path.isfile(scan_path):
        scan_files = sorted(
            glob.glob(os.path.join(scanner._results_dir, "scan_*.json")),
            reverse=True,
        )
        if not scan_files:
            return None
        scan_path = scan_files[0]

    try:
        with open(scan_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    except Exception:
        return None

    results = scan_data.get("results", [])
    if not results:
        return None

    # ═══════════════════════════════════════
    #  Пересчитываем ВСЁ из сырых результатов
    # ═══════════════════════════════════════

    member_to_computers = defaultdict(list)
    member_via_groups = defaultdict(set)
    via_group_counts = defaultdict(int)
    method_counts = defaultdict(int)
    error_types = defaultdict(int)
    os_counts = defaultdict(int)
    port_stats = {
        "winrm_open": 0, "winrm_ssl_open": 0,
        "smb_open": 0, "rdp_open": 0, "all_closed": 0
    }
    severity_counts = defaultdict(int)
    clean_machines = []
    risky_machines = []
    risky_details = {}
    machine_risks = {}
    scan_times = []
    success_count = 0
    error_count = 0

    for res in results:
        os_name = res.get("os", "") or "Unknown"
        os_counts[os_name] += 1

        ports = res.get("ports", {})
        if ports.get("5985_winrm"):
            port_stats["winrm_open"] += 1
        if ports.get("5986_winrm_ssl"):
            port_stats["winrm_ssl_open"] += 1
        if ports.get("445_smb"):
            port_stats["smb_open"] += 1
        if ports.get("3389_rdp"):
            port_stats["rdp_open"] += 1
        if not any(ports.values()):
            port_stats["all_closed"] += 1

        if res.get("scan_time_sec"):
            scan_times.append(res["scan_time_sec"])

        if res.get("error"):
            error_count += 1
            err = res["error"]
            if "DNS failed" in err:
                error_types["DNS failed"] += 1
            elif "OFFLINE" in err:
                error_types["Host offline"] += 1
            elif "WinRM CLOSED" in err:
                error_types["WinRM closed"] += 1
            elif "Access" in err or "401" in err:
                error_types["Access denied"] += 1
            else:
                error_types["Other"] += 1
            continue

        success_count += 1
        method = res.get("method", "unknown")
        method_counts[method] += 1

        risk = res.get("risk") or {}
        sev = risk.get("severity", "clean")
        severity_counts[sev] += 1
        machine_risks[res["computer"]] = risk

        has_nonbuiltin = False
        nonbuiltin_names = []

        # ═══════════════════════════════════════
        #  ОБРАБОТКА MEMBERS с учётом via_group
        # ═══════════════════════════════════════
        for m in res.get("members", []):
            name = m.get("name", "")
            if not name:
                continue

            member_to_computers[name].append(res["computer"])

            via = m.get("via_group", "")
            if via:
                member_via_groups[name].add(via)
                via_group_counts[via] += 1

            if not m.get("is_builtin", False):
                has_nonbuiltin = True
                nonbuiltin_names.append(name)

        if has_nonbuiltin:
            risky_machines.append(res["computer"])
            risky_details[res["computer"]] = nonbuiltin_names
        else:
            clean_machines.append(res["computer"])

    # ═══════════════════════════════════════
    #  ФОРМИРУЕМ top_admins — ВСЕ без лимита
    # ═══════════════════════════════════════
    all_admins_sorted = sorted(
        member_to_computers.items(),
        key=lambda x: len(x[1]),
        reverse=True,
    )

    avg_time = round(sum(scan_times) / len(scan_times), 2) if scan_times else 0
    max_time = round(max(scan_times), 2) if scan_times else 0
    min_time = round(min(scan_times), 2) if scan_times else 0

    top_admins_list = []
    for name, machines in all_admins_sorted:
        lower = name.lower()
        short = lower.split("\\")[-1] if "\\" in lower else lower
        is_builtin = short in BUILTIN_ADMINS
        is_local_admin = short in (
            "administrator",
            "\u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440",
        )

        via_groups = sorted(member_via_groups.get(name, set()))

        top_admins_list.append({
            "account": name,
            "machine_count": len(set(machines)),
            "is_builtin": is_builtin,
            "is_local_admin": is_local_admin,
            "via_group": ", ".join(via_groups) if via_groups else "",
            "type": "User",
            "machines": sorted(set(machines)),
        })

    top_groups = sorted(
        via_group_counts.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:20]

    rebuilt = {
        "scan_timestamp": summary_data.get("scan_timestamp", ""),
        "scan_id": summary_data.get("scan_id", ts),
        "total_scanned": len(results),
        "success": success_count,
        "errors": error_count,
        "error_breakdown": dict(error_types),
        "method_breakdown": dict(method_counts),
        "os_breakdown": dict(os_counts),
        "port_statistics": port_stats,
        "severity_breakdown": dict(severity_counts),
        "unique_admin_accounts": len(member_to_computers),
        "avg_scan_time_sec": avg_time,
        "max_scan_time_sec": max_time,
        "min_scan_time_sec": min_time,
        "top_admins": top_admins_list,
        "top_groups": [
            {"group": name, "member_entries": count}
            for name, count in top_groups
        ],
        "clean_machines_count": len(clean_machines),
        "clean_machines": sorted(clean_machines),
        "risky_machines_count": len(risky_machines),
        "risky_machines": sorted(risky_machines),
        "risky_details": risky_details,
        "machine_risks": machine_risks,
        "metrics": summary_data.get("metrics", {}),
    }

    return rebuilt
# ═══════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception:
        return HTMLResponse("<h1>Scanner running</h1>")


@app.get("/summary", response_class=HTMLResponse)
async def summary_page(request: Request):
    try:
        return templates.TemplateResponse("summary.html", {"request": request})
    except Exception:
        return HTMLResponse("<h1>Summary not found</h1>")


@app.get("/api/summary")
async def api_summary():
    if scanner._last_summary:
        return scanner._last_summary
    return JSONResponse({"error": "No summary available"}, status_code=404)


@app.get("/api/summary/load/{filename}")
async def api_load_summary(filename: str):
    """Load a specific summary JSON file."""
    safe = os.path.basename(filename)
    path = os.path.join(scanner._results_dir, safe)
    if not os.path.isfile(path):
        raise HTTPException(404, "File not found")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        scanner._last_summary = data
        scanner._last_summary_file = safe
        return data
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/scans")
async def api_list_scans():
    """List all available scan files."""
    results_dir = scanner._results_dir
    scans = []
    try:
        for fname in sorted(os.listdir(results_dir), reverse=True):
            fpath = os.path.join(results_dir, fname)
            if not os.path.isfile(fpath):
                continue
            size = os.path.getsize(fpath)
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S")
            ftype = "unknown"
            if fname.startswith("scan_") and fname.endswith(".json"):
                ftype = "scan_json"
            elif fname.startswith("scan_") and fname.endswith(".csv"):
                ftype = "scan_csv"
            elif fname.startswith("summary_") and fname.endswith(".json"):
                ftype = "summary"
            scans.append({
                "filename": fname,
                "type": ftype,
                "size": size,
                "modified": mtime,
            })
    except Exception as e:
        logger.error("List scans error: %s", e)
    return scans


@app.get("/api/diff")
async def api_diff(
    scan1: str = Query(..., description="First summary filename"),
    scan2: str = Query(..., description="Second summary filename"),
):
    """Compare two summary files and return diff."""
    def load_summary(fname):
        path = os.path.join(scanner._results_dir, os.path.basename(fname))
        if not os.path.isfile(path):
            raise HTTPException(404, "File not found: " + fname)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    s1 = load_summary(scan1)
    s2 = load_summary(scan2)

    # Build member sets
    def get_member_set(summary):
        result = {}
        for admin in summary.get("top_admins", []):
            account = admin["account"]
            for machine in admin.get("machines", []):
                key = machine + "|" + account
                result[key] = True
        return set(result.keys())

    set1 = get_member_set(s1)
    set2 = get_member_set(s2)

    added = sorted(set2 - set1)
    removed = sorted(set1 - set2)
    unchanged = sorted(set1 & set2)

    # Parse added/removed into structured data
    def parse_entries(entries):
        result = []
        for e in entries:
            parts = e.split("|", 1)
            if len(parts) == 2:
                result.append({"machine": parts[0], "account": parts[1]})
        return result

    return {
        "scan1": scan1,
        "scan2": scan2,
        "scan1_date": s1.get("scan_timestamp", ""),
        "scan2_date": s2.get("scan_timestamp", ""),
        "added": parse_entries(added),
        "removed": parse_entries(removed),
        "added_count": len(added),
        "removed_count": len(removed),
        "unchanged_count": len(unchanged),
        "scan1_total": s1.get("total_scanned", 0),
        "scan2_total": s2.get("total_scanned", 0),
        "scan1_risky": s1.get("risky_machines_count", 0),
        "scan2_risky": s2.get("risky_machines_count", 0),
    }


@app.get("/api/metrics")
async def api_metrics():
    return metrics.get_stats()


@app.get("/api/results/filter")
async def api_filter_results(
    severity: str = Query(None),
    method: str = Query(None),
    has_error: bool = Query(None),
    search: str = Query(None),
):
    """Filter last scan results."""
    if not scanner._last_summary:
        return []

    # Load last scan JSON
    results_dir = scanner._results_dir
    scan_files = sorted(glob.glob(os.path.join(results_dir, "scan_*.json")), reverse=True)
    if not scan_files:
        return []

    try:
        with open(scan_files[0], "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    results = data.get("results", [])
    filtered = []

    for r in results:
        if has_error is True and not r.get("error"):
            continue
        if has_error is False and r.get("error"):
            continue
        if severity:
            risk = r.get("risk") or {}
            if risk.get("severity") != severity:
                continue
        if method and r.get("method") != method:
            continue
        if search:
            sl = search.lower()
            found = False
            if sl in r.get("computer", "").lower():
                found = True
            for m in r.get("members", []):
                if sl in m.get("name", "").lower():
                    found = True
                    break
            if not found:
                continue
        filtered.append(r)

    return filtered


@app.post("/scan/start")
async def start_scan(request: Request):
    if scanner.running:
        return JSONResponse({"error": "Already running"}, status_code=409)
    body = await request.json()
    cfg = body.get("scan")
    if not cfg:
        return JSONResponse({"error": "Missing config"}, status_code=400)
    t = threading.Thread(target=scanner.run, args=(cfg,), daemon=True)
    t.start()
    return {"status": "started"}


@app.post("/scan/stop")
async def stop_scan():
    if scanner.running:
        scanner.stop()
        return {"status": "stopping"}
    return {"status": "not running"}


@app.get("/scan/status")
async def get_status():
    return {
        "running": scanner.running,
        "progress": scanner.progress,
        "total": scanner.total,
        "current": scanner.current,
        "found": scanner.found_members,
        "errors": scanner.error_count,
        "eta_seconds": scanner.eta_seconds,
    }


@app.get("/scan/results")
async def get_results():
    items = []
    for _ in range(200):
        try:
            items.append(scanner.result_queue.get_nowait())
        except queue.Empty:
            break
    return items


@app.get("/download/{filename}")
async def download_file(filename: str):
    safe = os.path.basename(filename)
    path = os.path.join(scanner._results_dir, safe)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path, filename=safe)


if __name__ == "__main__":
    import uvicorn
    os.makedirs("results", exist_ok=True)
    print("Server: http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
