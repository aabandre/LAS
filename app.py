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
import ipaddress
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
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

WIN32NET_AVAILABLE = False
WIN32NETCON_AVAILABLE = False
try:
    import win32net
    WIN32NET_AVAILABLE = True
except ImportError:
    pass
try:
    import win32netcon
    WIN32NETCON_AVAILABLE = True
except ImportError:
    pass

logger = logging.getLogger("scanner")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")


def _ensure_logger_handler(handler):
    for existing in logger.handlers:
        if type(existing) is type(handler):
            if isinstance(handler, RotatingFileHandler):
                if getattr(existing, "baseFilename", None) == getattr(handler, "baseFilename", None):
                    return existing
            else:
                if getattr(existing, "stream", None) is getattr(handler, "stream", None):
                    return existing
    logger.addHandler(handler)
    return handler


fh = RotatingFileHandler("scan.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
fh.setFormatter(formatter)
fh.setLevel(logging.DEBUG)
fh = _ensure_logger_handler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
ch.setLevel(logging.INFO)
ch = _ensure_logger_handler(ch)


def apply_runtime_log_settings(debug_enabled=False):
    debug_on = bool(debug_enabled)
    ch.setLevel(logging.DEBUG if debug_on else logging.INFO)
    logger.info("Runtime debug logging is %s", "ENABLED" if debug_on else "disabled")


BUILTIN_ADMINS = {
    "administrator", "администратор",
    "administrators", "администраторы",
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

LOCAL_GROUP_NAME_ALIASES = {
    "S-1-5-32-544": ["Administrators", "Администраторы"],
    "S-1-5-32-555": ["Remote Desktop Users", "Пользователи удаленного рабочего стола", "Пользователи удалённого рабочего стола"],
    "S-1-5-32-562": ["Distributed COM Users", "Пользователи распределенного COM", "Пользователи распределённого COM"],
    "S-1-5-32-580": ["Remote Management Users", "Пользователи удаленного управления", "Пользователи удалённого управления"],
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


def _build_machine_memberships(members):
    grouped = defaultdict(list)
    for m in members or []:
        name = (m.get("name") or "").strip()
        if not name:
            continue
        source_group = (m.get("source_group") or "").strip() or "(unknown local group)"
        grouped[source_group].append({
            "account": name,
            "type": m.get("type", "unknown"),
            "is_builtin": bool(m.get("is_builtin", False)),
            "via_group": m.get("via_group", ""),
        })

    result = {}
    for group_name, items in grouped.items():
        uniq = {}
        for item in items:
            key = (item["account"].lower(), item.get("via_group", "").lower(), item.get("type", ""))
            if key not in uniq:
                uniq[key] = item
        sorted_items = sorted(uniq.values(), key=lambda x: (x["account"].lower(), x.get("via_group", "").lower()))
        result[group_name] = sorted_items
    return result


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
        self.ldap_gc_conn = None
        self.executor = None
        self.probe_executor = None
        self.net_semaphore = None
        self.rpc_semaphore = None
        self._group_expand_cache = {}
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

    def _cfg_int(self, key, default, minimum=None, maximum=None):
        raw = self.config.get(key, default)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default
        if minimum is not None:
            value = max(minimum, value)
        if maximum is not None:
            value = min(maximum, value)
        return value

    @staticmethod
    def port_open(host, port, timeout=2.0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
            return True
        except (socket.error, OSError):
            return False

    def _probe_ports(self, host):
        p5985 = False
        p445 = False
        p3389 = False

        with ThreadPoolExecutor(max_workers=3) as probe_pool:
            fut5985 = probe_pool.submit(self.port_open, host, 5985, 2.0)
            fut445 = probe_pool.submit(self.port_open, host, 445, 1.2)
            fut3389 = probe_pool.submit(self.port_open, host, 3389, 1.2)
            p5985 = fut5985.result()
            p445 = fut445.result()
            p3389 = fut3389.result()

        p5986 = self.port_open(host, 5986, 2.0) if not p5985 else False
        return {
            "5985_winrm": p5985,
            "5986_winrm_ssl": p5986,
            "445_smb": p445,
            "3389_rdp": p3389,
        }

    def _probe_ports_fast(self, host):
        try:
            winrm_timeout = float(self.config.get("port_probe_timeout_winrm", 1.0) or 1.0)
        except (TypeError, ValueError):
            winrm_timeout = 1.5
        try:
            fast_timeout = float(self.config.get("port_probe_timeout_fast", 0.6) or 0.6)
        except (TypeError, ValueError):
            fast_timeout = 1.0
        winrm_timeout = max(0.5, min(10.0, winrm_timeout))
        fast_timeout = max(0.2, min(5.0, fast_timeout))

        probe_exec = getattr(self, "probe_executor", None)
        if probe_exec:
            f5985 = probe_exec.submit(self.port_open, host, 5985, winrm_timeout)
            f445 = probe_exec.submit(self.port_open, host, 445, fast_timeout)
            f3389 = probe_exec.submit(self.port_open, host, 3389, fast_timeout)
            p5985 = f5985.result()
            p445 = f445.result()
            p3389 = f3389.result()
        else:
            p5985 = self.port_open(host, 5985, winrm_timeout)
            p445 = self.port_open(host, 445, fast_timeout)
            p3389 = self.port_open(host, 3389, fast_timeout)
        p5986 = self.port_open(host, 5986, winrm_timeout) if not p5985 else False
        return {
            "5985_winrm": p5985,
            "5986_winrm_ssl": p5986,
            "445_smb": p445,
            "3389_rdp": p3389,
        }

    @staticmethod
    def _host_candidates(hostname, ip=None):
        def _is_ip(value):
            try:
                ipaddress.ip_address(str(value or '').strip())
                return True
            except ValueError:
                return False

        candidates = []
        seen = set()

        host = str(hostname or '').strip()
        host_short = host.split('.', 1)[0] if host and not _is_ip(host) else ''

        for candidate in (host, host_short, ip):
            val = str(candidate or '').strip()
            key = val.lower()
            if val and key not in seen:
                seen.add(key)
                candidates.append(val)
        return candidates

    def _is_fatal_enum_error(self, text):
        msg = str(text or "").lower()
        fatal_markers = (
            "netuseadd", "error 66", " 66", "2457", "clock skew",
            "часы данного сервера не синхронизованы",
            "неверно указан тип сетевого ресурса",
            "access denied", "доступ запрещен",
            "invalid credentials", "logon failure",
        )
        return any(m in msg for m in fatal_markers)

    def _run_rpc_with_limit(self, target_host, comp_info):
        sem = getattr(self, "rpc_semaphore", None)
        if sem is None:
            return self._try_rpc_samr(target_host, comp_info=comp_info)
        acquired = False
        try:
            while not sem.acquire(timeout=0.5):
                if self.cancelled:
                    return (None, "RPC-SAMR: cancelled")
            acquired = True
            return self._try_rpc_samr(target_host, comp_info=comp_info)
        finally:
            if acquired:
                sem.release()

    def _collect_members_for_target(self, target_host, comp_info, ports):
        os_name = str((comp_info or {}).get("os") or "").lower()
        is_legacy = ("windows 7" in os_name) or ("windows xp" in os_name) or ("windows 2003" in os_name)
        allow_winrm = (not is_legacy) or bool(self.config.get("legacy_allow_winrm", False))
        prefer_rpc_first = is_legacy and bool(self.config.get("legacy_prefer_rpc", True))
        rpc_enabled = bool(self.config.get("use_rpc_fallback", False)) and bool(ports.get("445_smb"))
        rpc_adaptive = bool(self.config.get("use_rpc_adaptive", True))

        def rpc_allowed():
            if not rpc_enabled:
                return False
            if not rpc_adaptive:
                return True
            return not ports.get("5985_winrm") and not ports.get("5986_winrm_ssl")

        plan = []
        if prefer_rpc_first and rpc_allowed():
            plan.append(("RPC-SAMR-legacy-priority", lambda: self._run_rpc_with_limit(target_host, comp_info)))
        if allow_winrm and ports.get("5985_winrm"):
            plan.append(("WinRM", lambda: self._try_winrm_methods(target_host, comp_info=comp_info, use_ssl=False)))
        if allow_winrm and ports.get("5986_winrm_ssl"):
            plan.append(("WinRM-SSL", lambda: self._try_winrm_methods(target_host, comp_info=comp_info, use_ssl=True)))
        if bool(self.config.get("use_wmi_fallback", False)):
            plan.append(("WMI", lambda: self._try_wmi(target_host, comp_info=comp_info)))
        if rpc_allowed() and not prefer_rpc_first:
            plan.append(("RPC-SAMR", lambda: self._run_rpc_with_limit(target_host, comp_info)))
        elif rpc_enabled and rpc_adaptive and (ports.get("5985_winrm") or ports.get("5986_winrm_ssl")):
            return None, None, ["RPC-SAMR skipped (adaptive mode: WinRM open)"]

        details = []
        for step_name, step_fn in plan:
            t0 = time.time()
            method, payload = step_fn()
            if method:
                metric_name = method + ("-legacy-priority" if step_name == "RPC-SAMR-legacy-priority" else "")
                metrics.add_method_timing(metric_name, time.time() - t0)
                if step_name == "RPC-SAMR-legacy-priority":
                    method = method + "-legacy-priority"
                return method, payload, details

            reason = str(payload or "empty")[:220]
            details.append(step_name + ": " + reason)
            if self._is_fatal_enum_error(reason):
                break

        return None, None, details

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

    def ensure_ldap_gc(self):
        if self.ldap_gc_conn and self.ldap_gc_conn.bound:
            return
        cfg = self.config.get("ad_config", {})
        server = ldap3.Server(cfg["server"], port=3268, get_info=ldap3.NONE)
        user = cfg["username"]
        if "@" not in user:
            user = user + "@" + cfg["domain"]
        self.ldap_gc_conn = ldap3.Connection(
            server, user=user, password=cfg["password"],
            authentication=ldap3.SIMPLE, auto_bind=True,
        )
        logger.info("LDAP GC connected to %s:3268", cfg["server"])

    def _credentials_for_target(self, comp_info=None):
        base = dict(self.config.get("ad_config", {}) or {})
        target_type = ""
        if isinstance(comp_info, dict):
            target_type = str(comp_info.get("target_type") or "").strip().lower()

        if target_type != "server":
            return base

        override = dict(self.config.get("server_ad_config", {}) or {})
        if not override:
            return base

        merged = dict(base)
        for key in ("username", "password", "domain", "netbios_domain", "server"):
            val = override.get(key)
            if val:
                merged[key] = val
        return merged

    @staticmethod
    def _escape_ldap_value(value):
        s = str(value or "")
        return (
            s.replace("\\", "\\5c")
             .replace("*", "\\2a")
             .replace("(", "\\28")
             .replace(")", "\\29")
             .replace("\x00", "\\00")
        )

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

    @staticmethod
    def _domain_from_dn(dn):
        dn_value = str(dn or "")
        parts = [part for part in dn_value.split(",") if part.upper().startswith("DC=")]
        return ".".join(part[3:] for part in parts) if parts else ""

    def _entry_account_name(self, entry, fallback=""):
        sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") and entry.sAMAccountName else ""
        cn = str(entry.cn) if hasattr(entry, "cn") and entry.cn else ""
        upn = str(entry.userPrincipalName) if hasattr(entry, "userPrincipalName") and entry.userPrincipalName else ""
        dn_value = str(entry.distinguishedName) if hasattr(entry, "distinguishedName") and entry.distinguishedName else ""
        domain = self._domain_from_dn(dn_value)

        if sam and domain:
            return domain + "\\" + sam
        if sam:
            return sam
        if upn:
            return upn
        if cn:
            return cn
        return str(fallback or dn_value or "")

    def _search_entry_first(self, search_filter, attributes=None, preferred_base=""):
        if attributes is None:
            attributes = ["distinguishedName"]

        if preferred_base:
            try:
                self.ensure_ldap()
                self.ldap_conn.search(
                    search_base=preferred_base,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=attributes,
                    size_limit=1,
                )
                if self.ldap_conn.entries:
                    return self.ldap_conn.entries[0]
            except Exception as e:
                logger.debug("LDAP search failed on preferred base %s: %s", preferred_base, e)

        try:
            self.ensure_ldap_gc()
            self.ldap_gc_conn.search(
                search_base="",
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                size_limit=1,
            )
            if self.ldap_gc_conn.entries:
                return self.ldap_gc_conn.entries[0]
        except Exception as e:
            logger.debug("GC search failed for filter %s: %s", search_filter, e)

        if not preferred_base:
            return None

        try:
            self.ensure_ldap()
            self.ldap_conn.search(
                search_base=preferred_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                size_limit=1,
            )
            if self.ldap_conn.entries:
                return self.ldap_conn.entries[0]
        except Exception as e:
            logger.debug("LDAP retry failed for filter %s: %s", search_filter, e)
        return None

    def _resolve_group_entry(self, account_name, domain_hint=""):
        cfg = self.config.get("ad_config", {})
        root_domain = cfg.get("domain", "")
        preferred_base = ",".join("DC=" + p for p in root_domain.split(".")) if root_domain else ""

        account = str(account_name or "").strip()
        if not account:
            return None

        escaped = self._escape_ldap_value(account)
        filt = (
            "(&(objectClass=group)(|"
            "(sAMAccountName=" + escaped + ")"
            "(cn=" + escaped + ")"
            "(name=" + escaped + ")"
            "))"
        )

        # Если есть доменный hint и это FQDN, сначала попробуем точный base DN для него.
        hint = str(domain_hint or "").strip().lower()
        if hint and "." in hint:
            hint_base = ",".join("DC=" + p for p in hint.split("."))
            entry = self._search_entry_first(filt, attributes=["distinguishedName", "member", "cn", "sAMAccountName", "userPrincipalName"], preferred_base=hint_base)
            if entry is not None:
                return entry

        return self._search_entry_first(
            filt,
            attributes=["distinguishedName", "member", "cn", "sAMAccountName", "userPrincipalName"],
            preferred_base=preferred_base,
        )

    def _resolve_group_members(self, group_name, seen_groups, depth=0, domain_hint=""):
        if depth > 5:
            return []

        group_key = (str(group_name or "").lower(), str(domain_hint or "").lower())
        cache = getattr(self, "_group_expand_cache", None)
        if isinstance(cache, dict) and group_key in cache:
            cached = cache.get(group_key)
            if cached is None:
                return None
            return [dict(x) for x in cached]
        if group_key in seen_groups:
            return []
        seen_groups.add(group_key)

        group_entry = self._resolve_group_entry(group_name, domain_hint=domain_hint)
        if group_entry is None:
            if isinstance(cache, dict):
                cache[group_key] = None
            return None

        group_dn = str(group_entry.distinguishedName) if hasattr(group_entry, "distinguishedName") and group_entry.distinguishedName else ""
        if not group_dn:
            return []

        escaped_dn = self._escape_ldap_value(group_dn)
        transitive_filter = (
            "(&(|(objectClass=user)(objectClass=group)(objectClass=computer))"
            "(memberOf:1.2.840.113556.1.4.1941:=" + escaped_dn + "))"
        )

        attrs = ["objectClass", "sAMAccountName", "cn", "userPrincipalName", "distinguishedName"]
        members = []
        seen_names = set()
        member_cap = self._cfg_int("expand_group_member_cap", 2000, minimum=100, maximum=20000)

        try:
            self.ensure_ldap_gc()
            self.ldap_gc_conn.search(
                search_base="",
                search_filter=transitive_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attrs,
                paged_size=1000,
            )
            while True:
                for entry in self.ldap_gc_conn.entries:
                    if len(members) >= member_cap:
                        break
                    name = self._entry_account_name(entry)
                    if not name:
                        continue
                    lower = name.lower()
                    if lower in seen_names:
                        continue
                    seen_names.add(lower)

                    obj_classes = [str(c).lower() for c in entry.objectClass.values] if entry.objectClass else []
                    if "group" in obj_classes:
                        otype = "Group (nested)"
                    elif "computer" in obj_classes:
                        otype = "Computer"
                    elif "user" in obj_classes or "person" in obj_classes:
                        otype = "User"
                    else:
                        otype = "unknown"
                    members.append({"name": name, "type": otype})
                if len(members) >= member_cap:
                    logger.debug("Group expansion cap reached for %s (%d)", group_name, member_cap)
                    break

                cookie = (
                    self.ldap_gc_conn.result
                    .get("controls", {})
                    .get("1.2.840.113556.1.4.319", {})
                    .get("value", {})
                    .get("cookie")
                )
                if not cookie:
                    break
                self.ldap_gc_conn.search(
                    search_base="",
                    search_filter=transitive_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=attrs,
                    paged_size=1000,
                    paged_cookie=cookie,
                )
        except Exception as e:
            logger.debug("Transitive GC member query failed for %s: %s", group_name, e)

        if members:
            if isinstance(cache, dict):
                cache[group_key] = [dict(x) for x in members]
            return members

        # Fallback: direct member list (если matching-rule не поддерживается)
        raw_members = group_entry.member.values if hasattr(group_entry, "member") and group_entry.member else []
        for dn in raw_members:
            resolved = self._resolve_dn(dn, seen_groups, depth + 1)
            for item in resolved:
                nm = (item.get("name") or "").strip().lower()
                if not nm or nm in seen_names:
                    continue
                seen_names.add(nm)
                members.append(item)
                if len(members) >= member_cap:
                    break
            if len(members) >= member_cap:
                break
        if isinstance(cache, dict):
            cache[group_key] = [dict(x) for x in members]
        return members

    def _expand_domain_groups(self, members_list):
        cfg = self.config.get("ad_config", {})
        domain = cfg.get("domain", "")
        if not domain:
            return members_list

        expanded = []
        seen_groups = set()
        expanded_group_keys = set()
        max_groups_per_host = self._cfg_int("expand_max_groups_per_host", 12, minimum=1, maximum=200)
        expand_unknown_accounts = bool(self.config.get("expand_unknown_domain_accounts", False))

        for member in members_list:
            name = (member.get("name") or "").strip()
            obj_type = (member.get("type") or "unknown").strip()
            is_group = obj_type.lower() in ("group", "группа", "group (nested)")

            account_name = name
            domain_hint = ""
            is_domainish = False

            if "\\" in name:
                domain_hint, account_name = name.split("\\", 1)
                is_domainish = bool(domain_hint)
            elif "@" in name:
                account_name, domain_hint = name.split("@", 1)
                is_domainish = True
            elif is_group:
                # Некоторые WMI-методы возвращают доменные группы без префикса DOMAIN\\.
                is_domainish = True
            elif expand_unknown_accounts and obj_type.lower() in ("unknown", "account") and account_name:
                # На части АРМ доменная группа приходит как generic Account/unknown без DOMAIN\.
                short = account_name.split("\\", 1)[-1].lower()
                is_domainish = short not in BUILTIN_ADMINS

            group_expand_key = ((domain_hint or domain).lower(), account_name.lower())
            should_expand = (
                is_domainish and account_name and
                obj_type.lower() not in ("computer", "wellknowngroup") and
                (is_group or expand_unknown_accounts) and
                group_expand_key not in expanded_group_keys
            )
            if should_expand and len(expanded_group_keys) >= max_groups_per_host:
                expanded.append(member)
                continue

            if should_expand:
                try:
                    group_members = self._resolve_group_members(account_name, seen_groups, domain_hint=domain_hint)
                    if group_members:
                        expanded_group_keys.add(group_expand_key)
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

            expanded.append(member)

        return expanded

    def _resolve_dn(self, dn, seen_groups, depth):
        attrs = ["objectClass", "sAMAccountName", "cn", "userPrincipalName", "member", "distinguishedName"]
        entry = None

        try:
            self.ensure_ldap_gc()
            self.ldap_gc_conn.search(
                search_base=str(dn),
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=attrs,
            )
            if self.ldap_gc_conn.entries:
                entry = self.ldap_gc_conn.entries[0]
        except Exception:
            entry = None

        if entry is None:
            try:
                self.ensure_ldap()
                self.ldap_conn.search(
                    search_base=str(dn),
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=attrs,
                )
                if self.ldap_conn.entries:
                    entry = self.ldap_conn.entries[0]
            except Exception:
                return [{"name": str(dn), "type": "unknown (cross-domain)"}]

        if entry is None:
            return [{"name": str(dn), "type": "unknown"}]

        obj_classes = [str(c).lower() for c in entry.objectClass.values] if entry.objectClass else []
        full_name = self._entry_account_name(entry, fallback=str(dn))

        if "group" in obj_classes:
            sam = str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") and entry.sAMAccountName else full_name
            dom = self._domain_from_dn(str(entry.distinguishedName) if hasattr(entry, "distinguishedName") else "")
            nested = self._resolve_group_members(sam, seen_groups, depth, domain_hint=dom)
            items = [{"name": full_name, "type": "Group (nested)"}]
            if nested:
                for nm in nested:
                    nm["via_group"] = full_name
                items.extend(nested)
            return items

        if "computer" in obj_classes:
            return [{"name": full_name, "type": "Computer"}]
        if "user" in obj_classes or "person" in obj_classes:
            return [{"name": full_name, "type": "User"}]
        return [{"name": full_name, "type": "unknown"}]

    def _make_session(self, computer, comp_info=None, use_ssl=False):
        cfg = self._credentials_for_target(comp_info)
        if cfg.get("netbios_domain"):
            username = cfg["netbios_domain"] + "\\" + cfg["username"]
        else:
            username = cfg["username"] + "@" + cfg["domain"]
        port = 5986 if use_ssl else 5985
        scheme = "https" if use_ssl else "http"
        target = scheme + "://" + computer + ":" + str(port)

        host_timeout = int(self.config.get("host_timeout", 20))
        os_name = str((comp_info or {}).get("os") or "").lower()
        is_legacy = ("windows 7" in os_name) or ("windows xp" in os_name) or ("windows 2003" in os_name)
        if is_legacy:
            host_timeout = int(self.config.get("legacy_host_timeout", 10))

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
        if selected is None:
            return ["S-1-5-32-544"]

        normalized = []
        for sid in selected:
            sid_str = str(sid).strip()
            if sid_str in LOCAL_GROUP_PRESETS and sid_str not in normalized:
                normalized.append(sid_str)

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

    def _try_winrm_methods(self, computer, comp_info=None, use_ssl=False):
        session = self._make_session(computer, comp_info=comp_info, use_ssl=use_ssl)
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

    def _make_wmi_connection(self, computer, wmi_user, password, domain="", netbios=""):
        attempts = [
            {"computer": computer, "user": wmi_user, "password": password},
            {"computer": computer, "user": wmi_user, "password": password, "namespace": r"root\cimv2", "find_classes": False},
        ]

        # Some environments require explicit authority for remote WMI/DCOM.
        dom = (netbios or domain or "").strip()
        if dom and "@" not in wmi_user:
            attempts.append({
                "computer": computer,
                "user": wmi_user,
                "password": password,
                "namespace": r"root\cimv2",
                "find_classes": False,
                "authority": "ntlmdomain:" + dom,
            })

        last_err = None
        for kwargs in attempts:
            try:
                return wmi_module.WMI(**kwargs), None
            except TypeError as e:
                # Different pywin32/wmi versions support different kwargs.
                last_err = e
                continue
            except Exception as e:
                last_err = e
                continue

        return None, last_err

    def _is_wmi_access_denied(self, err):
        txt = str(err).lower()
        return (
            "-2147024891" in txt
            or "access is denied" in txt
            or "отказано в доступе" in txt
            or "access denied" in txt
        )

    def _try_wmi(self, computer, comp_info=None):
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
            cfg = self._credentials_for_target(comp_info)
            username = (cfg.get("username") or "").strip()
            domain = (cfg.get("domain") or "").strip()
            netbios = (cfg.get("netbios_domain") or "").strip()

            # Build credential candidates: helps when one format is denied but another works.
            candidates = []
            if "\\" in username or "@" in username:
                candidates.append(username)
            else:
                if netbios:
                    candidates.append(netbios + "\\" + username)
                if domain:
                    candidates.append(username + "@" + domain)
                candidates.append(username)

            seen_cand = set()
            ordered_candidates = []
            for cnd in candidates:
                key = cnd.lower()
                if cnd and key not in seen_cand:
                    seen_cand.add(key)
                    ordered_candidates.append(cnd)

            local_groups = self._get_local_groups()
            last_err = None

            def _safe_member_name(obj):
                return (getattr(obj, "Caption", None) or getattr(obj, "Name", None) or getattr(obj, "SID", None) or "").strip()

            def _compose_member_name(obj, fallback=""):
                domain_v = str(getattr(obj, "Domain", "") or "").strip()
                name_v = str(getattr(obj, "Name", "") or "").strip()
                if domain_v and name_v:
                    return domain_v + "\\" + name_v

                ref_domain = str(getattr(obj, "ReferencedDomainName", "") or "").strip()
                account_name = str(getattr(obj, "AccountName", "") or "").strip()
                if ref_domain and account_name:
                    return ref_domain + "\\" + account_name
                if account_name:
                    return account_name

                caption_v = str(getattr(obj, "Caption", "") or "").strip()
                if caption_v:
                    return caption_v
                sid_v = str(getattr(obj, "SID", "") or "").strip()
                if sid_v:
                    return sid_v
                return str(fallback or "").strip()

            def _skip_noise_name(name, current_sid):
                if not name:
                    return True
                nm = str(name).strip()
                if not nm:
                    return True
                # Ignore obvious noise that appears from some WMI providers/parsing artifacts.
                if len(nm) == 2 and nm[1] == ":" and nm[0].isalpha():
                    return True
                # Do not include the group SID itself as a member.
                if nm.upper() == str(current_sid).upper():
                    return True

                nm_l = nm.lower()
                short = nm_l.split("\\", 1)[-1]
                # Filter self/builtin alias noise that some providers return as a "member".
                if nm_l in ("builtin\\administrators", "builtin\\администраторы"):
                    return True
                if short in ("administrators", "администраторы") and (nm_l.startswith("builtin\\") or nm_l in ("administrators", "администраторы")):
                    return True
                return False

            def _kv_from_component(comp):
                vals = {}
                if not comp:
                    return vals
                tail = str(comp).split(":", 1)[-1]
                if "." not in tail:
                    return vals
                data = tail.split(".", 1)[1]
                for part in data.split(','):
                    if "=" not in part:
                        continue
                    k, v = part.split("=", 1)
                    vals[k.strip()] = v.strip().strip('"')
                return vals

            def _compose_account_name(vals, fallback=""):
                domain_v = (vals.get("Domain") or "").strip()
                name_v = (vals.get("Name") or "").strip()
                if domain_v and name_v:
                    return domain_v + "\\" + name_v

                ref_domain = (vals.get("ReferencedDomainName") or "").strip()
                account_name = (vals.get("AccountName") or "").strip()
                if ref_domain and account_name:
                    return ref_domain + "\\" + account_name
                if account_name:
                    return account_name

                caption_v = (vals.get("Caption") or "").strip()
                if caption_v:
                    return caption_v
                sid_v = (vals.get("SID") or "").strip()
                if sid_v:
                    return sid_v
                return str(fallback or "").strip()

            sid_cache = {}

            def _member_type_from_path(path_value):
                text = str(path_value or "").lower()
                if "win32_group" in text:
                    return "Group"
                if "win32_useraccount" in text:
                    return "User"
                if "win32_account" in text:
                    return "Account"
                if "win32_systemaccount" in text:
                    return "WellKnownGroup"
                if "win32_sid" in text:
                    return "SID"
                return ""

            def _resolve_sid_identity(conn, sid_value):
                sid_text = str(sid_value or "").strip()
                if not sid_text or not sid_text.upper().startswith("S-"):
                    return ("", "")
                if sid_text in sid_cache:
                    return sid_cache[sid_text]

                resolved_name = ""
                resolved_type = ""
                try:
                    sid_objs = conn.Win32_SID(SID=sid_text)
                except Exception:
                    sid_objs = []

                for sid_obj in sid_objs:
                    try:
                        assoc = sid_obj.associators(wmi_result_class="Win32_Account")
                    except Exception:
                        assoc = []
                    for acc in assoc:
                        acc_name = _compose_member_name(acc, fallback="")
                        if acc_name:
                            resolved_name = acc_name
                            pth = str(getattr(acc, "Path_", ""))
                            detected_type = _member_type_from_path(pth)
                            resolved_type = detected_type if detected_type else "Account"
                            break
                    if resolved_name:
                        break

                sid_cache[sid_text] = (resolved_name, resolved_type)
                return sid_cache[sid_text]

            def _collect_via_netlocalgroup(remote_host, local_group_name, source_group_label):
                if not WIN32NET_AVAILABLE:
                    return []
                result = []
                try:
                    server = "\\\\" + str(remote_host).split(".")[0]
                    resume = 0
                    while True:
                        data, total, resume = win32net.NetLocalGroupGetMembers(server, local_group_name, 2, resume, 4096)
                        for item in data:
                            domain_and_name = str(item.get("domainandname") or "").strip()
                            if not domain_and_name:
                                continue
                            sid_v = str(item.get("sid") or "").strip()
                            if _skip_noise_name(domain_and_name, sid_v):
                                continue
                            sid_usage = int(item.get("sidusage", 0) or 0)
                            if sid_usage in (2, 4, 5):
                                typ = "Group"
                            elif sid_usage in (1, 6, 7):
                                typ = "User"
                            else:
                                typ = "Account"
                            result.append({"name": domain_and_name, "type": typ, "source_group": source_group_label})
                        if not resume:
                            break
                except Exception as e:
                    logger.debug("NetLocalGroupGetMembers failed for %s/%s: %s", remote_host, local_group_name, e)
                return result

            access_denied_users = []
            for wmi_user in ordered_candidates:
                c, conn_err = self._make_wmi_connection(
                    computer=computer,
                    wmi_user=wmi_user,
                    password=cfg["password"],
                    domain=domain,
                    netbios=netbios,
                )
                if c is None:
                    last_err = conn_err
                    # Do not fail fast on ACCESS_DENIED here: another credential format
                    # (e.g. UPN vs NETBIOS\\user) may still succeed for the same account.
                    if self._is_wmi_access_denied(conn_err):
                        access_denied_users.append(wmi_user)
                    continue

                members = []
                seen_members = set()
                scanned_groups = []
                short_host = computer.split(".")[0].lower()

                for target_group in local_groups:
                    sid = target_group["sid"]
                    group_name = target_group["name"]
                    groups = []
                    try:
                        groups = c.Win32_Group(SID=sid)
                    except Exception as e:
                        if self._is_wmi_access_denied(e):
                            return (None, "WMI access denied while reading group " + group_name)
                        pass

                    for group in groups:
                        scanned_groups.append(group_name)

                        # 1) Standard typed association paths
                        for rclass, rtype in [
                            ("Win32_UserAccount", "User"),
                            ("Win32_Group", "Group"),
                            ("Win32_Account", "Account"),
                            ("Win32_SystemAccount", "WellKnownGroup"),
                            ("Win32_SID", "SID"),
                        ]:
                            try:
                                assoc_items = group.associators(wmi_result_class=rclass)
                            except Exception as e:
                                if self._is_wmi_access_denied(e):
                                    return (None, "WMI access denied while reading members of " + group_name)
                                assoc_items = []
                            for a in assoc_items:
                                name = _compose_member_name(a, fallback=_safe_member_name(a))
                                member_type = rtype
                                sid_candidate = str(getattr(a, "SID", "") or "").strip()
                                if member_type == "SID" or str(name).upper().startswith("S-") or sid_candidate.upper().startswith("S-"):
                                    resolved_name, resolved_type = _resolve_sid_identity(c, sid_candidate or name)
                                    if resolved_name:
                                        name = resolved_name
                                        if resolved_type:
                                            member_type = resolved_type
                                if _skip_noise_name(name, sid):
                                    continue
                                key = (name.lower(), member_type, group_name)
                                if key in seen_members:
                                    continue
                                seen_members.add(key)
                                members.append({"name": name, "type": member_type, "source_group": group_name})

                        # 2) Raw association fallback
                        try:
                            raw_assoc = group.associators()
                        except Exception as e:
                            if self._is_wmi_access_denied(e):
                                return (None, "WMI access denied while reading raw associations of " + group_name)
                            raw_assoc = []
                        for a in raw_assoc:
                            name = _compose_member_name(a, fallback=_safe_member_name(a))
                            if not name:
                                continue
                            p = str(getattr(a, "Path_", ""))
                            typ = _member_type_from_path(p)
                            if not typ:
                                # Skip non-account objects to avoid noise (e.g. logical disks).
                                continue
                            sid_candidate = str(getattr(a, "SID", "") or "").strip()
                            if typ == "SID" or str(name).upper().startswith("S-") or sid_candidate.upper().startswith("S-"):
                                resolved_name, resolved_type = _resolve_sid_identity(c, sid_candidate or name)
                                if resolved_name:
                                    name = resolved_name
                                    if resolved_type:
                                        typ = resolved_type
                            if _skip_noise_name(name, sid):
                                continue
                            key = (name.lower(), typ, group_name)
                            if key in seen_members:
                                continue
                            seen_members.add(key)
                            members.append({"name": name, "type": typ, "source_group": group_name})

                        # 3) Win32_GroupUser targeted query (avoid scanning all relations globally)
                        try:
                            gdom = getattr(group, "Domain", None) or short_host
                            gname = getattr(group, "Name", None) or group_name
                            gc = 'Win32_Group.Domain="%s",Name="%s"' % (str(gdom).replace('"', '\"'), str(gname).replace('"', '\"'))
                            wql = 'SELECT * FROM Win32_GroupUser WHERE GroupComponent="%s"' % gc.replace('"', '\"')
                            rels = c.query(wql)
                        except Exception as e:
                            if self._is_wmi_access_denied(e):
                                return (None, "WMI access denied while reading GroupUser relations of " + group_name)
                            rels = []

                        for rel in rels:
                            pc = getattr(rel, "PartComponent", "")
                            pc_vals = _kv_from_component(pc)
                            name = _compose_account_name(pc_vals, fallback=pc)
                            if not name:
                                continue
                            pclass = str(pc).split(":", 1)[-1].split(".", 1)[0]
                            ptype = _member_type_from_path(pclass)
                            if not ptype:
                                continue
                            sid_candidate = (pc_vals.get("SID") or "").strip()
                            if ptype == "SID" or str(name).upper().startswith("S-") or sid_candidate.upper().startswith("S-"):
                                resolved_name, resolved_type = _resolve_sid_identity(c, sid_candidate or name)
                                if resolved_name:
                                    name = resolved_name
                                    if resolved_type:
                                        ptype = resolved_type
                            if _skip_noise_name(name, sid):
                                continue
                            key = (name.lower(), ptype, group_name)
                            if key in seen_members:
                                continue
                            seen_members.add(key)
                            members.append({"name": name, "type": ptype, "source_group": group_name})

                        # 3b) SID-based GroupUser query fallback (works when Domain/Name addressing misses localized entries)
                        try:
                            sid_like = sid.replace('"', '\"')
                            sid_wql = 'SELECT * FROM Win32_GroupUser WHERE GroupComponent LIKE "%%SID=\"%s\"%%"' % sid_like
                            sid_rels = c.query(sid_wql)
                        except Exception:
                            sid_rels = []

                        for rel in sid_rels:
                            pc = getattr(rel, "PartComponent", "")
                            pc_vals = _kv_from_component(pc)
                            name = _compose_account_name(pc_vals, fallback=pc)
                            if not name:
                                continue
                            pclass = str(pc).split(":", 1)[-1].split(".", 1)[0]
                            ptype = _member_type_from_path(pclass)
                            if not ptype:
                                continue

                            sid_candidate = (pc_vals.get("SID") or "").strip()
                            if ptype == "SID" or str(name).upper().startswith("S-") or sid_candidate.upper().startswith("S-"):
                                resolved_name, resolved_type = _resolve_sid_identity(c, sid_candidate or name)
                                if resolved_name:
                                    name = resolved_name
                                    if resolved_type:
                                        ptype = resolved_type

                            if _skip_noise_name(name, sid):
                                continue
                            key = (name.lower(), ptype, group_name)
                            if key in seen_members:
                                continue
                            seen_members.add(key)
                            members.append({"name": name, "type": ptype, "source_group": group_name})

                        # 3c) Broad GroupUser scan fallback for providers where exact GroupComponent filter is unreliable.
                        if not rels and not sid_rels:
                            try:
                                all_rels = c.query("SELECT * FROM Win32_GroupUser")
                            except Exception:
                                all_rels = []

                            group_dom = str(getattr(group, "Domain", "") or short_host).strip().lower()
                            group_nm = str(getattr(group, "Name", "") or group_name).strip().lower()
                            for rel in all_rels:
                                gc = getattr(rel, "GroupComponent", "")
                                gc_vals = _kv_from_component(gc)
                                gc_name = str(gc_vals.get("Name") or "").strip().lower()
                                if not gc_name or gc_name != group_nm:
                                    continue
                                gc_domain = str(gc_vals.get("Domain") or "").strip().lower()
                                if gc_domain and gc_domain not in (group_dom, short_host):
                                    continue

                                pc = getattr(rel, "PartComponent", "")
                                pc_vals = _kv_from_component(pc)
                                name = _compose_account_name(pc_vals, fallback=pc)
                                if not name:
                                    continue
                                pclass = str(pc).split(":", 1)[-1].split(".", 1)[0]
                                ptype = _member_type_from_path(pclass)
                                if not ptype:
                                    continue
                                sid_candidate = (pc_vals.get("SID") or "").strip()
                                if ptype == "SID" or str(name).upper().startswith("S-") or sid_candidate.upper().startswith("S-"):
                                    resolved_name, resolved_type = _resolve_sid_identity(c, sid_candidate or name)
                                    if resolved_name:
                                        name = resolved_name
                                        if resolved_type:
                                            ptype = resolved_type
                                if _skip_noise_name(name, sid):
                                    continue
                                key = (name.lower(), ptype, group_name)
                                if key in seen_members:
                                    continue
                                seen_members.add(key)
                                members.append({"name": name, "type": ptype, "source_group": group_name})

                # 4) ASSOCIATORS OF fallback: often returns domain groups where standard paths are incomplete
                for target_group in local_groups:
                    sid = target_group["sid"]
                    group_name = target_group["name"]
                    groups = []
                    try:
                        groups = c.Win32_Group(SID=sid)
                    except Exception:
                        groups = []

                    for group in groups:
                        gpath = str(getattr(group, "path_", "") or getattr(group, "Path_", "")).strip()
                        if not gpath:
                            continue
                        try:
                            wql = "ASSOCIATORS OF {" + gpath + "} WHERE AssocClass=Win32_GroupUser"
                            assoc_items = c.query(wql)
                        except Exception:
                            assoc_items = []

                        for a in assoc_items:
                            p = str(getattr(a, "Path_", ""))
                            typ = _member_type_from_path(p)
                            if not typ:
                                continue

                            vals = _kv_from_component(p)
                            name = _compose_account_name(vals, fallback=_safe_member_name(a))
                            sid_candidate = (vals.get("SID") or "").strip()
                            if typ == "SID" or str(name).upper().startswith("S-") or sid_candidate.upper().startswith("S-"):
                                resolved_name, resolved_type = _resolve_sid_identity(c, sid_candidate or name)
                                if resolved_name:
                                    name = resolved_name
                                    if resolved_type:
                                        typ = resolved_type
                            if _skip_noise_name(name, sid):
                                continue

                            key = (name.lower(), typ, group_name)
                            if key in seen_members:
                                continue
                            seen_members.add(key)
                            members.append({"name": name, "type": typ, "source_group": group_name})

                if WIN32NET_AVAILABLE:
                    for target_group in local_groups:
                        sid = target_group["sid"]
                        group_name = target_group["name"]
                        groups = []
                        try:
                            groups = c.Win32_Group(SID=sid)
                        except Exception:
                            groups = []
                        for group in groups:
                            resolved_group_name = str(getattr(group, "Name", "") or group_name).strip() or group_name
                            net_items = _collect_via_netlocalgroup(computer, resolved_group_name, group_name)
                            for ni in net_items:
                                key = (ni["name"].lower(), ni["type"], ni["source_group"])
                                if key in seen_members:
                                    continue
                                seen_members.add(key)
                                members.append(ni)

                if members:
                    suffix = "[" + ",".join(sorted(set(scanned_groups))) + "]" if scanned_groups else ""
                    return ("WMI" + suffix, members)

            if access_denied_users and last_err is not None:
                return (None, "WMI access denied for user(s): " + ", ".join(access_denied_users))
            if last_err is not None:
                return (None, "WMI: " + str(last_err))
            return (None, "WMI: empty")

        except Exception as e:
            return (None, "WMI: " + str(e))
        finally:
            if com_init and PYTHONCOM_AVAILABLE:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    def _try_rpc_samr(self, computer, comp_info=None, _cfg_override=None):
        if not WIN32NET_AVAILABLE:
            return (None, "NetAPI not installed")

        cfg = _cfg_override if isinstance(_cfg_override, dict) else self._credentials_for_target(comp_info)

        local_groups = self._get_local_groups()
        if not local_groups:
            return (None, "No local groups selected")

        members = []
        seen = set()
        errors = []

        server_candidates = []
        connected_shares = set()
        user_base = str(cfg.get("username") or "").strip()
        password = str(cfg.get("password") or "")
        netbios = str(cfg.get("netbios_domain") or "").strip()
        domain = str(cfg.get("domain") or "").strip()

        def _fmt_exc(err):
            txt = str(err)
            if len(txt) > 180:
                txt = txt[:180]
            return txt

        def _smb_user_candidates():
            candidates = []
            if not user_base:
                return candidates

            base_short = user_base
            if "\\" in user_base:
                base_short = user_base.split("\\", 1)[1].strip() or user_base
            elif "@" in user_base:
                base_short = user_base.split("@", 1)[0].strip() or user_base

            candidates.append(user_base)
            if netbios and base_short:
                candidates.append(netbios + "\\" + base_short)
            if domain and base_short:
                candidates.append(base_short + "@" + domain)
            if base_short:
                candidates.append(base_short)

            uniq = []
            seen = set()
            for cnd in candidates:
                key = cnd.lower()
                if cnd and key not in seen:
                    seen.add(key)
                    uniq.append(cnd)
            return uniq

        def _ensure_smb_session(server):
            if not WIN32NETCON_AVAILABLE:
                return (False, "win32netcon unavailable")
            users = _smb_user_candidates()
            if not users:
                return (False, "no smb user candidates")
            ipc_remote = str(server) + r"\IPC$"
            last_err = ""
            for smb_user in users:
                ui2 = {
                    "remote": ipc_remote,
                    "password": password,
                    "username": smb_user,
                    "asg_type": getattr(win32netcon, "USE_WILDCARD", 0),
                }
                try:
                    win32net.NetUseAdd(None, 2, ui2)
                    connected_shares.add(ipc_remote)
                    return (True, "session user=" + smb_user)
                except Exception as e1:
                    e1_text = _fmt_exc(e1)
                    e1_lower = e1_text.lower()
                    last_err = smb_user + ": " + e1_text
                    # Deterministic target/session errors: do not waste time on more retries.
                    if " 66" in e1_lower or "error 66" in e1_lower or "2457" in e1_lower or "clock skew" in e1_lower:
                        return (False, "fatal session error: " + last_err)
                    # Retry with NetUseDel only when this looks like an existing conflicting session.
                    if "1219" not in e1_text and "multiple connections" not in e1_lower:
                        continue
                    try:
                        try:
                            win32net.NetUseDel(None, ipc_remote, 2)
                        except Exception as del_err:
                            del_text = _fmt_exc(del_err).lower()
                            # 2250 means there was no mapped connection to delete; proceed with retry add.
                            if "2250" not in del_text and "could not be found" not in del_text:
                                raise
                        win32net.NetUseAdd(None, 2, ui2)
                        connected_shares.add(ipc_remote)
                        return (True, "session(retry) user=" + smb_user)
                    except Exception as e2:
                        last_err = smb_user + ": " + _fmt_exc(e2)
                        continue
            return (False, last_err or "session open failed")

        # IMPORTANT: do not use None here, it points to local machine context.
        # We must query only the remote target host.
        full = str(computer or "").strip()
        short = ""
        try:
            ipaddress.ip_address(full)
        except ValueError:
            short = full.split(".")[0].strip()
            # Guard against malformed numeric hostnames (e.g. partial IPv4-like labels).
            if short.replace("-", "").isdigit():
                short = ""
        for srv in (short, full):
            if not srv:
                continue
            candidate = r"\\" + srv
            if candidate not in server_candidates:
                server_candidates.append(candidate)

        for target_group in local_groups:
            sid = target_group["sid"]
            source_group = target_group["name"]
            aliases = []
            for nm in LOCAL_GROUP_NAME_ALIASES.get(sid, []):
                if nm and nm not in aliases:
                    aliases.append(nm)
            if source_group not in aliases:
                aliases.insert(0, source_group)

            group_ok = False
            group_attempt_errors = []

            for server in server_candidates:
                # Try explicit SMB session with provided credentials (helps when process token lacks remote admin rights).
                session_ok, session_note = _ensure_smb_session(server)
                if not session_ok:
                    logger.debug("RPC-SAMR session open failed for %s via %s: %s", computer, server, session_note)
                for group_name in aliases:
                    try:
                        level_errors = []
                        fetched_any = False
                        for lvl in (2, 1, 0):
                            try:
                                resume = 0
                                while True:
                                    data, total, resume = win32net.NetLocalGroupGetMembers(server, group_name, lvl, resume, 4096)
                                    fetched_any = True
                                    for item in data:
                                        if lvl == 2:
                                            raw_name = item.get("domainandname")
                                            sid_usage = int(item.get("sidusage", 0) or 0)
                                        elif lvl == 1:
                                            raw_name = item.get("name") or item.get("domainandname")
                                            sid_usage = int(item.get("sidusage", 0) or 0)
                                        else:
                                            raw_name = item.get("domainandname") or item.get("name") or item.get("sid")
                                            sid_usage = int(item.get("sidusage", 0) or 0)

                                        domain_and_name = str(raw_name or "").strip()
                                        if not domain_and_name:
                                            continue

                                        if sid_usage in (2, 4, 5):
                                            typ = "Group"
                                        elif sid_usage in (1, 6, 7):
                                            typ = "User"
                                        else:
                                            typ = "Account"

                                        key = (domain_and_name.lower(), typ, source_group)
                                        if key in seen:
                                            continue
                                        seen.add(key)
                                        members.append({"name": domain_and_name, "type": typ, "source_group": source_group})
                                    if not resume:
                                        break
                                if fetched_any:
                                    break
                            except Exception as le:
                                level_errors.append("lvl=" + str(lvl) + ": " + _fmt_exc(le))
                                if "access is denied" not in str(le).lower() and "'5'" not in str(le):
                                    break

                        if fetched_any:
                            group_ok = True
                            break

                        raise RuntimeError("; ".join(level_errors) if level_errors else "no data")
                    except Exception as e:
                        detail = (
                            "server=" + str(server) +
                            ", group=" + str(group_name) +
                            ", session=" + ("ok" if session_ok else "fail") +
                            (", " + session_note if session_note else "") +
                            ", err=" + _fmt_exc(e)
                        )
                        group_attempt_errors.append(detail)
                        continue
                if group_ok:
                    break

            if not group_ok:
                if group_attempt_errors:
                    errors.append(source_group + ": " + " || ".join(group_attempt_errors[:3]))
                else:
                    errors.append(source_group + ": no successful attempts")

        if WIN32NETCON_AVAILABLE:
            for remote in list(connected_shares):
                try:
                    win32net.NetUseDel(None, remote, 0)
                except Exception:
                    pass

        if members:
            return ("RPC-SAMR", members)

        # If primary credentials failed, try alternate server credential set once.
        if _cfg_override is None:
            override = dict(self.config.get("server_ad_config", {}) or {})
            if override:
                alt_cfg = dict(self.config.get("ad_config", {}) or {})
                for key in ("username", "password", "domain", "netbios_domain", "server"):
                    val = override.get(key)
                    if val:
                        alt_cfg[key] = val
                if alt_cfg:
                    cur_user = str(cfg.get("username") or "")
                    cur_pass = str(cfg.get("password") or "")
                    alt_user = str(alt_cfg.get("username") or "")
                    alt_pass = str(alt_cfg.get("password") or "")
                    if (alt_user, alt_pass) != (cur_user, cur_pass):
                        m2, r2 = self._try_rpc_samr(computer, comp_info=comp_info, _cfg_override=alt_cfg)
                        if m2:
                            return (m2, r2)
                        if r2:
                            errors.append("alt-creds: " + str(r2)[:200])

        if errors:
            return (None, "RPC-SAMR: " + "; ".join(errors))
        return (None, "RPC-SAMR: empty")


    # Backward compatibility alias for previous config/docs.
    def _try_smb_netapi(self, computer, comp_info=None):
        return self._try_rpc_samr(computer, comp_info=comp_info)

    def _build_target_candidates(self, computer, ip=None):
        candidates = []

        def _add(val):
            v = str(val or "").strip()
            if not v:
                return
            key = v.lower()
            if key not in seen:
                seen.add(key)
                candidates.append(v)

        seen = set()
        host = str(computer or "").strip()
        short = host.split(".", 1)[0] if host else ""

        _add(host)
        _add(short)

        domain = str((self.config.get("ad_config") or {}).get("domain") or "").strip()
        if short and domain and "." not in short:
            _add(short + "." + domain)

        _add(ip)
        return candidates

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
        sem_acquired = False
        try:
            if self.cancelled:
                raise RuntimeError("Cancelled")

            ip = dns_cache.resolve(computer)
            result["ip"] = ip

            sem = getattr(self, "net_semaphore", None)
            if sem is not None:
                queue_timeout = self._cfg_int("network_queue_timeout_sec", 30, minimum=5, maximum=300)
                wait_started = time.time()
                while not sem.acquire(timeout=0.5):
                    if self.cancelled:
                        raise RuntimeError("Cancelled")
                    if time.time() - wait_started > queue_timeout:
                        raise RuntimeError("Network queue timeout waiting for worker slot")
                sem_acquired = True

            deadline = time.time() + self._cfg_int("host_hard_timeout_sec", 45, minimum=10, maximum=900)
            targets = self._host_candidates(computer, ip)
            if not ip:
                targets = [computer]

            aggregate_ports = {
                "5985_winrm": False,
                "5986_winrm_ssl": False,
                "445_smb": False,
                "3389_rdp": False,
            }
            details = []
            resolved_method = None
            resolved_members = None

            for candidate in targets:
                if time.time() >= deadline:
                    details.append("Host hard timeout reached")
                    break

                ports = self._probe_ports_fast(candidate)
                for key in aggregate_ports:
                    aggregate_ports[key] = aggregate_ports[key] or bool(ports.get(key))

                try:
                    method, members, try_details = self._collect_members_for_target(candidate, comp_info, ports)
                except Exception as exc:
                    logger.exception("Collector failed for %s via %s: %s", computer, candidate, exc)
                    method, members, try_details = (None, None, ["collector error: " + str(exc)])

                if members is not None:
                    resolved_method = method
                    resolved_members = members
                    if candidate != computer:
                        result["computer_resolved"] = candidate
                    break

                for item in (try_details or []):
                    details.append(candidate + ": " + str(item))
                if any(self._is_fatal_enum_error(x) for x in (try_details or [])):
                    break

            result["ports"] = aggregate_ports

            if resolved_members is None:
                if not ip:
                    base_error = "DNS failed"
                elif not any(aggregate_ports.values()):
                    base_error = "Host OFFLINE. IP: " + str(ip)
                elif any("access denied" in str(d).lower() for d in details):
                    base_error = "Host ALIVE, but access denied for remote enumeration"
                elif aggregate_ports["445_smb"] and not aggregate_ports["5985_winrm"] and not aggregate_ports["5986_winrm_ssl"]:
                    base_error = "Host ALIVE (SMB), WinRM CLOSED"
                elif aggregate_ports["3389_rdp"] and not aggregate_ports["5985_winrm"] and not aggregate_ports["5986_winrm_ssl"]:
                    base_error = "Host ALIVE (RDP), WinRM CLOSED"
                else:
                    base_error = "All methods failed"
                if details:
                    base_error += " | " + "; ".join(details)
                raise RuntimeError(base_error)

            result["method"] = resolved_method
            classified = []
            for entry in resolved_members:
                if isinstance(entry, dict):
                    name = str(entry.get("name", "")).strip()
                    typ = entry.get("type", "unknown")
                    src_group = entry.get("source_group")
                else:
                    name = str(entry).strip()
                    typ = "unknown"
                    src_group = None
                if not name:
                    continue
                classified_member = self._classify_member(name, typ)
                if src_group:
                    classified_member["source_group"] = src_group
                classified.append(classified_member)

            classified = self._expand_with_domain_aliases(classified, self.config.get("domain_aliases", []))
            if self.config.get("expand_groups", True):
                try:
                    classified = self._expand_domain_groups(classified)
                except Exception as expand_err:
                    logger.debug("Group expansion error on %s: %s", computer, expand_err)

            result["members"] = classified
            self._add_members(len(classified))
            result["risk"] = calc_risk_score(classified, set(self.config.get("allowed_admins", [])))

        except Exception as e:
            if str(e) != "Cancelled":
                result["error"] = str(e)
                self._inc_errors()
                logger.warning("FAIL %s: %s", computer, e)
        finally:
            if sem_acquired and getattr(self, "net_semaphore", None) is not None:
                try:
                    self.net_semaphore.release()
                except Exception:
                    pass

        result["scan_time_sec"] = round(time.time() - t0, 2)
        self.result_queue.put({"type": "machine", "data": result})
        return result

    def run(self, config):
        self.reset()
        self.running = True
        self.config = config
        self._start_time = time.time()

        apply_runtime_log_settings(config.get("debug_log", False))

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
                    workstations = self.get_computers(config["workstations_ou"])
                    for c in workstations:
                        c["target_type"] = "workstation"
                    comp_list += workstations
                if config.get("servers_ou"):
                    servers = self.get_computers(config["servers_ou"])
                    for c in servers:
                        c["target_type"] = "server"
                    comp_list += servers
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
            max_cfg = int(config.get("max_threads", 30))
            cpu_hint = max(4, (os.cpu_count() or 4) * 8)
            hard_cap = min(64, cpu_hint)
            if self.total < max_cfg:
                max_w = max(1, self.total)
            else:
                max_w = min(max_cfg, hard_cap)

            self.executor = ThreadPoolExecutor(max_workers=max_w)
            net_limit_cfg = int(config.get("network_limit", 0) or 0)
            if net_limit_cfg > 0:
                net_limit = max(1, min(net_limit_cfg, max_w))
                self.net_semaphore = threading.BoundedSemaphore(net_limit)
                logger.info("Network concurrency limit: %d", net_limit)
            else:
                net_limit = 0
                self.net_semaphore = None
            rpc_limit_cfg = int(config.get("rpc_parallel_limit", 0) or 0)
            if bool(config.get("use_rpc_fallback", False)):
                if rpc_limit_cfg <= 0:
                    rpc_limit = max(1, min(8, max_w // 4 or 1))
                else:
                    rpc_limit = max(1, min(rpc_limit_cfg, max_w))
                self.rpc_semaphore = threading.BoundedSemaphore(rpc_limit)
                logger.info("RPC concurrency limit: %d", rpc_limit)
            else:
                self.rpc_semaphore = None

            probe_workers = min(64, max(8, max_w * 2))
            self.probe_executor = ThreadPoolExecutor(max_workers=probe_workers)
            logger.info("Thread pool size: %d (requested=%d, cap=%d)", max_w, max_cfg, hard_cap)
            logger.info("Network concurrency limit: %s", "disabled" if net_limit == 0 else str(net_limit))
            logger.info("Port probe pool size: %d", probe_workers)
            futs = {}
            for c in unique:
                futs[self.executor.submit(self.scan_machine, c)] = c["hostname"]

            per_host_guard = self._cfg_int("host_hard_timeout_sec", 45, minimum=10, maximum=900) + 10
            pending = set(futs.keys())
            started_at = {fut: time.time() for fut in pending}
            warned_overdue = set()

            while pending and not self.cancelled:
                done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)

                for fut in done:
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

                now = time.time()
                for fut in pending:
                    if now - started_at.get(fut, now) > per_host_guard and fut not in warned_overdue:
                        warned_overdue.add(fut)
                        host = futs.get(fut, "(unknown)")
                        logger.warning(
                            "Host is running longer than guard limit but still waiting for real result: %s",
                            host,
                        )

            if self.cancelled and pending:
                logger.info("Cancellation requested: persisting partial results (%d pending hosts will be cancelled)", len(pending))
                for fut in pending:
                    fut.cancel()

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
                    "cancelled": bool(self.cancelled),
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
            if getattr(self, "probe_executor", None):
                self.probe_executor.shutdown(wait=False, cancel_futures=True)
                self.probe_executor = None
            self.net_semaphore = None
            self.rpc_semaphore = None
            if self.ldap_conn:
                try:
                    self.ldap_conn.unbind()
                except Exception:
                    pass
            if self.ldap_gc_conn:
                try:
                    self.ldap_gc_conn.unbind()
                except Exception:
                    pass

            # Clear password from memory
            if self.config.get("ad_config"):
                self.config["ad_config"]["password"] = "***CLEARED***"
            if self.config.get("server_ad_config"):
                self.config["server_ad_config"]["password"] = "***CLEARED***"

            self.running = False
            self.result_queue.put({
                "type": "completed",
                "json": os.path.basename(json_path),
                "csv": os.path.basename(csv_path),
                "summary": os.path.basename(summary_path),
                "stopped": bool(self.cancelled),
            })

    def _build_summary(self, all_results):
        member_to_computers = defaultdict(list)
        member_via_groups = defaultdict(set)      # НОВОЕ: какие группы привели этого участника
        member_types = defaultdict(set)           # НОВОЕ: какие типы объектов были у участника
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
        machine_memberships = {}
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
                machine_memberships[res["computer"]] = {
                    "os": res.get("os", ""),
                    "method": res.get("method", ""),
                    "scan_time_sec": res.get("scan_time_sec", 0),
                    "ports": res.get("ports", {}),
                    "error": res.get("error", ""),
                    "groups": {},
                }
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
            machine_memberships[res["computer"]] = {
                "os": res.get("os", ""),
                "method": res.get("method", ""),
                "scan_time_sec": res.get("scan_time_sec", 0),
                "ports": res.get("ports", {}),
                "error": "",
                "groups": _build_machine_memberships(res.get("members", [])),
            }

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

                mtype = str(m.get("type", "") or "").strip()
                if mtype:
                    member_types[name].add(mtype)

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

            types_for_member = sorted(member_types.get(name, set()))
            is_group_member = any("group" in t.lower() or "группа" in t.lower() or "nested" in t.lower() for t in types_for_member)

            top_admins_list.append({
                "account": name,
                "machine_count": len(set(machines)),
                "is_builtin": is_builtin,
                "is_local_admin": is_local_admin,
                "via_group": ", ".join(via_groups) if via_groups else "",
                "type": "Group" if is_group_member else "User",
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
            "machine_memberships": machine_memberships,
            "metrics": metrics.get_stats(),
        }
    def stop(self):
        self.cancelled = True
        if self.executor:
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        if getattr(self, "probe_executor", None):
            try:
                self.probe_executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
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
    member_types = defaultdict(set)
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
    machine_memberships = {}
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
            machine_memberships[res["computer"]] = {
                "os": res.get("os", ""),
                "method": res.get("method", ""),
                "scan_time_sec": res.get("scan_time_sec", 0),
                "ports": res.get("ports", {}),
                "error": res.get("error", ""),
                "groups": {},
            }
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
        machine_memberships[res["computer"]] = {
            "os": res.get("os", ""),
            "method": res.get("method", ""),
            "scan_time_sec": res.get("scan_time_sec", 0),
            "ports": res.get("ports", {}),
            "error": "",
            "groups": _build_machine_memberships(res.get("members", [])),
        }

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

            mtype = str(m.get("type", "") or "").strip()
            if mtype:
                member_types[name].add(mtype)

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

        types_for_member = sorted(member_types.get(name, set()))
        is_group_member = any("group" in t.lower() or "группа" in t.lower() or "nested" in t.lower() for t in types_for_member)

        top_admins_list.append({
            "account": name,
            "machine_count": len(set(machines)),
            "is_builtin": is_builtin,
            "is_local_admin": is_local_admin,
            "via_group": ", ".join(via_groups) if via_groups else "",
            "type": "Group" if is_group_member else "User",
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
        "machine_memberships": machine_memberships,
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

    # Backward compatibility: allow legacy checkbox payload under scan.groups
    if "group_targets" not in cfg and isinstance(cfg.get("groups"), dict):
        groups = cfg.get("groups") or {}
        group_targets = []
        if groups.get("administrators"):
            group_targets.append("S-1-5-32-544")
        if groups.get("remoteDesktopUsers"):
            group_targets.append("S-1-5-32-555")
        if groups.get("distributedComUsers"):
            group_targets.append("S-1-5-32-562")
        if groups.get("remoteManagementUsers"):
            group_targets.append("S-1-5-32-580")
        cfg["group_targets"] = group_targets

    if isinstance(cfg.get("group_targets"), list) and not cfg.get("group_targets"):
        return JSONResponse({"error": "Select at least one local group to scan"}, status_code=400)

    ad_cfg = cfg.get("ad_config") or {}
    srv_cfg = cfg.get("server_ad_config") or {}
    work_ou = str(cfg.get("workstations_ou") or "").strip()
    srv_ou = str(cfg.get("servers_ou") or "").strip()

    # Credentials fallback to reduce operator friction:
    # - If server creds are omitted, reuse workstation creds.
    # - If workstation password is omitted but server password is present, reuse it.
    if not str(srv_cfg.get("username") or "").strip() and str(ad_cfg.get("username") or "").strip():
        srv_cfg["username"] = ad_cfg.get("username")
    if not str(srv_cfg.get("password") or "").strip() and str(ad_cfg.get("password") or "").strip():
        srv_cfg["password"] = ad_cfg.get("password")
    if not str(ad_cfg.get("password") or "").strip() and str(srv_cfg.get("password") or "").strip():
        ad_cfg["password"] = srv_cfg.get("password")
    cfg["ad_config"] = ad_cfg
    cfg["server_ad_config"] = srv_cfg

    # Sanitize runtime tuning values to avoid unusable tiny timeouts from UI input.
    try:
        cfg["host_timeout"] = max(2, min(300, int(cfg.get("host_timeout", 20))))
    except (TypeError, ValueError):
        cfg["host_timeout"] = 20
    try:
        cfg["host_hard_timeout_sec"] = max(10, min(900, int(cfg.get("host_hard_timeout_sec", 45))))
    except (TypeError, ValueError):
        cfg["host_hard_timeout_sec"] = 45
    try:
        cfg["port_probe_timeout_winrm"] = max(0.3, min(5.0, float(cfg.get("port_probe_timeout_winrm", 1.0))))
    except (TypeError, ValueError):
        cfg["port_probe_timeout_winrm"] = 1.0
    try:
        cfg["port_probe_timeout_fast"] = max(0.1, min(3.0, float(cfg.get("port_probe_timeout_fast", 0.6))))
    except (TypeError, ValueError):
        cfg["port_probe_timeout_fast"] = 0.6
    try:
        cfg["rpc_parallel_limit"] = max(0, min(64, int(cfg.get("rpc_parallel_limit", 0))))
    except (TypeError, ValueError):
        cfg["rpc_parallel_limit"] = 0
    try:
        cfg["expand_max_groups_per_host"] = max(1, min(200, int(cfg.get("expand_max_groups_per_host", 12))))
    except (TypeError, ValueError):
        cfg["expand_max_groups_per_host"] = 12
    try:
        cfg["expand_group_member_cap"] = max(100, min(20000, int(cfg.get("expand_group_member_cap", 2000))))
    except (TypeError, ValueError):
        cfg["expand_group_member_cap"] = 2000
    cfg["expand_unknown_domain_accounts"] = bool(cfg.get("expand_unknown_domain_accounts", False))
    cfg["use_rpc_fallback"] = bool(cfg.get("use_rpc_fallback", True))
    cfg["use_rpc_adaptive"] = bool(cfg.get("use_rpc_adaptive", True))

    if not str(ad_cfg.get("server") or "").strip() or not str(ad_cfg.get("username") or "").strip():
        return JSONResponse({"error": "Missing AD server/username"}, status_code=400)

    if work_ou and not str(ad_cfg.get("password") or "").strip():
        return JSONResponse({"error": "Workstations OU requires workstation password"}, status_code=400)

    if srv_ou and (not str(srv_cfg.get("username") or "").strip() or not str(srv_cfg.get("password") or "").strip()):
        return JSONResponse({"error": "Servers OU requires server username/password"}, status_code=400)

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
