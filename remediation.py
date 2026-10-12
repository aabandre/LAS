"""LAS local-group remediation engine, isolated from the scanner and HTTP routes."""
import base64
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import winrm

WMI_AVAILABLE = False
try:
    import wmi as wmi_module
    WMI_AVAILABLE = True
except ImportError:
    wmi_module = None

WIN32NET_AVAILABLE = False
WIN32SECURITY_AVAILABLE = False
try:
    import win32net
    WIN32NET_AVAILABLE = True
except ImportError:
    win32net = None
try:
    import win32security
    WIN32SECURITY_AVAILABLE = True
except ImportError:
    win32security = None

logger = logging.getLogger("scanner")
scanner = None
dns_cache = None
remediation_executor = ThreadPoolExecutor(max_workers=8)
remediation_jobs = {}
remediation_jobs_lock = threading.Lock()

LOCAL_GROUP_NAME_ALIASES = {
    "S-1-5-32-544": ["Administrators", "Администраторы"],
    "S-1-5-32-555": ["Remote Desktop Users", "Пользователи удаленного рабочего стола", "Пользователи удалённого рабочего стола"],
    "S-1-5-32-562": ["Distributed COM Users", "Пользователи распределенного COM", "Пользователи распределённого COM"],
    "S-1-5-32-580": ["Remote Management Users", "Пользователи удаленного управления", "Пользователи удалённого управления"],
}

def configure(scanner_instance, dns_cache_instance, logger_instance=None):
    global scanner, dns_cache, logger
    scanner = scanner_instance
    dns_cache = dns_cache_instance
    if logger_instance is not None:
        logger = logger_instance

def _remediation_account_key(value):
    text = str(value or "").strip().lower()
    if "\\" in text:
        text = text.split("\\", 1)[1]
    return text


def _remediation_sid_text(value):
    if value is None:
        return ""
    try:
        if WIN32SECURITY_AVAILABLE:
            return str(win32security.ConvertSidToStringSid(value))
    except Exception:
        pass
    text = str(value).strip()
    return text if text.upper().startswith("S-") else ""


def _remediation_group_sid(group):
    text = str(group or "").strip()
    if text.upper().startswith("S-"):
        return text.upper()

    low = text.casefold()
    if low in {
        "administrators", "администраторы",
        "builtin\\administrators", "builtin\\администраторы",
    }:
        return "S-1-5-32-544"
    if low in {
        "remote desktop users", "пользователи удаленного рабочего стола",
        "пользователи удалённого рабочего стола",
    }:
        return "S-1-5-32-555"
    if low in {
        "distributed com users", "пользователи распределенного com",
        "пользователи распределённого com",
    }:
        return "S-1-5-32-562"
    if low in {
        "remote management users", "пользователи удаленного управления",
        "пользователи удалённого управления",
    }:
        return "S-1-5-32-580"
    return ""


def _resolve_local_group_name_rpc(machine, group):
    """Resolve a local group name without assuming the target OS language."""
    if not WIN32NET_AVAILABLE:
        raise RuntimeError("pywin32 win32net is not available")

    server = "\\\\" + str(machine).split(".")[0]
    requested = str(group or "").strip()
    candidates = []

    def add_candidate(value):
        value = str(value or "").strip()
        if value and value.casefold() not in {x.casefold() for x in candidates}:
            candidates.append(value)

    add_candidate(requested)

    sid_text = _remediation_group_sid(requested)
    if sid_text and WIN32SECURITY_AVAILABLE:
        try:
            sid = win32security.ConvertStringSidToSid(sid_text)
            domain, name, _sid_type = win32security.LookupAccountSid(
                str(machine).split(".")[0], sid
            )
            add_candidate(name)
        except Exception as exc:
            logger.debug("RPC group SID lookup failed for %s/%s: %s", machine, group, exc)

    # Enumerating the local groups is the final language-independent fallback.
    try:
        resume = 0
        while True:
            data, total, resume = win32net.NetLocalGroupEnum(server, 1, resume, 4096)
            for item in data:
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                if any(name.casefold() == candidate.casefold() for candidate in candidates):
                    return name
            if not resume:
                break
    except Exception as exc:
        logger.debug("RPC local-group enumeration failed for %s: %s", machine, exc)

    # For built-in groups, ask the remote machine to resolve the well-known SID.
    if sid_text and WIN32SECURITY_AVAILABLE:
        try:
            sid = win32security.ConvertStringSidToSid(sid_text)
            _domain, name, _sid_type = win32security.LookupAccountSid(
                str(machine).split(".")[0], sid
            )
            if name:
                return str(name)
        except Exception:
            pass

    # Last chance: try the names known for the supported built-in groups.
    aliases = LOCAL_GROUP_NAME_ALIASES.get(sid_text, [])
    for alias in aliases:
        add_candidate(alias)
        try:
            win32net.NetLocalGroupGetInfo(server, alias, 1)
            return alias
        except Exception:
            pass

    raise RuntimeError(
        "Local group not found on {0}: requested '{1}', SID '{2}'".format(
            machine, requested, sid_text or "unknown"
        )
    )


def _iter_local_group_members_rpc(server, group_name):
    resume = 0
    while True:
        data, total, resume = win32net.NetLocalGroupGetMembers(
            server, group_name, 2, resume, 4096
        )
        for item in data:
            yield item
        if not resume:
            break


def _member_sid_for_machine(machine, account):
    if not WIN32SECURITY_AVAILABLE:
        return ""
    requested = str(account or "").strip()
    if not requested or requested.upper().startswith("S-"):
        return requested.upper()
    candidates = [requested]
    if "\\" in requested:
        candidates.append(requested.replace("/", "\\"))
    try:
        for candidate in candidates:
            sid, _domain, _sid_type = win32security.LookupAccountName(
                str(machine).split(".")[0], candidate
            )
            sid_text = _remediation_sid_text(sid)
            if sid_text:
                return sid_text.upper()
    except Exception as exc:
        logger.debug("RPC member SID lookup failed for %s/%s: %s", machine, account, exc)
    return ""


def _rpc_member_matches(item, requested, requested_sid):
    name = str(item.get("domainandname") or "").strip()
    sid_text = _remediation_sid_text(item.get("sid"))
    if requested_sid and sid_text and sid_text.upper() == requested_sid.upper():
        return True
    if name.casefold() == requested.casefold():
        return True
    return _remediation_account_key(name) == _remediation_account_key(requested)


def _verify_local_group_member_rpc(machine, group, account, member_sid=""):
    if not WIN32NET_AVAILABLE:
        return None
    server = "\\\\" + str(machine).split(".")[0]
    requested = str(account or "").strip()
    requested_sid_input = str(member_sid or "").strip()
    if not requested_sid_input and requested.upper().startswith("S-"):
        requested_sid_input = requested
    try:
        group_name = _resolve_local_group_name_rpc(machine, group)
        requested_sid = requested_sid_input.upper() if requested_sid_input else _member_sid_for_machine(machine, requested)
        for item in _iter_local_group_members_rpc(server, group_name):
            if _rpc_member_matches(item, requested, requested_sid):
                return True
        return False
    except Exception as e:
        logger.debug(
            "RPC remediation verification failed for %s/%s/%s: %s",
            machine, group, account, e
        )
        return None


def _remove_local_group_member_rpc(machine, group, account, username="", password="", domain="", member_sid=""):
    """
    Remove by the member SID (NetAPI level 0) whenever possible.

    This is important for stale/dead AD SIDs: a SID stored in the local SAM
    does not need to resolve back to an AD object in order to be removed.
    """
    if not WIN32NET_AVAILABLE:
        return None

    server = "\\\\" + str(machine).split(".")[0]
    requested = str(account or "").strip()
    requested_sid_input = str(member_sid or "").strip()

    try:
        group_name = _resolve_local_group_name_rpc(machine, group)
        requested_sid = requested_sid_input.upper() if requested_sid_input else (requested.upper() if requested.upper().startswith("S-") else _member_sid_for_machine(machine, requested))

        # For a raw SID, do not enumerate/resolve the member first.  This is
        # required for orphaned AD SIDs that no longer resolve to an account.
        if requested_sid:
            target_sid = requested_sid
            try:
                sid_obj = win32security.ConvertStringSidToSid(target_sid) if WIN32SECURITY_AVAILABLE else None
                if sid_obj is None:
                    raise RuntimeError("win32security is required for direct SID removal")
                win32net.NetLocalGroupDelMembers(
                    server, group_name, 0, [{"sid": sid_obj}]
                )
            except Exception as delete_error:
                verified = _verify_local_group_member_rpc(machine, group_name, target_sid)
                if verified is False:
                    return {
                        "ok": True, "method": "RPC-NetAPI-SID",
                        "status": "AlreadyAbsent", "sid": target_sid,
                        "group_resolved": group_name,
                    }
                raise delete_error
            verified = _verify_local_group_member_rpc(machine, group_name, requested, target_sid)
            if verified is False:
                return {
                    "ok": True, "method": "RPC-NetAPI-SID",
                    "status": "Removed", "sid": target_sid,
                    "account": requested, "group_resolved": group_name,
                }
            if verified is True:
                return {
                    "ok": False, "method": "RPC-NetAPI-SID",
                    "status": "StillPresent", "sid": target_sid,
                    "account": requested, "group_resolved": group_name,
                    "error": "Member is still present after NetAPI removal",
                }
            return {
                "ok": True, "method": "RPC-NetAPI-SID",
                "status": "RemovedUnverified", "sid": target_sid,
                "account": requested, "group_resolved": group_name,
            }

        target_item = None
        for item in _iter_local_group_members_rpc(server, group_name):
            if _rpc_member_matches(item, requested, requested_sid):
                target_item = item
                break

        if target_item is None:
            return {
                "ok": True,
                "method": "RPC-NetAPI",
                "status": "AlreadyAbsent",
                "group_resolved": group_name,
            }

        target_sid = _remediation_sid_text(target_item.get("sid"))
        if target_sid and WIN32SECURITY_AVAILABLE:
            sid_obj = win32security.ConvertStringSidToSid(target_sid)
            # NetLocalGroupDelMembers level 0 removes by SID and therefore
            # works even when LookupAccountSid/AD resolution fails.
            win32net.NetLocalGroupDelMembers(
                server, group_name, 0, [{"sid": sid_obj}]
            )
        else:
            resolved_name = str(target_item.get("domainandname") or "").strip()
            if not resolved_name:
                raise RuntimeError(
                    "Target member has no SID and no resolvable account name"
                )
            win32net.NetLocalGroupDelMembers(
                server, group_name, 3, [{"domainandname": resolved_name}]
            )

        verified = _verify_local_group_member_rpc(machine, group_name, requested, target_sid)
        if verified is False:
            return {
                "ok": True,
                "method": "RPC-NetAPI-SID" if target_sid else "RPC-NetAPI-Name",
                "status": "Removed",
                "account": requested,
                "sid": target_sid,
                "group_resolved": group_name,
            }
        if verified is True:
            return {
                "ok": False,
                "method": "RPC-NetAPI-SID" if target_sid else "RPC-NetAPI-Name",
                "status": "StillPresent",
                "account": requested,
                "sid": target_sid,
                "group_resolved": group_name,
                "error": "Member is still present after NetAPI removal",
            }
        return {
            "ok": True,
            "method": "RPC-NetAPI-SID" if target_sid else "RPC-NetAPI-Name",
            "status": "RemovedUnverified",
            "account": requested,
            "sid": target_sid,
            "group_resolved": group_name,
        }
    except Exception as e:
        return {
            "ok": False,
            "method": "RPC-NetAPI",
            "status": "Failed",
            "error": str(e)[:1000],
        }


def _remove_local_group_member_wmi(machine, group, account, username="", password="", domain="", member_sid=""):
    """
    Credentialed WMI/DCOM fallback.

    The actual mutation is performed on the target with NetAPI level 0 via a
    short 64-bit PowerShell helper. The member is addressed by SID, so an
    orphaned/dead AD SID can be removed without resolving the AD account.
    """
    if not WMI_AVAILABLE:
        return None

    user = str(username or "").strip()
    if not user or not password:
        return None
    if domain and "\\" not in user and "@" not in user:
        user = str(domain).strip() + "\\" + user

    host = str(machine or "").strip()
    short_host = host.split(".")[0]
    requested = str(account or "").strip()
    requested_sid_input = str(member_sid or "").strip()
    group_sid = _remediation_group_sid(group)

    try:
        c = wmi_module.WMI(
            computer=short_host,
            user=user,
            password=password,
            namespace="root\\cimv2",
        )

        if group_sid:
            groups = c.Win32_Group(SID=group_sid)
        else:
            groups = c.Win32_Group(Name=group)
        if not groups:
            return {
                "ok": False, "method": "WMI", "status": "Failed",
                "error": "Local group '{}' was not found".format(group),
            }

        g = groups[0]
        group_name = str(getattr(g, "Name", "") or group)

        target_sid = requested_sid_input.upper() if requested_sid_input else (requested.upper() if requested.upper().startswith("S-") else _member_sid_for_machine(short_host, requested))

        def get_members():
            items = []
            try:
                assoc = g.associators()
            except Exception:
                assoc = []
            for item in assoc:
                name = str(getattr(item, "Name", "") or "").strip()
                dom = str(getattr(item, "Domain", "") or "").strip()
                sid = _remediation_sid_text(getattr(item, "SID", None))
                full = (dom + "\\" + name) if dom and name else name
                items.append((full, name, sid))
            return items

        if requested_sid_input or requested.upper().startswith("S-"):
            # An orphaned SID must be passed straight to the target; do not
            # require WMI/AD name resolution to discover it first.
            target = ("", "", target_sid)
        else:
            members = get_members()
            target = None
            for full, name, sid in members:
                if target_sid and sid and sid.upper() == target_sid.upper():
                    target = (full, name, sid)
                    break
                if (
                    full.casefold() == requested.casefold()
                    or name.casefold() == requested.rsplit("\\", 1)[-1].casefold()
                ):
                    target = (full, name, sid)
                    break

            if not target:
                return {
                    "ok": True, "method": "WMI", "status": "AlreadyAbsent",
                    "group_resolved": group_name,
                }

        target_sid = target[2] or target_sid
        if not target_sid:
            return {
                "ok": False, "method": "WMI", "status": "Failed",
                "group_resolved": group_name,
                "error": "Unable to obtain target member SID",
            }

        # Run on the target. Remove-LocalGroupMember accepts SID members, but
        # older hosts may not have Microsoft.PowerShell.LocalAccounts, so the
        # helper falls back to NetLocalGroupDelMembers level 0.
        ps = r'''
$ErrorActionPreference = "Stop"
$groupName = __GROUP__
$memberSidText = __SID__
$sid = New-Object System.Security.Principal.SecurityIdentifier($memberSidText)

try {
    if (Get-Command Remove-LocalGroupMember -ErrorAction SilentlyContinue) {
        Remove-LocalGroupMember -Name $groupName -Member $sid -Confirm:$false -ErrorAction Stop
        exit 0
    }

    if (-not ("LasNetApi" -as [type])) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class LasNetApi {
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupDelMembers(
        string servername,
        string localgroupname,
        int level,
        IntPtr buf,
        int totalentries);
}
"@
    }

    $bytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($bytes, 0)
    $sidPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
    $bufPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    try {
        [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $sidPtr, $bytes.Length)
        [Runtime.InteropServices.Marshal]::WriteIntPtr($bufPtr, $sidPtr)
        $rc = [LasNetApi]::NetLocalGroupDelMembers($null, $groupName, 0, $bufPtr, 1)
        if ([int]$rc -ne 0) {
            throw ("NetLocalGroupDelMembers failed with Win32 error {0}" -f [int]$rc)
        }
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($bufPtr)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($sidPtr)
    }
    exit 0
}
catch {
    exit 1
}
'''
        ps = ps.replace("__GROUP__", json.dumps(group_name)).replace("__SID__", json.dumps(target_sid))

        encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
        command = (
            "powershell.exe -NoLogo -NoProfile -NonInteractive "
            "-ExecutionPolicy Bypass -EncodedCommand " + encoded
        )
        result = c.Win32_Process.Create(CommandLine=command)
        pid = int(getattr(result, "ProcessId", 0) or 0)
        ret = int(getattr(result, "ReturnValue", 0) or 0)
        if ret != 0 or not pid:
            return {
                "ok": False, "method": "WMI", "status": "Failed",
                "group_resolved": group_name,
                "error": "Win32_Process.Create failed: return value {}".format(ret),
            }

        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                if not c.Win32_Process(ProcessId=pid):
                    break
            except Exception:
                break
            time.sleep(0.25)

        left = get_members()
        for full, name, sid in left:
            if sid and sid.upper() == target_sid.upper():
                return {
                    "ok": False, "method": "WMI-NetAPI-SID", "status": "StillPresent",
                    "group_resolved": group_name,
                    "sid": target_sid,
                    "error": "Member is still present after WMI/NetAPI removal",
                }

        return {
            "ok": True, "method": "WMI-NetAPI-SID", "status": "Removed",
            "account": requested,
            "sid": target_sid,
            "group_resolved": group_name,
        }
    except Exception as e:
        return {
            "ok": False, "method": "WMI", "status": "Failed",
            "error": str(e)[:1000],
        }


def _build_remediation_winrm_script(group, account, member_sid=""):
    group_json = json.dumps(str(group or ""), ensure_ascii=False)
    account_json = json.dumps(str(account or ""), ensure_ascii=False)
    member_sid_json = json.dumps(str(member_sid or ""), ensure_ascii=False)
    group_sid = _remediation_group_sid(group) or "S-1-5-32-544"

    # The target SID is the authoritative identity. This handles orphaned AD
    # SIDs that cannot be translated to DOMAIN\name.
    return (
        "$ErrorActionPreference='Stop';"
        "$requestedGroup=" + group_json + ";"
        "$requestedMember=" + account_json + ";"
        "$requestedMemberSid=" + member_sid_json + ";"
        "if($requestedMemberSid){$requestedMember=$requestedMemberSid};"
        "$groupName=$null;"
        "try{"
        "  $g=Get-WmiObject Win32_Group -Filter " + json.dumps("SID='" + group_sid + "'") + " -ErrorAction Stop | Select-Object -First 1;"
        "  if($g){$groupName=[string]$g.Name}"
        "}catch{};"
        "if(-not $groupName -and (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue)){"
        "  try{$lg=Get-LocalGroup | Where-Object {$_.Name -ieq $requestedGroup} | Select-Object -First 1;if($lg){$groupName=[string]$lg.Name}}catch{}"
        "};"
        "if(-not $groupName){throw ('Local group not found: '+$requestedGroup)};"
        "$requestedSid=$null;"
        "if($requestedMember -match '^S-[0-9-]+$'){$requestedSid=$requestedMember}"
        "else{"
        "  try{$requestedSid=([System.Security.Principal.NTAccount]$requestedMember).Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{}"
        "};"
        "$targetSid=$requestedSid;"
        "$targetName=$requestedMember;"
        "if(-not $targetSid){"
        "  try{"
        "    if(Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){"
        "      foreach($m in @(Get-LocalGroupMember -Name $groupName -ErrorAction Stop)){"
        "        $msid=if($m.SID){$m.SID.Value}else{''};"
        "        $mname=[string]$m.Name;"
        "        if(($mname -ieq $requestedMember) -or ($mname -split [char]92)[-1] -ieq (($requestedMember -split [char]92)[-1])){"
        "          $targetSid=$msid;if($mname){$targetName=$mname};break"
        "        }"
        "      }"
        "    }"
        "  }catch{}"
        "};"
        "if(-not $targetSid){throw ('Unable to resolve member SID: '+$requestedMember)};"

        # Do not require SID -> account translation or membership enumeration
        # before deletion. NetAPI level 0 is authoritative for live and orphaned SIDs.
                "if(-not ('LasNetApi' -as [type])){"
        "  Add-Type @'"
        "using System;"
        "using System.Runtime.InteropServices;"
        "public static class LasNetApi {"
        "  [DllImport(\"Netapi32.dll\", CharSet=CharSet.Unicode)]"
        "  public static extern int NetLocalGroupDelMembers(string servername,string localgroupname,int level,IntPtr buf,int totalentries);"
        "}"
        "'@"
        "};"
        "$sidObj=New-Object System.Security.Principal.SecurityIdentifier($targetSid);"
        "$bytes=New-Object byte[] $sidObj.BinaryLength;"
        "$sidObj.GetBinaryForm($bytes,0);"
        "$sidPtr=[Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length);"
        "$bufPtr=[Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size);"
        "try{"
        "  [Runtime.InteropServices.Marshal]::Copy($bytes,0,$sidPtr,$bytes.Length);"
        "  [Runtime.InteropServices.Marshal]::WriteIntPtr($bufPtr,$sidPtr);"
        "  $rc=[LasNetApi]::NetLocalGroupDelMembers($null,$groupName,0,$bufPtr,1);"
        "  if([int]$rc -ne 0){$verifyPresent=$false;try{if(Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){foreach($m in @(Get-LocalGroupMember -Name $groupName -ErrorAction Stop)){if($m.SID -and $m.SID.Value -ieq $targetSid){$verifyPresent=$true;break}}}}catch{};if(-not $verifyPresent){try{foreach($rel in @(Get-WmiObject Win32_GroupUser -ErrorAction Stop)){$gc=[string]$rel.GroupComponent;$pc=[string]$rel.PartComponent;if($gc -match [regex]::Escape($groupName) -and $pc -match [regex]::Escape($targetSid)){$verifyPresent=$true;break}}}catch{}};if(-not $verifyPresent){return ('LAS-RESULT:'+(@{Status='AlreadyAbsent';Group=$groupName;Account=$targetName;SID=$targetSid} | ConvertTo-Json -Compress))};throw ('NetLocalGroupDelMembers failed with Win32 error '+[int]$rc)}"
        "}finally{"
        "  [Runtime.InteropServices.Marshal]::FreeHGlobal($bufPtr);"
        "  [Runtime.InteropServices.Marshal]::FreeHGlobal($sidPtr)"
        "};"
        "Start-Sleep -Milliseconds 500;"
        "$still=$false;"
        "try{"
        "  if(Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue){"
        "    foreach($m in @(Get-LocalGroupMember -Name $groupName -ErrorAction Stop)){if($m.SID -and $m.SID.Value -ieq $targetSid){$still=$true;break}}"
        "  }"
        "}catch{};"
        "if(-not $still){try{foreach($rel in @(Get-WmiObject Win32_GroupUser -ErrorAction Stop)){$gc=[string]$rel.GroupComponent;$pc=[string]$rel.PartComponent;if($gc -match [regex]::Escape($groupName) -and $pc -match [regex]::Escape($targetSid)){$still=$true;break}}}catch{}};"
        "if($still){throw ('Member is still present after SID removal: '+$targetSid)};"
        "return ('LAS-RESULT:'+(@{Status='Removed';Group=$groupName;Account=$targetName;SID=$targetSid} | ConvertTo-Json -Compress))"
    )


def _run_remediation_job(job_id, machine, account, group, use_ssl, auth_user, auth_pass, auth_domain, member_sid=""):
    start = time.time()
    attempts = []

    def finish(result):
        result.update({
            "job_id": job_id,
            "machine": machine,
            "account": account,
            "group": group,
            "elapsed_ms": round((time.time() - start) * 1000),
        })
        with remediation_jobs_lock:
            remediation_jobs[job_id] = result

    def progress(message, method=""):
        with remediation_jobs_lock:
            current = remediation_jobs.get(job_id)
            if current is not None:
                current["state"] = "running"
                current["status"] = "Running"
                current["current"] = message
                if method:
                    current["method"] = method
                current["elapsed_ms"] = round((time.time() - start) * 1000)

    def run_winrm():
        username = auth_user
        if auth_user and auth_pass and auth_domain and ("\\" not in username and "@" not in username):
            username = auth_domain + "\\" + username

        if not auth_user or not auth_pass:
            raise RuntimeError("Remediation credentials are required")

        # Reuse the scanner's target/port discovery instead of assuming 5985.
        # The scan already knows whether the host is reachable through 5985 or 5986.
        try:
            resolved_ip = dns_cache.resolve(machine, domain_hint=str(auth_domain or "").strip())
        except Exception:
            resolved_ip = None

        candidates = scanner._host_candidates(machine, resolved_ip)
        if not candidates:
            candidates = [machine]

        transport_candidates = []
        seen = set()
        for host in candidates:
            try:
                ports = scanner._probe_ports_fast(host)
            except Exception:
                ports = {}
            available = []
            if ports.get("5985_winrm"):
                available.append(False)
            if ports.get("5986_winrm_ssl"):
                available.append(True)
            # If probing is inconclusive, retain the requested transport and
            # then try the other one. This mirrors the scanner's fallback model.
            if not available:
                available = [bool(use_ssl), not bool(use_ssl)]
            for ssl_mode in available:
                key = (str(host).lower(), bool(ssl_mode))
                if key not in seen:
                    seen.add(key)
                    transport_candidates.append((host, bool(ssl_mode)))

        if not transport_candidates:
            transport_candidates = [(machine, bool(use_ssl)), (machine, not bool(use_ssl))]

        errors = []
        for target_host, ssl_mode in transport_candidates:
            port = 5986 if ssl_mode else 5985
            progress("WinRM " + str(target_host) + ":" + str(port), "WinRM")
            scheme = "https" if ssl_mode else "http"
            target = scheme + "://" + str(target_host) + ":" + str(port)
            try:
                session = winrm.Session(
                    target=target,
                    auth=(username, auth_pass),
                    transport="ntlm",
                    server_cert_validation="ignore",
                    read_timeout_sec=15,
                    operation_timeout_sec=10,
                )
                raw = scanner._run_ps(
                    session,
                    _build_remediation_winrm_script(group, account, member_sid),
                    machine,
                )
                text = str(raw or "")
                status = "Removed"
                result_account = account
                result_group = group
                for line in text.splitlines():
                    if line.startswith("LAS-RESULT:"):
                        try:
                            obj = json.loads(line[len("LAS-RESULT:"):])
                            status = str(obj.get("Status") or status)
                            result_account = str(obj.get("Account") or result_account)
                            result_group = str(obj.get("Group") or result_group)
                        except Exception:
                            pass

                return {
                    "ok": status not in ("Failed", "StillPresent"),
                    "method": "WinRM-NetAPI-SID" + ("-SSL" if ssl_mode else ""),
                    "status": status,
                    "account": result_account,
                    "group": result_group,
                    "target": target,
                }
            except Exception as e:
                errors.append("{}: {}".format(target, str(e)[:300]))

        raise RuntimeError("WinRM remediation failed: " + " | ".join(errors)[:1200])

    try:
        result = run_winrm()
        if result.get("ok"):
            finish(result)
            return
        attempts.append({"method": "WinRM", "status": result.get("status"), "error": "verification failed"})
    except Exception as e:
        attempts.append({"method": "WinRM", "status": "Failed", "error": str(e)[:1000]})

    # WMI/DCOM is the credential-aware fallback. Unlike the old ADSI fallback,
    # it does not depend on the web server's process credentials and does not
    # enumerate the WinNT provider tree.
    try:
        progress("WMI/DCOM", "WMI")
        result = _remove_local_group_member_wmi(
            machine, group, account, auth_user, auth_pass, auth_domain, member_sid
        )
        if result is not None:
            attempts.append({
                "method": result.get("method", "WMI"),
                "status": result.get("status"),
                "error": result.get("error", ""),
            })
            if result.get("ok"):
                result.update({
                    "attempts": attempts,
                })
                finish(result)
                return
    except Exception as e:
        attempts.append({"method": "WMI", "status": "Failed", "error": str(e)[:1000]})

    # Last fallback: NetAPI. This remains useful when the LAS service itself
    # already runs under an account allowed to administer the target.
    try:
        progress("RPC/NetAPI", "RPC")
        rpc_result = _remove_local_group_member_rpc(
            machine, group, account, auth_user, auth_pass, auth_domain, member_sid
        )
        if rpc_result is not None:
            attempts.append({
                "method": rpc_result.get("method", "RPC"),
                "status": rpc_result.get("status"),
                "error": rpc_result.get("error", ""),
            })
            if rpc_result.get("ok"):
                rpc_result.update({"attempts": attempts})
                finish(rpc_result)
                return
    except Exception as e:
        attempts.append({"method": "RPC", "status": "Failed", "error": str(e)[:1000]})

    errors = []
    for item in attempts:
        if item.get("error"):
            errors.append(item["method"] + ": " + item["error"])
    finish({
        "ok": False,
        "status": "Failed",
        "error": " | ".join(errors)[:2000] or "All remediation methods failed",
        "attempts": attempts,
    })



def start_remediation_job(machine, account, group, use_ssl, auth_user, auth_pass, auth_domain, member_sid=""):
    job_id = "{}-{:08x}".format(
        datetime.now().strftime("%Y%m%d%H%M%S%f"),
        abs(hash((machine, account, time.time_ns()))) & 0xffffffff,
    )
    with remediation_jobs_lock:
        remediation_jobs[job_id] = {
            "job_id": job_id, "status": "Running", "state": "running",
            "machine": machine, "account": account, "group": group, "sid": member_sid,
            "created_at": time.time(),
        }
    remediation_executor.submit(
        _run_remediation_job, job_id, machine, account, group, use_ssl,
        auth_user, auth_pass, auth_domain, member_sid,
    )
    return job_id


def get_remediation_job(job_id):
    with remediation_jobs_lock:
        result = remediation_jobs.get(job_id)
        return dict(result) if result is not None else None
