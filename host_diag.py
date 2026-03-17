import argparse
import socket
from typing import List, Optional, Tuple


def build_user_candidates(username: str, domain: Optional[str] = None) -> List[str]:
    """Build unique credential variants for remote auth attempts."""
    if "\\" in username or "@" in username:
        return [username]

    candidates = []
    if domain:
        candidates.extend([f"{domain}\\{username}", f"{username}@{domain}"])
    candidates.append(username)

    unique: List[str] = []
    seen = set()
    for candidate in candidates:
        key = candidate.lower()
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def check_port(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "open"
    except OSError as exc:
        return False, str(exc)


def try_wmi(host: str, username: str, password: str, domain: Optional[str] = None) -> Tuple[bool, str]:
    try:
        import wmi  # type: ignore
    except Exception as exc:
        return False, f"wmi module unavailable: {exc}"

    errors = []
    for user_candidate in build_user_candidates(username, domain):
        try:
            connection = wmi.WMI(
                computer=host,
                user=user_candidate,
                password=password,
                namespace=r"root\cimv2",
                find_classes=False,
            )
            groups = connection.Win32_Group(SID="S-1-5-32-544")
            if not groups:
                return False, f"WMI connected as {user_candidate}, but Administrators group by SID not found"

            members = []
            for assoc in groups[0].associators():
                member_name = getattr(assoc, "Caption", None) or getattr(assoc, "Name", None) or getattr(assoc, "SID", None)
                if member_name:
                    members.append(str(member_name))
            return True, f"WMI OK as {user_candidate}, members={len(members)}: {members[:10]}"
        except Exception as exc:
            errors.append(f"{user_candidate}: {exc}")

    return False, " | ".join(errors)


def _netuse_add(remote_ipc: str, username: str, password: str):
    import win32net  # type: ignore
    import win32netcon  # type: ignore

    ui2 = {
        "remote": remote_ipc,
        "username": username,
        "password": password,
        "asg_type": win32netcon.USE_WILDCARD,
    }
    return win32net.NetUseAdd(None, 2, ui2)


def try_rpc_samr(host: str, username: str, password: str, domain: Optional[str] = None, group: str = "Administrators") -> Tuple[bool, str]:
    try:
        import win32net  # type: ignore
    except Exception as exc:
        return False, f"win32net unavailable: {exc}"

    server = "\\\\" + host
    ipc = server + "\\IPC$"
    errors = []

    for user_candidate in build_user_candidates(username, domain):
        try:
            try:
                _netuse_add(ipc, user_candidate, password)
            except Exception:
                pass

            resume = 0
            members = []
            while True:
                data, total, resume = win32net.NetLocalGroupGetMembers(server, group, 2, resume, 4096)
                for item in data:
                    domain_and_name = str(item.get("domainandname") or "").strip()
                    if domain_and_name:
                        members.append(domain_and_name)
                if not resume:
                    break
            return True, f"RPC-SAMR OK as {user_candidate}, members={len(members)}: {members[:10]}"
        except Exception as exc:
            errors.append(f"{user_candidate}: {exc}")
        finally:
            try:
                win32net.NetUseDel(None, ipc, 0)
            except Exception:
                pass

    return False, " | ".join(errors)


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick host diagnostics for local Administrators membership")
    parser.add_argument("--host", required=True, help="target host, e.g. AB-AU-0131 or AB-AU-0131.rosseti-sib.ru")
    parser.add_argument("--user", required=True, help="username (user, DOMAIN\\user, or user@domain)")
    parser.add_argument("--password", required=True, help="password")
    parser.add_argument("--domain", default="", help="domain/netbios hint for user format")
    parser.add_argument("--group", default="Administrators", help="local group name for RPC test")
    args = parser.parse_args()

    host_short = args.host.split(".")[0]

    print(f"== Host: {args.host} (short={host_short})")

    for port in (135, 139, 445, 5985, 5986):
        ok, msg = check_port(args.host, port)
        print(f"PORT {port}: {'OPEN' if ok else 'CLOSED'} ({msg})")

    ok_wmi, msg_wmi = try_wmi(args.host, args.user, args.password, args.domain or None)
    print(f"WMI: {'OK' if ok_wmi else 'FAIL'} | {msg_wmi}")

    ok_rpc, msg_rpc = try_rpc_samr(host_short, args.user, args.password, args.domain or None, args.group)
    print(f"RPC-SAMR: {'OK' if ok_rpc else 'FAIL'} | {msg_rpc}")


if __name__ == "__main__":
    main()
