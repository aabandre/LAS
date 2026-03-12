import argparse
import socket


def check_port(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True, "open"
    except Exception as e:
        return False, str(e)
    finally:
        try:
            s.close()
        except Exception:
            pass


def try_wmi(host, username, password, domain=None):
    try:
        import wmi  # type: ignore
    except Exception as e:
        return False, f"wmi module unavailable: {e}"

    users = []
    if "\\" in username or "@" in username:
        users.append(username)
    else:
        if domain:
            users.append(f"{domain}\\{username}")
            users.append(f"{username}@{domain}")
        users.append(username)

    errors = []
    for u in users:
        try:
            c = wmi.WMI(computer=host, user=u, password=password, namespace=r"root\cimv2", find_classes=False)
            groups = c.Win32_Group(SID="S-1-5-32-544")
            if not groups:
                return False, f"WMI connected as {u}, but Administrators group by SID not found"
            g = groups[0]
            members = []
            for a in g.associators():
                nm = getattr(a, "Caption", None) or getattr(a, "Name", None) or getattr(a, "SID", None)
                if nm:
                    members.append(str(nm))
            return True, f"WMI OK as {u}, members={len(members)}: {members[:10]}"
        except Exception as e:
            errors.append(f"{u}: {e}")
    return False, " | ".join(errors)


def _netuse_add(remote_ipc, username, password):
    import win32net  # type: ignore
    import win32netcon  # type: ignore
    ui2 = {
        "remote": remote_ipc,
        "username": username,
        "password": password,
        "asg_type": win32netcon.USE_WILDCARD,
    }
    return win32net.NetUseAdd(None, 2, ui2)


def try_rpc_samr(host, username, password, domain=None, group="Administrators"):
    try:
        import win32net  # type: ignore
    except Exception as e:
        return False, f"win32net unavailable: {e}"

    users = []
    if "\\" in username or "@" in username:
        users.append(username)
    else:
        if domain:
            users.append(f"{domain}\\{username}")
            users.append(f"{username}@{domain}")
        users.append(username)

    server = "\\\\" + host
    ipc = server + "\\IPC$"
    errors = []

    for u in users:
        try:
            try:
                _netuse_add(ipc, u, password)
            except Exception:
                pass

            resume = 0
            members = []
            while True:
                data, total, resume = win32net.NetLocalGroupGetMembers(server, group, 2, resume, 4096)
                for item in data:
                    dn = str(item.get("domainandname") or "").strip()
                    if dn:
                        members.append(dn)
                if not resume:
                    break
            return True, f"RPC-SAMR OK as {u}, members={len(members)}: {members[:10]}"
        except Exception as e:
            errors.append(f"{u}: {e}")
        finally:
            try:
                win32net.NetUseDel(None, ipc, 0)
            except Exception:
                pass

    return False, " | ".join(errors)


def main():
    ap = argparse.ArgumentParser(description="Quick host diagnostics for local Administrators membership")
    ap.add_argument("--host", required=True, help="target host, e.g. AB-AU-0131 or AB-AU-0131.rosseti-sib.ru")
    ap.add_argument("--user", required=True, help="username (user, DOMAIN\\user, or user@domain)")
    ap.add_argument("--password", required=True, help="password")
    ap.add_argument("--domain", default="", help="domain/netbios hint for user format")
    ap.add_argument("--group", default="Administrators", help="local group name for RPC test")
    args = ap.parse_args()

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
