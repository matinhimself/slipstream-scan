#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ipaddress
import os
import random
import socket
import ssl
import shlex
import subprocess
import sys
import threading
import time
from collections import deque
from queue import Queue, Empty
from typing import Iterable, List, Optional, Tuple

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import (
    Progress, BarColumn, TimeElapsedColumn, TimeRemainingColumn,
    SpinnerColumn, TaskProgressColumn, TextColumn
)

# ==========================================================
# Slipstreamplus-CLI
# DNS Tunnel Scanner and Tester
# ==========================================================


# ========================= Parsing helpers =========================

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except Exception:
        return False

def _strip_port(s: str) -> str:
    s = (s or "").strip()
    if ":" in s:
        s = s.split(":", 1)[0].strip()
    return s

def _parse_token(tok: str) -> Tuple[Optional[str], Optional[str]]:
    tok = (tok or "").strip()
    if not tok:
        return None, None
    if "/" in tok:
        return "cidr", tok
    ip = _strip_port(tok)
    if _is_ip(ip):
        return "ip", ip
    return None, None

def _iter_clean_tokens(lines: Iterable[str]) -> Iterable[str]:
    for line in lines:
        line = (line or "").strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith("//"):
            continue
        line = line.split("#", 1)[0].split("//", 1)[0].strip()
        for t in line.replace(",", " ").replace(";", " ").split():
            t = t.strip()
            if t:
                yield t

def _file_has_plain_ip(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for t in _iter_clean_tokens(f):
                k, v = _parse_token(t)
                if k == "ip" and v:
                    return True
    except Exception:
        pass
    return False


# ========================= CIDR Random like GUI =========================

def _cidr_sample_ips(cidr: str, k: int) -> List[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []
    if net.version != 4:
        return []
    total = int(net.num_addresses)
    if total <= 0:
        return []
    k = min(max(0, int(k)), total)
    if k <= 0:
        return []
    picks = random.sample(range(0, total), k)
    return [str(net.network_address + int(off)) for off in picks]


# ========================= Count total (GUI-like) =========================

def _count_targets_in_lines(lines: Iterable[str], use_random: bool, random_k: int) -> int:
    total = 0
    for t in _iter_clean_tokens(lines):
        k, v = _parse_token(t)
        if k == "ip" and v:
            total += 1
        elif k == "cidr" and v:
            try:
                net = ipaddress.ip_network(v, strict=False)
                if net.version != 4:
                    continue
                n = int(net.num_addresses)
                total += min(random_k, n) if (use_random and random_k > 0) else n
            except Exception:
                continue
    return total

def _count_targets_file(path: str, use_random: bool, random_k: int) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return _count_targets_in_lines(f, use_random, random_k)
    except Exception:
        return 0


# ========================= Target generator (streaming + GUI behavior) =========================

def _iter_targets_file(path: str, stop_evt: threading.Event, use_random: bool, random_k: int) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for t in _iter_clean_tokens(f):
            if stop_evt.is_set():
                return
            k, v = _parse_token(t)
            if k == "ip" and v:
                yield v
            elif k == "cidr" and v:
                if use_random and random_k > 0:
                    for ip in _cidr_sample_ips(v, random_k):
                        if stop_evt.is_set():
                            return
                        yield ip
                else:
                    # GUI behavior: expand ALL (⚠ huge)
                    try:
                        net = ipaddress.ip_network(v, strict=False)
                    except Exception:
                        continue
                    if net.version != 4:
                        continue
                    n = int(net.num_addresses)
                    for off in range(0, n):
                        if stop_evt.is_set():
                            return
                        yield str(net.network_address + int(off))

def _iter_targets_tokens(tokens: List[str], stop_evt: threading.Event, use_random: bool, random_k: int) -> Iterable[str]:
    for raw in tokens:
        if stop_evt.is_set():
            return
        k, v = _parse_token(raw)
        if k == "ip" and v:
            yield v
        elif k == "cidr" and v:
            if use_random and random_k > 0:
                for ip in _cidr_sample_ips(v, random_k):
                    if stop_evt.is_set():
                        return
                    yield ip
            else:
                try:
                    net = ipaddress.ip_network(v, strict=False)
                except Exception:
                    continue
                if net.version != 4:
                    continue
                n = int(net.num_addresses)
                for off in range(0, n):
                    if stop_evt.is_set():
                        return
                    yield str(net.network_address + int(off))


# ========================= Fast DNS tunnel probe =========================

def _encode_dns_query(qname: str) -> bytes:
    tid = random.randint(0, 0xFFFF)
    hdr = tid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    body = b""
    for p in qname.strip(".").split("."):
        body += bytes([len(p)]) + p.encode("ascii", "ignore")
    body += b"\x00\x00\x01\x00\x01"
    return hdr + body

def _dns_rcode(resp: bytes) -> Optional[int]:
    if len(resp) < 4:
        return None
    return resp[3] & 0x0F

def fast_dns_tunnel_check(ip: str, domain: str, timeout_ms: int) -> Tuple[bool, str, int]:
    qname = f"{random.randint(100000, 999999)}.{domain.strip('.')}"
    payload = _encode_dns_query(qname)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(max(timeout_ms, 50) / 1000.0)
    start = time.monotonic()
    try:
        s.sendto(payload, (ip, 53))
        resp, _ = s.recvfrom(4096)
        ms = int((time.monotonic() - start) * 1000)
        rcode = _dns_rcode(resp)
        if rcode is None:
            return False, "BadResp", ms

        # GUI: NOERROR + NXDOMAIN = alive
        if rcode == 0:
            return True, "OK (Resolved)", ms
        if rcode == 3:
            return True, "Tunnel Alive (NX)", ms
        if rcode == 2:
            return False, "ServFail", ms
        if rcode == 5:
            return False, "Refused", ms
        return False, f"RCODE {rcode}", ms

    except socket.timeout:
        return False, "TIMEOUT", -1
    except Exception:
        return False, "ERROR", -1
    finally:
        try:
            s.close()
        except Exception:
            pass


# ========================= RealTest helpers =========================

def _free_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    p = int(s.getsockname()[1])
    s.close()
    return p

def _start_slipstream(exe: str, resolver_ip: str, domain: str, port: int) -> Tuple[subprocess.Popen, threading.Event]:
    ready = threading.Event()
    cmd = [exe, "--resolver", f"{resolver_ip}:53", "--domain", domain, "--tcp-listen-port", str(port)]
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=creationflags,
    )

    def _reader():
        try:
            if not proc.stdout:
                return
            for line in proc.stdout:
                line_lower = line.lower()
                if "ready" in line_lower or "listening" in line_lower:
                    ready.set()
        except Exception:
            pass

    threading.Thread(target=_reader, daemon=True).start()
    return proc, ready

def _stop_proc(proc: Optional[subprocess.Popen]) -> None:
    if not proc:
        return
    try:
        if proc.poll() is not None:
            return
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

def _socks5_probe(proxy_port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", int(proxy_port)))
        s.sendall(b"\x05\x01\x00")
        r = s.recv(2)
        return len(r) == 2 and r[0] == 0x05 and r[1] == 0x00
    finally:
        try:
            s.close()
        except Exception:
            pass

def _wait_ready_or_socks(ev: threading.Event, port: int, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if ev.is_set():
            return True
        try:
            if _socks5_probe(port, 0.8):
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False

def _socks_auth_req(user: str, pwd: str) -> bytes:
    """
    Build the SOCKS5 username/password authentication request.

    According to RFC 1929:
        +----+------+--------+
        |VER | ULEN | USERID |
        +----+------+--------+
    """
    user_b = user.encode("utf-8")
    pwd_b  = pwd.encode("utf-8")

    return (
        b"\x01"                                 # VER  = 1 (username/password)
        + bytes([len(user_b)])                  # ULEN
        + user_b                                # USERID
        + bytes([len(pwd_b)])                   # PLEN
        + pwd_b                                 # PASSWD
    )

def _real_ping_via_socks(port: int, timeout: float, host: str, dst_port: int,
                         auth: Tuple[str, str] = ("user", "pass")) -> Tuple[int, str]:
    """
    Connect to a SOCKS5 proxy on 127.0.0.1:port, optionally authenticate
    with username/password, then establish a TCP connection to *host:*dst_port.
    Finally, perform a tiny HTTPS GET request and return (status_code, body).
    """
    user, pwd = auth
    start = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        # 1️⃣ Connect to the proxy itself
        s.connect(("127.0.0.1", int(port)))

        # 2️⃣ Send the “greeting” – list of supported methods
        #     If we want auth, we must advertise that method.
        methods = b"\x00"  # NO AUTHENTICATION
        if user or pwd:
            methods += b"\x02"  # USERNAME/PASSWORD

        s.sendall(b"\x05" + bytes([len(methods)]) + methods)
        r = s.recv(2)

        if len(r) != 2:
            return -1, "SOCKS: No reply from proxy"

        ver, method = r
        if ver != 0x05:
            return -1, f"SOCKS: Unsupported version {ver}"

        # 3️⃣ If we advertised USERNAME/PASSWORD, do the auth handshake
        if method == 0x02:          # proxy requires authentication
            s.sendall(_socks_auth_req(user, pwd))
            auth_resp = s.recv(2)
            if len(auth_resp) != 2 or auth_resp[1] != 0x00:
                return -1, "SOCKS: Authentication failed"
        elif method == 0xFF:
            return -1, "SOCKS: No acceptable auth methods"

        # 4️⃣ Build CONNECT request to the real destination
        hb = host.encode("utf-8")
        req = (
            b"\x05"          # SOCKS version
            + b"\x01"        # CONNECT command
            + b"\x00"        # Reserved
            + b"\x03"        # ATYP = DOMAINNAME
            + bytes([len(hb)])  # Length of domain name
            + hb
            + dst_port.to_bytes(2, "big")  # Destination port
        )
        s.sendall(req)

        rep = s.recv(10)   # we only need the first 2 bytes
        if len(rep) < 2 or rep[1] != 0x00:
            return -1, "SOCKS: CONNECT failed"

        # 5️⃣ Upgrade the socket to TLS (HTTPS)
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(s, server_hostname=host)

        # 6️⃣ Send a minimal HTTP GET request
        http_req = (
            f"GET /generate_204 HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        tls_sock.sendall(http_req)

        # 7️⃣ Read the response (just a chunk – not needed for the test)
        resp = tls_sock.recv(1024)
        tls_sock.close()

        # 8️⃣ Return something useful – here we just give the HTTP status code
        ms = int((time.monotonic() - start) * 1000)
        return ms, f"{ms} ms"
    except socket.timeout:
        return -1, "TIMEOUT"
    except Exception:
        return -1, "ERROR"
    finally:
        try:
            s.close()
        except Exception:
            pass

def realtest_one(ip: str, domain: str, exe: str, ready_ms: int, timeout_s: float,
                 auth: Tuple[str, str] = ("user", "pass")) -> Tuple[str, str]:
    port = _free_port()
    proc = None
    try:
        proc, ev = _start_slipstream(exe, ip, domain, port)
        if not _wait_ready_or_socks(ev, port, max(0.2, ready_ms / 1000.0)):
            return "READY TIMEOUT", "-"
        ms, st = _real_ping_via_socks(port, timeout_s, "www.google.com", 443, auth=auth)
        return st, ("-" if ms < 0 else str(ms))
    except FileNotFoundError:
        return "SLIPSTREAM NOT FOUND", "-"
    finally:
        _stop_proc(proc)


# ========================= Output Writers =========================

def _open_text_out(path: str):
    if not path:
        return None
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return open(path, "w", encoding="utf-8", newline="\n")

def _fmt_ipms(ip: str, ms: str) -> str:
    # ms may be '-' or numeric string
    return f"{ip} {ms}".strip()


def _merge_and_save_results(result_dir: str, filename: str, new_ips: List[str]) -> str:
    """Merge new IPs with existing results and save to directory.

    Returns the full path to the result file.
    """
    if not result_dir:
        return ""

    # Create directory if it doesn't exist
    os.makedirs(result_dir, exist_ok=True)

    result_path = os.path.join(result_dir, filename)

    # Load existing IPs
    existing_ips = set()
    if os.path.exists(result_path):
        try:
            with open(result_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith("#"):
                        existing_ips.add(ip)
        except Exception:
            pass

    # Merge with new IPs (deduplicate)
    all_ips = existing_ips | set(new_ips)

    # Write merged results
    with open(result_path, "w", encoding="utf-8", newline="\n") as f:
        for ip in sorted(all_ips):
            f.write(ip + "\n")

    return result_path



# ========================= Rich Dashboard =========================
# - Table shows ONLY Scan-OK IPs
# - RealPing "Now" ticker line (moving)
# - RealPing OK rows in GREEN

class RichDashboard:
    def __init__(self, total_scan: int, table_keep: int = 1500):
        self.console = Console(stderr=True)
        self.total_scan = max(1, int(total_scan))

        self.scan_done = 0
        self.scan_ok = 0
        self.scan_fail = 0

        self.rt_done = 0
        self.rt_ok = 0
        self.rt_fail = 0

        self.rt_enqueued = 0  # for live mode display

        self.rows_ok = {}      # ip -> dict(scan_ms, scan_st, rt_ms, rt_st)
        self.order_ok = deque()
        self.table_keep = int(table_keep)

        self.current_rt_ip: str = ""
        self._marquee_tick = 0

        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Slipstreamplus-CLI[/bold cyan]"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            transient=False,
        )
        self.task = self.progress.add_task("scan", total=self.total_scan)

    def _touch_ok(self, ip: str):
        if ip in self.rows_ok:
            return
        self.rows_ok[ip] = {"scan_ms": "-", "scan_st": "-", "rt_ms": "-", "rt_st": "-"}
        self.order_ok.append(ip)
        while len(self.order_ok) > self.table_keep:
            old = self.order_ok.popleft()
            self.rows_ok.pop(old, None)

    def update_scan(self, ip: str, scan_ms: str, scan_status: str, ok: bool):
        self.scan_done += 1
        if ok:
            self.scan_ok += 1
            self._touch_ok(ip)
            self.rows_ok[ip]["scan_ms"] = scan_ms
            self.rows_ok[ip]["scan_st"] = scan_status
        else:
            self.scan_fail += 1
        self.progress.update(self.task, completed=self.scan_done)

    def set_current_realtest(self, ip: str):
        self.current_rt_ip = ip or ""

    def inc_rt_enq(self):
        self.rt_enqueued += 1

    def update_realtest(self, ip: str, rt_ms: str, rt_status: str, ok: bool):
        self._touch_ok(ip)
        self.rows_ok[ip]["rt_ms"] = rt_ms
        self.rows_ok[ip]["rt_st"] = rt_status

        self.rt_done += 1
        if ok:
            self.rt_ok += 1
        else:
            self.rt_fail += 1

    def _marquee_line(self, width: int = 78) -> Text:
        base = "RealPing Now: "
        ip = self.current_rt_ip.strip()
        if not ip:
            return Text("RealPing Now: (idle)", style="dim")

        msg = f"{base}{ip}   "
        s = msg * 6
        self._marquee_tick = (self._marquee_tick + 1) % max(1, len(msg))
        start = self._marquee_tick
        view = s[start:start + width]
        return Text(view, style="bold yellow")

    def render(self, subtitle: str = "") -> Panel:
        header = Text()
        header.append("Slipstreamplus-CLI\n", style="bold cyan")
        header.append("Slipstream Scanner", style="bold green")
        if subtitle:
            header.append(f"\n{subtitle}", style="dim")

        stats = Text()
        stats.append("Scan: ", style="bold")
        stats.append(f"{self.scan_done}/{self.total_scan}  ", style="bold")
        stats.append(f"OK={self.scan_ok} ", style="green")
        stats.append(f"FAIL={self.scan_fail}\n", style="red")

        stats.append("RealPing: ", style="bold")
        if self.rt_enqueued > 0:
            stats.append(f"DONE={self.rt_done}/{self.rt_enqueued}  ", style="bold")
        else:
            stats.append(f"DONE={self.rt_done}  ", style="bold")
        stats.append(f"OK={self.rt_ok} ", style="green")
        stats.append(f"FAIL={self.rt_fail}", style="red")

        table = Table(show_header=True, header_style="bold magenta", expand=True)
        table.add_column("IP", style="bold", no_wrap=True)
        table.add_column("Scan ms", justify="right")
        table.add_column("Scan Status")
        table.add_column("RealPing ms", justify="right")
        table.add_column("RealPing Status")

        ips = list(self.order_ok)[-70:]
        for ip in ips:
            d = self.rows_ok.get(ip, {})
            scan_ms = str(d.get("scan_ms", "-"))
            scan_st = str(d.get("scan_st", "-"))
            rt_ms = str(d.get("rt_ms", "-"))
            rt_st = str(d.get("rt_st", "-"))

            is_rt_ok = (" ms" in rt_st)
            ip_cell = Text(ip, style=("bold green" if is_rt_ok else "bold"))
            rt_ms_cell = Text(rt_ms, style=("green" if is_rt_ok else ""))
            rt_st_cell = Text(rt_st, style=("green" if is_rt_ok else ("red" if rt_st not in ("-", "") else "")))

            table.add_row(ip_cell, scan_ms, scan_st, rt_ms_cell, rt_st_cell)

        grid = Table.grid(expand=True)
        grid.add_row(header)
        grid.add_row(stats)
        grid.add_row(self._marquee_line())
        grid.add_row(self.progress)
        grid.add_row(table)

        return Panel(grid, border_style="cyan", padding=(1, 2))


# ========================= Commands =========================

def _run_scan_remote(args: argparse.Namespace) -> int:
    """Handle --on: upload scanner to remote servers, run there, merge results."""
    import concurrent.futures
    import tempfile
    from ssh_client import SSHClient, parse_on

    console = Console(stderr=True)
    servers = args.on
    domain = args.domain.strip()
    auth = tuple(args.auth.split(":", 1)) if getattr(args, "auth", None) else ("user", "pass")

    # Read targets locally
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            all_targets = [l.strip() for l in f if l.strip()]
    else:
        all_targets = list(args.targets or [])

    if not all_targets:
        print("ERROR: no targets", file=sys.stderr)
        return 2

    # Split targets round-robin across servers
    chunks = [[] for _ in servers]
    for i, t in enumerate(all_targets):
        chunks[i % len(servers)].append(t)

    scan_ok_out = getattr(args, "scan_ok_out", "") or ""
    all_results = []
    results_lock = threading.Lock()

    def run_on_server(spec, chunk):
        client = SSHClient.from_spec(spec)
        console.print(f"[cyan]Connecting to {spec} ({len(chunk)} targets)...[/cyan]")
        try:
            # Upload scanner
            scanner_path = os.path.abspath(__file__)
            client.run("mkdir -p /tmp/dnstt_work")
            client.upload(scanner_path, "/tmp/dnstt_work/slipscan_cli_2n.py")

            # Write chunk to temp file and upload
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(chunk) + "\n")
                tf_path = tf.name
            try:
                client.upload(tf_path, "/tmp/dnstt_work/targets.txt")
            finally:
                os.unlink(tf_path)

            # Build remote command (with sudo for raw socket access)
            remote_cmd = (
                f"sudo python3 /tmp/dnstt_work/slipscan_cli_2n.py scan"
                f" --domain {shlex.quote(domain)}"
                f" --file /tmp/dnstt_work/targets.txt"
                f" --threads {args.threads}"
                f" --timeout-ms {args.timeout_ms}"
                f" --result-dir /tmp/dnstt_work"
                f" --stdout"
                f" --auth {shlex.quote(auth[0] + ':' + auth[1])}"
            )
            if getattr(args, "auto_realtest", "off") != "off":
                remote_cmd += f" --auto-realtest {args.auto_realtest}"

            lines = []
            def on_line(line):
                console.print(f"  [{spec}] {line}")
                lines.append(line)

            rc = client.run_streaming(remote_cmd, on_line)
            if rc != 0:
                console.print(f"[red]Remote scan on {spec} exited {rc}[/red]")

            # Download results
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                local_result = tf.name
            try:
                client.download("/tmp/dnstt_work/scan_ok.txt", local_result)
                with open(local_result, "r") as f:
                    ips = [l.strip() for l in f if l.strip()]
                with results_lock:
                    all_results.extend(ips)
            except Exception:
                console.print(f"[yellow]No scan_ok.txt from {spec}[/yellow]")
            finally:
                try:
                    os.unlink(local_result)
                except OSError:
                    pass

        finally:
            client.cleanup_remote("/tmp/dnstt_work")

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(servers)) as pool:
        futs = []
        for spec, chunk in zip(servers, chunks):
            if chunk:
                futs.append(pool.submit(run_on_server, spec, chunk))
        for fut in concurrent.futures.as_completed(futs):
            try:
                fut.result()
            except Exception as exc:
                console.print(f"[red]Server error: {exc}[/red]")

    # Merge and write results
    result_dir = getattr(args, "result_dir", None)
    if result_dir and all_results:
        result_path = _merge_and_save_results(result_dir, "scan_ok.txt", all_results)
        console.print(f"[dim]Results merged and saved to: {result_path}[/dim]")

    console.print(f"\n[bold green]Scan complete: {len(all_results)} OK IPs from {len(servers)} server(s)[/bold green]")
    return 0


def _run_realtest_remote(args: argparse.Namespace, split_targets: bool = True) -> int:
    """Handle --on/--test-from for realtest: upload scanner + IPs, run remotely.

    Args:
        args: Command line arguments
        split_targets: If True, split IPs round-robin across servers.
                      If False, each server tests the full IP list.
    """
    import concurrent.futures
    import tempfile
    from ssh_client import SSHClient, parse_on

    console = Console(stderr=True)
    servers = args.on if split_targets else args.test_from
    domain = args.domain.strip()
    auth = tuple(args.auth.split(":", 1)) if getattr(args, "auth", None) else ("user", "pass")

    # Read IPs from file or stdin
    ips: List[str] = []
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                ip = _strip_port(line.strip())
                if _is_ip(ip):
                    ips.append(ip)
    else:
        if not sys.stdin.isatty():
            for line in sys.stdin.read().splitlines():
                ip = _strip_port(line.strip())
                if _is_ip(ip):
                    ips.append(ip)

    if not ips:
        print("ERROR: no IPs for remote realtest", file=sys.stderr)
        return 2

    # Split IPs across servers or send full list to each
    if split_targets:
        # Round-robin split
        chunks = [[] for _ in servers]
        for i, ip in enumerate(ips):
            chunks[i % len(servers)].append(ip)
    else:
        # Each server gets the full list
        chunks = [ips[:] for _ in servers]

    all_results = []
    results_lock = threading.Lock()
    result_dir = getattr(args, "result_dir", None) or "results"

    def run_on_server(spec, chunk):
        client = SSHClient.from_spec(spec)
        console.print(f"[cyan]RealTest on {spec} ({len(chunk)} IPs)...[/cyan]")

        # Extract server IP from spec (remove user@ and :port)
        server_host = spec.split("@")[-1].split(":")[0]

        try:
            scanner_path = os.path.abspath(__file__)
            client.run("mkdir -p /tmp/dnstt_work")
            client.upload(scanner_path, "/tmp/dnstt_work/slipscan_cli_2n.py")

            # Upload slipstream-client binary if exists locally
            local_bin = os.path.join(os.path.dirname(scanner_path), "bin", "slipstream-client")
            remote_slipstream = "/tmp/dnstt_work/slipstream-client"
            if os.path.exists(local_bin):
                console.print(f"  [cyan]Uploading slipstream-client binary...[/cyan]")
                client.upload(local_bin, remote_slipstream)
                client.run(f"chmod +x {remote_slipstream}")
            else:
                remote_slipstream = "slipstream-client"  # Use system binary

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(chunk) + "\n")
                tf_path = tf.name
            try:
                client.upload(tf_path, "/tmp/dnstt_work/ips.txt")
            finally:
                os.unlink(tf_path)

            remote_cmd = (
                f"sudo python3 /tmp/dnstt_work/slipscan_cli_2n.py realtest"
                f" --domain {shlex.quote(domain)}"
                f" --file /tmp/dnstt_work/ips.txt"
                f" --slipstream-path {remote_slipstream}"
                f" --result-dir /tmp/dnstt_work"
                f" --ready-timeout-ms {args.ready_timeout_ms}"
                f" --timeout-s {args.timeout_s}"
                f" --stdout"
                f" --auth {shlex.quote(auth[0] + ':' + auth[1])}"
            )

            def on_line(line):
                console.print(f"  [{spec}] {line}")

            rc = client.run_streaming(remote_cmd, on_line)
            if rc != 0:
                console.print(f"[red]Remote realtest on {spec} exited {rc}[/red]")

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                local_result = tf.name
            try:
                client.download("/tmp/dnstt_work/realtest_ok.txt", local_result)
                with open(local_result, "r") as f:
                    result_ips = [l.strip() for l in f if l.strip()]

                # Save results with server IP in filename
                if result_ips:
                    filename = f"realtest_ok_{server_host}.txt"
                    result_path = _merge_and_save_results(result_dir, filename, result_ips)
                    console.print(f"[dim]Server {server_host}: {len(result_ips)} IPs saved to {result_path}[/dim]")

                with results_lock:
                    all_results.extend(result_ips)
            except Exception:
                console.print(f"[yellow]No realtest_ok.txt from {spec}[/yellow]")
            finally:
                try:
                    os.unlink(local_result)
                except OSError:
                    pass
        finally:
            client.cleanup_remote("/tmp/dnstt_work")

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(servers)) as pool:
        futs = []
        for spec, chunk in zip(servers, chunks):
            if chunk:
                futs.append(pool.submit(run_on_server, spec, chunk))
        for fut in concurrent.futures.as_completed(futs):
            try:
                fut.result()
            except Exception as exc:
                console.print(f"[red]Server error: {exc}[/red]")

    console.print(f"\n[bold green]RealTest complete: {len(all_results)} OK IPs from {len(servers)} server(s)[/bold green]")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    # Handle remote execution via --on
    if getattr(args, "on", None):
        return _run_scan_remote(args)

    domain = args.domain.strip()
    if not domain:
        print("ERROR: --domain is required", file=sys.stderr)
        return 2

    # Parse auth
    auth = tuple(args.auth.split(":", 1)) if getattr(args, "auth", None) else ("user", "pass")

    use_file = bool(args.file)
    tokens = list(args.targets or [])
    if not use_file and not tokens:
        print("ERROR: provide --file or --targets", file=sys.stderr)
        return 2

    timeout_ms = int(args.timeout_ms)
    threads = max(1, int(args.threads))
    random_k = int(args.random_per_cidr)
    use_random = random_k > 0

    if use_file and use_random and _file_has_plain_ip(args.file):
        use_random = False
        random_k = 0

    if use_file:
        total = _count_targets_file(args.file, use_random, random_k)
    else:
        total = _count_targets_in_lines(tokens, use_random, random_k)

    if total <= 0:
        print("WARN: No targets found.", file=sys.stderr)
        return 1

    worker_count = min(threads, max(1, total))

    target_q: "Queue[str]" = Queue(maxsize=10000)
    out_q: "Queue[Tuple[str,bool,str,int]]" = Queue()

    stop_evt = threading.Event()
    producer_done = threading.Event()

    auto_mode = args.auto_realtest.lower()
    ms_max = args.realtest_ms_max

    rt_exe = args.realtest_slipstream_path.strip() if args.realtest_slipstream_path else ""
    if not rt_exe:
        rt_exe = "slipstream-client-windows-amd64.exe" if os.name == "nt" else "slipstream-client"

    rt_ready = int(args.realtest_ready_ms)
    rt_timeout = float(args.realtest_timeout_s)
    rt_parallel = max(1, int(args.realtest_parallel))

    found_end: List[str] = []
    found_seen = set()

    rt_in: "Queue[str]" = Queue()
    rt_out: "Queue[Tuple[str,str,str]]" = Queue()
    rt_stop = threading.Event()

    dash = RichDashboard(total_scan=total, table_keep=1500)

    # Collect results for directory merge
    scan_ok_ips = []
    rt_ok_ips = []

    def _write_scan_ok(ip_: str):
        scan_ok_ips.append(ip_.strip())

    def _write_rt_ok(ip_: str, ms_: str):
        rt_ok_ips.append(ip_.strip())

    # Fix #1: When UI is ON, don't print lines to stdout unless --stdout is set
    ui_stdout_off = args.ui and (not args.stdout)

    # live ENQ counter
    rt_enq_lock = threading.Lock()
    rt_enqueued = 0

    def subtitle():
        return f"domain={domain} | workers={worker_count}/{threads} | timeout={timeout_ms}ms | random={random_k} | auto={auto_mode}"

    def producer():
        try:
            it = _iter_targets_file(args.file, stop_evt, use_random, random_k) if use_file else _iter_targets_tokens(tokens, stop_evt, use_random, random_k)
            for ip in it:
                if stop_evt.is_set():
                    break
                target_q.put(ip)
        finally:
            producer_done.set()

    def worker():
        while True:
            if producer_done.is_set() and target_q.empty():
                return
            try:
                ip = target_q.get(timeout=0.2)
            except Empty:
                continue
            ok1, detail, ms = fast_dns_tunnel_check(ip, domain, timeout_ms)
            out_q.put((ip, ok1, detail, ms))

    def rt_worker():
        while not rt_stop.is_set():
            try:
                ip = rt_in.get(timeout=0.2)
            except Empty:
                # do not exit too early; only exit when stop is set OR nothing more expected later
                if producer_done.is_set() and rt_in.empty():
                    time.sleep(0.05)
                continue
            dash.set_current_realtest(ip)
            st, ms = realtest_one(ip, domain, rt_exe, rt_ready, rt_timeout, auth=auth)
            rt_out.put((ip, st, ms))
            dash.set_current_realtest("")

    threading.Thread(target=producer, daemon=True).start()
    for _ in range(worker_count):
        threading.Thread(target=worker, daemon=True).start()

    if auto_mode == "live":
        for _ in range(rt_parallel):
            threading.Thread(target=rt_worker, daemon=True).start()

    done = 0

    try:
        # Fix #2: keep final screen (screen=False, transient=False)
        with Live(dash.render(subtitle()), refresh_per_second=12, console=dash.console, screen=False, transient=False) as live:
            while done < total:
                # drain rt outputs (live)
                if auto_mode == "live":
                    for _ in range(600):
                        try:
                            ip_rt, st_rt, ms_rt = rt_out.get_nowait()
                        except Empty:
                            break
                        ok_rt = st_rt.endswith(" ms")
                        dash.update_realtest(ip_rt, ms_rt, st_rt, ok_rt)
                        if ok_rt:
                            _write_rt_ok(ip_rt, ms_rt)

                try:
                    ip, ok1, detail, ms = out_q.get(timeout=0.2)
                except Empty:
                    live.update(dash.render(subtitle()))
                    continue

                done += 1
                scan_ms_str = "-" if ms < 0 else str(ms)
                dash.update_scan(ip, scan_ms_str, detail, ok1)

                if ok1:
                    _write_scan_ok(ip)
                    if not ui_stdout_off:
                        print(f"{ip}\t{scan_ms_str}\t{detail}")

                    if ip not in found_seen:
                        found_seen.add(ip)

                        passes = True
                        if ms_max is not None:
                            if ms < 0:
                                passes = False
                            else:
                                passes = ms < int(ms_max)

                        if passes:
                            if auto_mode == "end":
                                found_end.append(ip)
                            elif auto_mode == "live":
                                rt_in.put(ip)
                                with rt_enq_lock:
                                    rt_enqueued += 1
                                    dash.rt_enqueued = rt_enqueued
                                    dash.inc_rt_enq()  # keep in sync, harmless

                live.update(dash.render(subtitle()))

            # ---- scan finished ----

            if auto_mode == "live":
                # IMPORTANT: do NOT stop workers immediately.
                # Wait until all enqueued realtests are DONE or deadline hits.
                with rt_enq_lock:
                    enq = rt_enqueued
                    dash.rt_enqueued = enq

                deadline = time.monotonic() + max(5.0, float(args.live_drain_timeout_s))
                while True:
                    drained = False
                    for _ in range(1200):
                        try:
                            ip_rt, st_rt, ms_rt = rt_out.get_nowait()
                        except Empty:
                            break
                        drained = True
                        ok_rt = st_rt.endswith(" ms")
                        dash.update_realtest(ip_rt, ms_rt, st_rt, ok_rt)
                        if ok_rt:
                            _write_rt_ok(ip_rt, ms_rt)

                    live.update(dash.render(subtitle()))

                    # finish condition: all enqueued results arrived and queue empty
                    if dash.rt_done >= enq and rt_in.empty():
                        break

                    if time.monotonic() > deadline:
                        break

                    if not drained:
                        time.sleep(0.05)

                rt_stop.set()

            if auto_mode == "end" and found_end:
                for ip in found_end:
                    dash.set_current_realtest(ip)
                    live.update(dash.render(subtitle()))

                    st, ms_rt = realtest_one(ip, domain, rt_exe, rt_ready, rt_timeout, auth=auth)
                    ok_rt = st.endswith(" ms")
                    dash.update_realtest(ip, ms_rt, st, ok_rt)
                    if ok_rt:
                        _write_rt_ok(ip, ms_rt)

                    dash.set_current_realtest("")
                    live.update(dash.render(subtitle()))

                    if not ui_stdout_off:
                        print(f"RT\t{ip}\t{st}\t{ms_rt}")

        # After Live ends, print final panel so it stays
        dash.console.print(dash.render(subtitle()))

    except KeyboardInterrupt:
        stop_evt.set()
        rt_stop.set()
        print("\nInterrupted.", file=sys.stderr)

    # Save results to directory
    result_dir = getattr(args, "result_dir", None)
    if result_dir:
        if scan_ok_ips:
            scan_path = _merge_and_save_results(result_dir, "scan_ok.txt", scan_ok_ips)
            print(f"Scan results saved to: {scan_path}", file=sys.stderr)
        if rt_ok_ips:
            rt_path = _merge_and_save_results(result_dir, "realtest_ok.txt", rt_ok_ips)
            print(f"RealTest results saved to: {rt_path}", file=sys.stderr)

    return 0


def cmd_realtest(args: argparse.Namespace) -> int:
    # Handle remote execution via --on (split IPs) or --test-from (full list per server)
    if getattr(args, "test_from", None):
        return _run_realtest_remote(args, split_targets=False)
    if getattr(args, "on", None):
        return _run_realtest_remote(args, split_targets=True)

    domain = args.domain.strip()
    auth = tuple(args.auth.split(":", 1)) if getattr(args, "auth", None) else ("user", "pass")
    exe = args.slipstream_path.strip() if args.slipstream_path else ""
    if not exe:
        exe = "slipstream-client-windows-amd64.exe" if os.name == "nt" else "slipstream-client"

    ips: List[str] = []
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                ip = _strip_port(line.strip())
                if _is_ip(ip):
                    ips.append(ip)
    else:
        if not sys.stdin.isatty():
            for line in sys.stdin.read().splitlines():
                ip = _strip_port(line.strip())
                if _is_ip(ip):
                    ips.append(ip)

    seen = set()
    uniq = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    ips = uniq

    if not ips:
        print("ERROR: no IPs provided for realtest", file=sys.stderr)
        return 2

    dash = RichDashboard(total_scan=len(ips), table_keep=500)

    # Collect results for directory merge
    rt_ok_ips = []

    def _write_rt_ok(ip_: str, ms_: str):
        rt_ok_ips.append(ip_.strip())

    def subtitle():
        return f"RealTest only | domain={domain} | timeout={args.timeout_s}s | ready={args.ready_timeout_ms}ms"

    ui_stdout_off = args.ui and (not args.stdout)

    with Live(dash.render(subtitle()), refresh_per_second=12, console=dash.console, screen=False, transient=False) as live:
        for ip in ips:
            dash.update_scan(ip, "-", "(manual list)", True)
            dash.set_current_realtest(ip)
            live.update(dash.render(subtitle()))

            st, ms = realtest_one(ip, domain, exe, args.ready_timeout_ms, args.timeout_s, auth=auth)
            ok_rt = st.endswith(" ms")
            dash.update_realtest(ip, ms, st, ok_rt)
            if ok_rt:
                _write_rt_ok(ip, ms)

            dash.set_current_realtest("")
            live.update(dash.render(subtitle()))

            if not ui_stdout_off:
                print(f"{ip}\t{st}\t{ms}")

    dash.console.print(dash.render(subtitle()))

    # Save results to directory
    result_dir = getattr(args, "result_dir", None)
    if result_dir and rt_ok_ips:
        rt_path = _merge_and_save_results(result_dir, "realtest_ok.txt", rt_ok_ips)
        print(f"RealTest results saved to: {rt_path}", file=sys.stderr)

    return 0


# ========================= CLI =========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="Slipstream-Scan", description="DNS Tunnel Scanner and Deployment Tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Fast scan (UDP/53) + Rich UI")
    s.add_argument("--domain", required=True)
    s.add_argument("--file")
    s.add_argument("--targets", nargs="*")
    s.add_argument("--timeout-ms", type=int, default=1000)
    s.add_argument("--threads", type=int, default=200)
    s.add_argument("--random-per-cidr", type=int, default=0)

    s.add_argument("--ui", action="store_true", help="Enable Rich UI dashboard")
    s.add_argument("--stdout", action="store_true", help="When --ui is on, also print results to stdout (default: off)")
    s.add_argument("--result-dir", default="results", help="Directory to store results (default: results/)")

    # Legacy compatibility (deprecated)
    s.add_argument("--scan-ok-out", default="", help="[DEPRECATED] Use --result-dir instead")
    s.add_argument("--realtest-ok-out", default="", help="[DEPRECATED] Use --result-dir instead")
    s.add_argument("--realtest-ok-format", choices=["ip", "ipms"], default="ip", help="[DEPRECATED]")

    s.add_argument("--auto-realtest", choices=["off", "end", "live"], default="off")
    s.add_argument("--realtest-ms-max", type=int, default=None)
    s.add_argument("--realtest-timeout-s", type=float, default=25.0)
    s.add_argument("--realtest-ready-ms", type=int, default=20000)
    s.add_argument("--realtest-slipstream-path", default="")
    s.add_argument("--realtest-parallel", type=int, default=1, help="Only for live mode (default 1)")

    s.add_argument("--live-drain-timeout-s", type=float, default=30.0,
                   help="After scan finishes in live mode, wait up to this many seconds for remaining RealPing results.")

    s.add_argument("--auth", default=None, help="SOCKS5 auth as USER:PASS (default: user:pass)")
    s.add_argument("--on", action="append", default=None, metavar="[USER@]HOST[:PORT]",
                   help="Run scan on remote server(s) via SSH (repeatable)")

    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("realtest", help="RealPing from file/stdin + Rich UI")
    r.add_argument("--domain", required=True)
    r.add_argument("--file")
    r.add_argument("--slipstream-path", default="")
    r.add_argument("--ready-timeout-ms", type=int, default=20000)
    r.add_argument("--timeout-s", type=float, default=25.0)
    r.add_argument("--ui", action="store_true", help="Enable Rich UI dashboard")
    r.add_argument("--stdout", action="store_true", help="When --ui is on, also print results to stdout (default: off)")
    r.add_argument("--result-dir", default="results", help="Directory to store results (default: results/)")

    # Legacy compatibility (deprecated)
    r.add_argument("--realtest-ok-out", default="", help="[DEPRECATED] Use --result-dir instead")
    r.add_argument("--realtest-ok-format", choices=["ip", "ipms"], default="ip", help="[DEPRECATED]")

    r.add_argument("--auth", default=None, help="SOCKS5 auth as USER:PASS (default: user:pass)")
    r.add_argument("--on", action="append", default=None, metavar="[USER@]HOST[:PORT]",
                   help="Run realtest on remote server(s) via SSH (repeatable)")

    r.set_defaults(func=cmd_realtest)

    return p


def add_subparser(subparsers) -> None:
    """Register scan and realtest subcommands into an external argparse subparsers group."""
    # We rebuild the arguments here so dnstt.py can incorporate them.
    s = subparsers.add_parser("scan", help="Fast scan (UDP/53) + Rich UI")
    s.add_argument("--domain", required=True)
    s.add_argument("--file")
    s.add_argument("--targets", nargs="*")
    s.add_argument("--timeout-ms", type=int, default=1000)
    s.add_argument("--threads", type=int, default=200)
    s.add_argument("--random-per-cidr", type=int, default=0)

    s.add_argument("--ui", action="store_true", help="Enable Rich UI dashboard")
    s.add_argument("--stdout", action="store_true", help="When --ui is on, also print results to stdout (default: off)")
    s.add_argument("--result-dir", default="results", help="Directory to store results (default: results/)")

    # Legacy
    s.add_argument("--scan-ok-out", default="", help="[DEPRECATED]")
    s.add_argument("--realtest-ok-out", default="", help="[DEPRECATED]")
    s.add_argument("--realtest-ok-format", choices=["ip", "ipms"], default="ip")

    s.add_argument("--auto-realtest", choices=["off", "end", "live"], default="off")
    s.add_argument("--realtest-ms-max", type=int, default=None)
    s.add_argument("--realtest-timeout-s", type=float, default=25.0)
    s.add_argument("--realtest-ready-ms", type=int, default=20000)
    s.add_argument("--realtest-slipstream-path", default="")
    s.add_argument("--realtest-parallel", type=int, default=1)

    s.add_argument("--live-drain-timeout-s", type=float, default=30.0)

    s.add_argument("--auth", default=None, help="SOCKS5 auth as USER:PASS")
    s.add_argument("--on", action="append", default=None, metavar="[USER@]HOST[:PORT]",
                   help="Run scan on remote server(s) via SSH (repeatable)")
    s.set_defaults(func=cmd_scan)

    r = subparsers.add_parser("realtest", help="RealPing from file/stdin + Rich UI")
    r.add_argument("--domain", required=True)
    r.add_argument("--file")
    r.add_argument("--slipstream-path", default="")
    r.add_argument("--ready-timeout-ms", type=int, default=20000)
    r.add_argument("--timeout-s", type=float, default=25.0)
    r.add_argument("--ui", action="store_true", help="Enable Rich UI dashboard")
    r.add_argument("--stdout", action="store_true")
    r.add_argument("--result-dir", default="results", help="Directory to store results (default: results/)")

    # Legacy
    r.add_argument("--realtest-ok-out", default="", help="[DEPRECATED]")
    r.add_argument("--realtest-ok-format", choices=["ip", "ipms"], default="ip")

    r.add_argument("--auth", default=None, help="SOCKS5 auth as USER:PASS")
    r.add_argument("--on", action="append", default=None, metavar="[USER@]HOST[:PORT]",
                   help="Run realtest on remote server(s) via SSH, splitting IPs round-robin (repeatable)")
    r.add_argument("--test-from", action="append", default=None, metavar="[USER@]HOST[:PORT]",
                   help="Test from remote server(s) in parallel, each server tests ALL IPs (repeatable)")
    r.set_defaults(func=cmd_realtest)

def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))

if __name__ == "__main__":
    raise SystemExit(main())
