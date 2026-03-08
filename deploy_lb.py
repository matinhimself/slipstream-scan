#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Load Balancer deployment — deploy HAProxy instances with various configurations."""

import argparse
import os
import sys
from typing import List, Tuple
from urllib.parse import urlparse

from rich.console import Console

from ssh_client import SSHClient, parse_on


# ============================================================================
# HAProxy Configuration Templates
# ============================================================================

HAPROXY_GLOBAL = """\
global
    maxconn 10000
    log /dev/log local0

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client 300s
    timeout server 300s
    retries 3
"""


def _haproxy_socks_lb_config(listen_port: int, backends: List[Tuple[str, int]]) -> str:
    """Mode 1: SOCKS Backend Load Balancer

    Single frontend -> multiple SOCKS backends
    """
    cfg = HAPROXY_GLOBAL
    cfg += f"""\
frontend socks_lb
    bind *:{listen_port}
    mode tcp
    default_backend socks_pool

backend socks_pool
    mode tcp
    balance roundrobin
"""
    for i, (host, port) in enumerate(backends, start=1):
        cfg += f"    server socks{i} {host}:{port} check inter 5s fall 3 rise 2\n"

    return cfg


def _haproxy_multi_fe_config(frontend_ips: List[str], fe_port: int,
                               dns_resolvers: List[str]) -> str:
    """Mode 2: Multi-Frontend Load Balancer

    Multiple frontends (one per IP) -> shared DNS resolver pool
    """
    cfg = HAPROXY_GLOBAL

    # Create frontend for each IP
    for i, ip in enumerate(frontend_ips, start=1):
        cfg += f"""\
frontend dns_fe_{i}
    bind {ip}:{fe_port}
    mode tcp
    default_backend dns_pool

"""

    # Shared backend
    cfg += """\
backend dns_pool
    mode tcp
    balance roundrobin
"""
    for i, resolver in enumerate(dns_resolvers, start=1):
        cfg += f"    server dns{i} {resolver}:53 check inter 5s fall 3 rise 2\n"

    return cfg


def _haproxy_tunnel_lb_config(listen_port: int, tunnel_ports: List[int]) -> str:
    """Mode 3: DNS Tunnel SOCKS Load Balancer

    Single SOCKS frontend -> multiple local slipstream backends
    """
    cfg = HAPROXY_GLOBAL
    cfg += f"""\
frontend tunnel_socks
    bind *:{listen_port}
    mode tcp
    default_backend tunnel_pool

backend tunnel_pool
    mode tcp
    balance roundrobin
"""
    for i, port in enumerate(tunnel_ports, start=1):
        cfg += f"    server tunnel{i} 127.0.0.1:{port} check inter 5s fall 3 rise 2\n"

    return cfg


SLIPSTREAM_LB_UNIT_TEMPLATE = """\
[Unit]
Description=SlipStream LB backend {idx} for {resolver}
After=network.target

[Service]
Type=simple
ExecStart={slipstream_bin} \\
    --resolver {resolver}:53 \\
    --domain {domain} -l {port}

CapabilityBoundingSet = CAP_NET_RAW
AmbientCapabilities   = CAP_NET_RAW
Restart=always

[Install]
WantedBy=multi-user.target
"""


# ============================================================================
# Helper Functions
# ============================================================================

def _configure_apt_mirrors(client: SSHClient, console: Console) -> None:
    """Configure fast apt mirrors for the server."""
    console.print("  [dim]Configuring apt mirrors for faster downloads...[/dim]")

    # Use Shatel mirror for Ubuntu (Iranian mirror, very fast)
    sources_list = """
# Shatel Ubuntu Mirror
deb https://mirror.shatel.ir/ubuntu/ noble main restricted universe multiverse
deb https://mirror.shatel.ir/ubuntu/ noble-updates main restricted universe multiverse
deb https://mirror.shatel.ir/ubuntu/ noble-security main restricted universe multiverse
"""

    try:
        # Backup original sources
        client.run("sudo cp /etc/apt/sources.list /etc/apt/sources.list.backup 2>/dev/null || true")

        # Write new sources
        client.run(f"sudo bash -c \"cat > /etc/apt/sources.list << 'APT_SOURCES_EOF'\n{sources_list}APT_SOURCES_EOF\"")
        console.print("  [dim]Apt mirrors configured[/dim]")
    except Exception as e:
        console.print(f"  [yellow]Mirror configuration failed, using defaults: {e}[/yellow]")


def _ensure_haproxy_installed(client: SSHClient, console: Console) -> bool:
    """Install HAProxy if not present. Returns True if HAProxy is available."""
    # Check if already installed
    stdout, _, rc = client.run("which haproxy")
    if rc == 0 and stdout.strip():
        console.print(f"  [dim]HAProxy already installed: {stdout.strip()}[/dim]")
        return True

    # Upload and install from local .deb
    local_deb = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "haproxy_2.8.5-1ubuntu3_amd64.deb")
    if not os.path.exists(local_deb):
        console.print(f"[red]HAProxy not found on remote and {local_deb} missing locally[/red]")
        return False

    console.print("  [cyan]Uploading and installing HAProxy...[/cyan]")
    try:
        # Upload liblua5.4 dependency from local bin
        local_lua = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "liblua5.4-0_5.4.6-3build2_amd64.deb")
        if os.path.exists(local_lua):
            console.print("  [dim]Uploading and installing liblua5.4-0...[/dim]")
            client.upload(local_lua, "/tmp/liblua.deb")
            client.run("sudo dpkg -i /tmp/liblua.deb || true")
            client.run("sudo rm -f /tmp/liblua.deb")
        else:
            console.print("  [dim]liblua5.4 .deb not found, skipping...[/dim]")

        # Upload and install HAProxy
        client.upload(local_deb, "/tmp/haproxy.deb")
        client.run("sudo dpkg -i /tmp/haproxy.deb || true")
        client.run("sudo rm -f /tmp/haproxy.deb")

        # Verify installation
        stdout, _, rc = client.run("haproxy -v")
        if rc == 0:
            console.print(f"  [green]HAProxy installed successfully: {stdout.splitlines()[0] if stdout else 'OK'}[/green]")
            return True
        else:
            console.print("[red]HAProxy installation verification failed[/red]")
            return False
    except Exception as e:
        console.print(f"[red]Failed to install HAProxy: {e}[/red]")
        return False


def _ensure_slipstream_installed(client: SSHClient, console: Console) -> str:
    """Upload slipstream-client binary if not present. Returns path to binary."""
    # Check if already installed
    stdout, _, rc = client.run("which slipstream-client")
    if rc == 0 and stdout.strip():
        return stdout.strip()

    # Upload from local bin
    local_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "slipstream-client")
    if not os.path.exists(local_bin):
        console.print(f"[red]slipstream-client not found locally at {local_bin}[/red]")
        return "/usr/bin/slipstream-client"  # fallback

    console.print("  [cyan]Uploading slipstream-client binary...[/cyan]")
    try:
        remote_path = "/usr/local/bin/slipstream-client"
        client.upload(local_bin, "/tmp/slipstream-client")
        client.run("sudo mv /tmp/slipstream-client /usr/local/bin/slipstream-client")
        client.run("sudo chmod +x /usr/local/bin/slipstream-client")
        console.print(f"  [green]slipstream-client installed to {remote_path}[/green]")
        return remote_path
    except Exception as e:
        console.print(f"[yellow]Failed to upload slipstream-client: {e}[/yellow]")
        return "/usr/bin/slipstream-client"


# ============================================================================
# Deployment Functions
# ============================================================================

def _parse_socks_url(url: str) -> Tuple[str, str, str, int]:
    """Parse socks5://user:pass@host:port -> (user, pass, host, port)"""
    parsed = urlparse(url)
    if parsed.scheme != "socks5":
        raise ValueError(f"Invalid SOCKS URL (must start with socks5://): {url}")

    user = parsed.username or "mat"
    password = parsed.password or "somethingelse"
    host = parsed.hostname or ""
    port = parsed.port or 1080

    if not host:
        raise ValueError(f"Missing host in SOCKS URL: {url}")

    return user, password, host, port


def _deploy_socks_lb(spec: str, socks_urls: List[str], listen_port: int,
                      console: Console) -> List[str]:
    """Mode 1: Deploy SOCKS Backend Load Balancer"""
    client = SSHClient.from_spec(spec)
    _, host_on, _ = parse_on(spec)

    console.print(f"[cyan]Deploying SOCKS Load Balancer to {spec}...[/cyan]")

    # Ensure HAProxy is installed
    if not _ensure_haproxy_installed(client, console):
        return []

    # Parse SOCKS URLs to get backends
    backends = []
    for url in socks_urls:
        try:
            _, _, host, port = _parse_socks_url(url)
            backends.append((host, port))
        except ValueError as e:
            console.print(f"[yellow]Skipping invalid URL: {e}[/yellow]")

    if not backends:
        console.print("[red]No valid SOCKS backends found[/red]")
        return []

    # Generate HAProxy config
    haproxy_cfg = _haproxy_socks_lb_config(listen_port, backends)

    # Upload and install
    client.run("sudo mkdir -p /etc/haproxy")
    client.run(
        f"sudo bash -c \"cat > /etc/haproxy/haproxy-socks-lb.cfg << 'HAPROXY_CFG_EOF'\n"
        f"{haproxy_cfg}"
        f"HAPROXY_CFG_EOF\""
    )

    # Create systemd unit
    systemd_unit = f"""\
[Unit]
Description=HAProxy SOCKS Load Balancer
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/haproxy -f /etc/haproxy/haproxy-socks-lb.cfg
Restart=always

[Install]
WantedBy=multi-user.target
"""

    client.run(
        f"sudo bash -c \"cat > /etc/systemd/system/haproxy-socks-lb.service << 'UNIT_EOF'\n"
        f"{systemd_unit}"
        f"UNIT_EOF\""
    )

    # Enable and start
    client.run("sudo systemctl daemon-reload")
    client.run("sudo systemctl enable --now haproxy-socks-lb.service")

    console.print(f"  [green]Created haproxy-socks-lb.service on port {listen_port}[/green]")

    # Get host IP
    stdout, _, _ = client.run("hostname -I | awk '{print $1}'")
    host_ip = stdout.strip() or host_on

    return [f"socks5://{host_ip}:{listen_port}"]


def _deploy_multi_fe_lb(spec: str, frontend_ips: List[str], dns_resolvers: List[str],
                         fe_port: int, console: Console) -> List[str]:
    """Mode 2: Deploy Multi-Frontend Load Balancer"""
    client = SSHClient.from_spec(spec)

    console.print(f"[cyan]Deploying Multi-Frontend LB to {spec}...[/cyan]")

    # Ensure HAProxy is installed
    if not _ensure_haproxy_installed(client, console):
        return []

    # Generate HAProxy config
    haproxy_cfg = _haproxy_multi_fe_config(frontend_ips, fe_port, dns_resolvers)

    # Upload and install
    client.run("sudo mkdir -p /etc/haproxy")
    client.run(
        f"sudo bash -c \"cat > /etc/haproxy/haproxy-multi-fe.cfg << 'HAPROXY_CFG_EOF'\n"
        f"{haproxy_cfg}"
        f"HAPROXY_CFG_EOF\""
    )

    # Create systemd unit
    systemd_unit = f"""\
[Unit]
Description=HAProxy Multi-Frontend Load Balancer
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/haproxy -f /etc/haproxy/haproxy-multi-fe.cfg
Restart=always

[Install]
WantedBy=multi-user.target
"""

    client.run(
        f"sudo bash -c \"cat > /etc/systemd/system/haproxy-multi-fe.service << 'UNIT_EOF'\n"
        f"{systemd_unit}"
        f"UNIT_EOF\""
    )

    # Enable and start
    client.run("sudo systemctl daemon-reload")
    client.run("sudo systemctl enable --now haproxy-multi-fe.service")

    console.print(f"  [green]Created haproxy-multi-fe.service with {len(frontend_ips)} frontends[/green]")

    # Return list of DNS endpoints
    return [f"{ip}:{fe_port}" for ip in frontend_ips]


def _deploy_tunnel_lb(spec: str, dns_resolvers: List[str], domain: str,
                       auth: Tuple[str, str], listen_port: int,
                       slipstream_bin: str, console: Console) -> List[str]:
    """Mode 3: Deploy DNS Tunnel SOCKS Load Balancer"""
    client = SSHClient.from_spec(spec)
    _, host_on, _ = parse_on(spec)

    console.print(f"[cyan]Deploying Tunnel Load Balancer to {spec}...[/cyan]")

    # Ensure HAProxy is installed
    if not _ensure_haproxy_installed(client, console):
        return []

    # Ensure slipstream-client is installed
    slipstream_path = _ensure_slipstream_installed(client, console)

    # Create slipstream units for each resolver
    tunnel_ports = []
    base_tunnel_port = listen_port + 1

    for i, resolver in enumerate(dns_resolvers, start=1):
        tunnel_port = base_tunnel_port + i - 1
        tunnel_ports.append(tunnel_port)

        unit_content = SLIPSTREAM_LB_UNIT_TEMPLATE.format(
            idx=i,
            resolver=resolver,
            domain=domain,
            port=tunnel_port,
            slipstream_bin=slipstream_path,
        )

        client.run(
            f"sudo bash -c \"cat > /etc/systemd/system/slipstream-lb-{i}.service << 'SLIP_UNIT_EOF'\n"
            f"{unit_content}"
            f"SLIP_UNIT_EOF\""
        )
        console.print(f"  [green]Created slipstream-lb-{i}.service -> {resolver}:53 on port {tunnel_port}[/green]")

    # Generate HAProxy config
    haproxy_cfg = _haproxy_tunnel_lb_config(listen_port, tunnel_ports)

    # Upload and install HAProxy config
    client.run("sudo mkdir -p /etc/haproxy")
    client.run(
        f"sudo bash -c \"cat > /etc/haproxy/haproxy-tunnel-lb.cfg << 'HAPROXY_CFG_EOF'\n"
        f"{haproxy_cfg}"
        f"HAPROXY_CFG_EOF\""
    )

    # Create HAProxy systemd unit
    systemd_unit = f"""\
[Unit]
Description=HAProxy DNS Tunnel Load Balancer
After=network.target
Requires={' '.join([f'slipstream-lb-{i}.service' for i in range(1, len(dns_resolvers) + 1)])}

[Service]
Type=simple
ExecStart=/usr/sbin/haproxy -f /etc/haproxy/haproxy-tunnel-lb.cfg
Restart=always

[Install]
WantedBy=multi-user.target
"""

    client.run(
        f"sudo bash -c \"cat > /etc/systemd/system/haproxy-tunnel-lb.service << 'UNIT_EOF'\n"
        f"{systemd_unit}"
        f"UNIT_EOF\""
    )

    # Enable and start all services
    client.run("sudo systemctl daemon-reload")

    for i in range(1, len(dns_resolvers) + 1):
        client.run(f"sudo systemctl enable --now slipstream-lb-{i}.service")

    client.run("sudo systemctl enable --now haproxy-tunnel-lb.service")

    console.print(f"  [green]Created haproxy-tunnel-lb.service on port {listen_port}[/green]")

    # Get host IP
    stdout, _, _ = client.run("hostname -I | awk '{print $1}'")
    host_ip = stdout.strip() or host_on

    user, password = auth
    return [
        f"socks5://{user}:{password}@{host_ip}:{listen_port}#tunnel-lb",
        f"tg://socks?server={host_ip}&port={listen_port}&user={user}&pass={password}",
    ]


# ============================================================================
# Command Entry Point
# ============================================================================

def cmd_deploy_lb(args: argparse.Namespace) -> int:
    console = Console(stderr=True)

    mode = args.mode
    servers = args.on

    if not servers:
        console.print("[red]ERROR: --on is required[/red]")
        return 2

    all_outputs = []

    # Mode 1: SOCKS Backend Load Balancer
    if mode == "socks-lb":
        if not args.socks_urls:
            console.print("[red]ERROR: --socks-url is required for socks-lb mode[/red]")
            return 2

        listen_port = int(args.lb_port)

        for spec in servers:
            try:
                outputs = _deploy_socks_lb(spec, args.socks_urls, listen_port, console)
                all_outputs.extend(outputs)
            except Exception as exc:
                console.print(f"[red]Failed on {spec}: {exc}[/red]")

    # Mode 2: Multi-Frontend Load Balancer
    elif mode == "multi-fe":
        if not args.frontend_ips:
            console.print("[red]ERROR: --frontend-ip is required for multi-fe mode[/red]")
            return 2
        if not args.dns_resolvers:
            console.print("[red]ERROR: --dns-resolver is required for multi-fe mode[/red]")
            return 2

        fe_port = int(args.lb_port)

        for spec in servers:
            try:
                outputs = _deploy_multi_fe_lb(spec, args.frontend_ips,
                                                args.dns_resolvers, fe_port, console)
                all_outputs.extend(outputs)
            except Exception as exc:
                console.print(f"[red]Failed on {spec}: {exc}[/red]")

    # Mode 3: DNS Tunnel SOCKS Load Balancer
    elif mode == "tunnel-lb":
        if not args.dns_resolvers:
            console.print("[red]ERROR: --dns-resolver is required for tunnel-lb mode[/red]")
            return 2
        if not args.domain:
            console.print("[red]ERROR: --domain is required for tunnel-lb mode[/red]")
            return 2

        auth = tuple(args.auth.split(":", 1)) if args.auth else ("mat", "somethingelse")
        listen_port = int(args.lb_port)
        slipstream_bin = args.slipstream_bin

        for spec in servers:
            try:
                outputs = _deploy_tunnel_lb(spec, args.dns_resolvers, args.domain,
                                             auth, listen_port, slipstream_bin, console)
                all_outputs.extend(outputs)
            except Exception as exc:
                console.print(f"[red]Failed on {spec}: {exc}[/red]")

    # Print outputs
    if all_outputs:
        console.print("\n[bold green]Load Balancer Endpoints:[/bold green]")
        for output in all_outputs:
            console.print(f"  {output}")

    console.print(f"\n[bold green]Done — {mode} deployed to {len(servers)} server(s)[/bold green]")
    return 0


def add_subparser(subparsers) -> None:
    """Register the deploy-lb subcommand."""
    p = subparsers.add_parser("deploy-lb", help="Deploy HAProxy load balancers")

    p.add_argument("--mode", required=True,
                   choices=["socks-lb", "multi-fe", "tunnel-lb"],
                   help="Load balancer mode")

    p.add_argument("--on", action="append", required=True, metavar="[USER@]HOST[:PORT]",
                   help="Remote server(s) to deploy to (repeatable)")

    # Mode 1: socks-lb options
    p.add_argument("--socks-url", action="append", dest="socks_urls", default=None,
                   metavar="socks5://user:pass@host:port",
                   help="[socks-lb] SOCKS5 backend URLs (repeatable)")

    # Mode 2: multi-fe options
    p.add_argument("--frontend-ip", action="append", dest="frontend_ips", default=None,
                   metavar="IP",
                   help="[multi-fe] Frontend bind IPs (repeatable)")
    p.add_argument("--dns-resolver", action="append", dest="dns_resolvers", default=None,
                   metavar="IP",
                   help="[multi-fe/tunnel-lb] DNS resolver IPs (repeatable)")

    # Mode 3: tunnel-lb options
    p.add_argument("--domain", default=None,
                   help="[tunnel-lb] DNS tunnel domain")
    p.add_argument("--auth", default=None,
                   help="[tunnel-lb] SOCKS5 auth as USER:PASS (default: user:pass)")
    p.add_argument("--slipstream-bin", default="/usr/bin/slipstream-client",
                   help="[tunnel-lb] Path to slipstream-client binary on remote")

    # Common options
    p.add_argument("--lb-port", type=int, default=6000,
                   help="Load balancer listening port (default: 6000 for socks-lb, 6100 for multi-fe, 6200 for tunnel-lb)")

    p.set_defaults(func=cmd_deploy_lb)
