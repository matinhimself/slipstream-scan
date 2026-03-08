#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deploy subcommand — create systemd slipstream-client units on remote servers."""

import argparse
import os
import sys
from typing import List

from rich.console import Console

from ssh_client import SSHClient, parse_on


UNIT_TEMPLATE = """\
[Unit]
Description=SlipStream client for {ip}
After=network.target

[Service]
Type=simple
ExecStart={slipstream_bin} \\
    --resolver {ip}:53 \\
    --domain {domain} -l {port}

CapabilityBoundingSet = CAP_NET_RAW
AmbientCapabilities   = CAP_NET_RAW
Restart=always

[Install]
WantedBy=multi-user.target
"""


def _deploy_to_server(spec: str, ips: List[str], domain: str,
                      auth: tuple, start_port: int,
                      slipstream_bin: str, console: Console) -> List[str]:
    """Deploy units for *ips* on one server.  Returns SOCKS5 URLs."""
    client = SSHClient.from_spec(spec)
    user_on, host_on, _ = parse_on(spec)

    console.print(f"[cyan]Deploying {len(ips)} units to {spec}...[/cyan]")

    for i, ip in enumerate(ips, start=1):
        port = start_port + i - 1
        dest_dir = f"/etc/slipservers/ip/{i}"

        client.run(f"sudo mkdir -p {dest_dir}")
        client.run(f"sudo bash -c \"printf '%s\\n' '{ip}' > {dest_dir}/common-ips-real.txt\"")

        unit_content = UNIT_TEMPLATE.format(
            ip=ip,
            domain=domain,
            port=port,
            slipstream_bin=slipstream_bin,
        )
        # Write unit file via heredoc over ssh
        client.run(
            f"sudo bash -c \"cat > /etc/systemd/system/slipstream-client-{i}.service << 'DNSTT_UNIT_EOF'\n"
            f"{unit_content}"
            f"DNSTT_UNIT_EOF\""
        )
        console.print(f"  [green]Created slipstream-client-{i}.service (port {port})[/green]")

    # Reload and enable
    client.run("sudo systemctl daemon-reload")
    for i in range(1, len(ips) + 1):
        unit = f"slipstream-client-{i}.service"
        client.run(f"sudo systemctl enable --now {unit}")
        console.print(f"  [green]Enabled {unit}[/green]")
    client.run("sudo systemctl daemon-reload")

    # Determine host IP for proxy URLs
    stdout, _, _ = client.run("hostname -I | awk '{print $1}'")
    host_ip = stdout.strip() or host_on

    # Build proxy URLs
    auth_user, auth_pass = auth
    urls = []
    for i in range(len(ips)):
        port = start_port + i
        urls.append(f"socks5://{auth_user}:{auth_pass}@{host_ip}:{port}#slip-{auth_user}-{port}")
        urls.append(f"tg://socks?server={host_ip}&port={port}&user={auth_user}&pass={auth_pass}")

    return urls


def cmd_deploy(args: argparse.Namespace) -> int:
    console = Console(stderr=True)

    # Read IPs
    if not args.file:
        console.print("[red]ERROR: --file is required[/red]")
        return 2

    ips: List[str] = []
    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ip = line.split()[0].strip()
                if ip:
                    ips.append(ip)

    if not ips:
        console.print("[red]ERROR: no IPs found in file[/red]")
        return 2

    servers = args.on
    if not servers:
        console.print("[red]ERROR: --on is required[/red]")
        return 2

    domain = args.domain.strip()
    auth = tuple(args.auth.split(":", 1)) if args.auth else ("mat", "somethingelse")
    start_port = int(args.start_port)
    slipstream_bin = args.slipstream_bin.strip()

    all_urls = []
    for spec in servers:
        try:
            urls = _deploy_to_server(spec, ips, domain, auth, start_port,
                                     slipstream_bin, console)
            all_urls.extend(urls)
        except Exception as exc:
            console.print(f"[red]Failed on {spec}: {exc}[/red]")

    if all_urls:
        console.print("\n[bold green]Proxy URLs:[/bold green]")
        for url in all_urls:
            console.print(f"  {url}")

    console.print(f"\n[bold green]Done — {len(ips)} services deployed to {len(servers)} server(s)[/bold green]")
    return 0


def add_subparser(subparsers) -> None:
    """Register the deploy subcommand."""
    p = subparsers.add_parser("deploy", help="Deploy slipstream-client units to remote servers")
    p.add_argument("--file", required=True, help="File with IPs (one per line)")
    p.add_argument("--on", action="append", required=True, metavar="[USER@]HOST[:PORT]",
                   help="Remote server(s) to deploy to (repeatable)")
    p.add_argument("--domain", required=True, help="DNS tunnel domain")
    p.add_argument("--auth", default=None, help="SOCKS5 auth as USER:PASS (default: user:pass)")
    p.add_argument("--start-port", type=int, default=5200, help="First listening port (default: 5200)")
    p.add_argument("--slipstream-bin", default="/usr/bin/slipstream-client",
                   help="Path to slipstream-client binary on remote (default: /usr/bin/slipstream-client)")
    p.set_defaults(func=cmd_deploy)
