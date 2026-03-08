#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dnstt — unified CLI for scan, realtest, deploy, and pipeline."""

import argparse
import sys
from typing import List, Optional

from ssh_client import SSHClient, parse_on


def cmd_servers_test(args: argparse.Namespace) -> int:
    """Quick SSH connectivity check for one or more servers."""
    from rich.console import Console
    console = Console(stderr=True)
    hosts = args.hosts
    ok = 0
    for spec in hosts:
        client = SSHClient.from_spec(spec)
        stdout, stderr, rc = client.run("echo ok")
        if rc == 0 and "ok" in stdout:
            console.print(f"  [green]OK[/green]  {spec}")
            ok += 1
        else:
            detail = stderr.strip().splitlines()[0] if stderr.strip() else f"exit {rc}"
            console.print(f"  [red]FAIL[/red] {spec} — {detail}")
    console.print(f"\n{ok}/{len(hosts)} servers reachable")
    return 0 if ok == len(hosts) else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dnstt",
        description="dnstt — unified CLI for DNS tunnel scanning, testing, and deployment",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Import and register subcommands from each module
    from slipscan_cli_2n import add_subparser as scan_add
    scan_add(sub)

    from deploy import add_subparser as deploy_add
    deploy_add(sub)

    from deploy_lb import add_subparser as deploy_lb_add
    deploy_lb_add(sub)

    from pipeline import add_subparser as pipeline_add
    pipeline_add(sub)

    # servers test — inline subcommand
    srv = sub.add_parser("servers", help="Server management commands")
    srv_sub = srv.add_subparsers(dest="servers_cmd", required=True)

    test = srv_sub.add_parser("test", help="Test SSH connectivity to servers")
    test.add_argument("hosts", nargs="+", metavar="[USER@]HOST[:PORT]",
                      help="Server(s) to test")
    test.set_defaults(func=cmd_servers_test)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
