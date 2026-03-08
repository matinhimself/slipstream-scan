#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pipeline orchestration — scan -> realtest -> deploy in one command."""

import argparse
import os
import shlex
import sys
import tempfile
import threading
from typing import List

from rich.console import Console

from ssh_client import SSHClient
from deploy import _deploy_to_server


def _run_remote_stage(stage_name: str, servers: List[str], scanner_path: str,
                      targets: List[str], remote_cmd_builder, console: Console,
                      upload_slipstream: bool = False) -> List[str]:
    """Upload scanner + targets to servers, run command, download results.

    *remote_cmd_builder(remote_targets_path)* returns the remote command string.
    Returns merged result IPs.
    """
    import concurrent.futures

    # Split targets round-robin
    chunks = [[] for _ in servers]
    for i, t in enumerate(targets):
        chunks[i % len(servers)].append(t)

    all_results = []
    results_lock = threading.Lock()

    def run_on(spec, chunk):
        client = SSHClient.from_spec(spec)
        console.print(f"[cyan]{stage_name} on {spec} ({len(chunk)} targets)...[/cyan]")
        try:
            client.run("mkdir -p /tmp/dnstt_pipeline")
            client.upload(scanner_path, "/tmp/dnstt_pipeline/slipscan_cli_2n.py")

            # Upload slipstream-client binary if needed
            if upload_slipstream:
                local_bin = os.path.join(os.path.dirname(scanner_path), "bin", "slipstream-client")
                if os.path.exists(local_bin):
                    console.print(f"  [cyan]Uploading slipstream-client binary...[/cyan]")
                    client.upload(local_bin, "/tmp/dnstt_pipeline/slipstream-client")
                    client.run("chmod +x /tmp/dnstt_pipeline/slipstream-client")

            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(chunk) + "\n")
                tf_path = tf.name
            try:
                client.upload(tf_path, "/tmp/dnstt_pipeline/targets.txt")
            finally:
                os.unlink(tf_path)

            remote_cmd = remote_cmd_builder("/tmp/dnstt_pipeline/targets.txt")

            def on_line(line):
                console.print(f"  [{spec}] {line}")

            rc = client.run_streaming(remote_cmd, on_line)
            if rc != 0:
                console.print(f"[red]{stage_name} on {spec} exited {rc}[/red]")

            # Download result
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                local_result = tf.name
            try:
                client.download("/tmp/dnstt_pipeline/result_ok.txt", local_result)
                with open(local_result, "r") as f:
                    ips = [l.strip() for l in f if l.strip()]
                with results_lock:
                    all_results.extend(ips)
            except Exception:
                console.print(f"[yellow]No results from {spec}[/yellow]")
            finally:
                try:
                    os.unlink(local_result)
                except OSError:
                    pass
        finally:
            client.cleanup_remote("/tmp/dnstt_pipeline")

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(servers)) as pool:
        futs = []
        for spec, chunk in zip(servers, chunks):
            if chunk:
                futs.append(pool.submit(run_on, spec, chunk))
        for fut in concurrent.futures.as_completed(futs):
            try:
                fut.result()
            except Exception as exc:
                console.print(f"[red]Server error: {exc}[/red]")

    return all_results


def cmd_pipeline(args: argparse.Namespace) -> int:
    console = Console(stderr=True)

    # Read targets
    if not args.file:
        console.print("[red]ERROR: --file is required[/red]")
        return 2

    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        all_targets = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]

    if not all_targets:
        console.print("[red]ERROR: no targets found[/red]")
        return 2

    auth = tuple(args.auth.split(":", 1)) if args.auth else ("mat", "somethingelse")
    auth_str = f"{auth[0]}:{auth[1]}"
    scanner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "slipscan_cli_2n.py")

    scan_servers = args.scan_on
    realtest_servers = args.realtest_on
    deploy_servers = args.deploy_on

    # ---- Stage 1: Scan ----
    console.print("\n[bold cyan]== Stage 1: Scan ==[/bold cyan]")

    def scan_cmd_builder(remote_targets):
        return (
            f"sudo python3 /tmp/dnstt_pipeline/slipscan_cli_2n.py scan"
            f" --domain {shlex.quote(args.domain)}"
            f" --file {remote_targets}"
            f" --threads {args.scan_threads}"
            f" --timeout-ms {args.scan_timeout_ms}"
            f" --scan-ok-out /tmp/dnstt_pipeline/result_ok.txt"
            f" --stdout"
            f" --auth {shlex.quote(auth_str)}"
        )

    scan_ok = _run_remote_stage("Scan", scan_servers, scanner_path,
                                all_targets, scan_cmd_builder, console)

    console.print(f"[bold]Scan result: {len(scan_ok)} IPs passed[/bold]")
    if not scan_ok:
        console.print("[red]No IPs passed scan — stopping pipeline[/red]")
        return 1

    # ---- Stage 2: RealTest ----
    console.print("\n[bold cyan]== Stage 2: RealTest ==[/bold cyan]")

    def realtest_cmd_builder(remote_targets):
        return (
            f"sudo python3 /tmp/dnstt_pipeline/slipscan_cli_2n.py realtest"
            f" --domain {shlex.quote(args.domain)}"
            f" --file {remote_targets}"
            f" --slipstream-path /tmp/dnstt_pipeline/slipstream-client"
            f" --realtest-ok-out /tmp/dnstt_pipeline/result_ok.txt"
            f" --stdout"
            f" --auth {shlex.quote(auth_str)}"
        )

    realtest_ok = _run_remote_stage("RealTest", realtest_servers, scanner_path,
                                     scan_ok, realtest_cmd_builder, console,
                                     upload_slipstream=True)

    console.print(f"[bold]RealTest result: {len(realtest_ok)} IPs passed[/bold]")
    if not realtest_ok:
        console.print("[red]No IPs passed realtest — stopping pipeline[/red]")
        return 1

    # ---- Stage 3: Deploy ----
    console.print("\n[bold cyan]== Stage 3: Deploy ==[/bold cyan]")

    deploy_domain = args.deploy_domain or args.domain
    start_port = int(args.start_port)

    all_urls = []
    for spec in deploy_servers:
        try:
            urls = _deploy_to_server(
                spec, realtest_ok, deploy_domain, auth,
                start_port, "/usr/bin/slipstream-client", console,
            )
            all_urls.extend(urls)
        except Exception as exc:
            console.print(f"[red]Deploy failed on {spec}: {exc}[/red]")

    # ---- Summary ----
    console.print("\n[bold green]== Pipeline Complete ==[/bold green]")
    console.print(f"  Scanned: {len(all_targets)} targets")
    console.print(f"  Scan OK: {len(scan_ok)}")
    console.print(f"  RealTest OK: {len(realtest_ok)}")
    console.print(f"  Deployed to: {len(deploy_servers)} server(s)")

    if all_urls:
        console.print("\n[bold green]Proxy URLs:[/bold green]")
        for url in all_urls:
            console.print(f"  {url}")

    return 0


def add_subparser(subparsers) -> None:
    """Register the pipeline subcommand."""
    p = subparsers.add_parser("pipeline", help="Full pipeline: scan -> realtest -> deploy")
    p.add_argument("--file", required=True, help="Targets file")
    p.add_argument("--domain", required=True, help="DNS tunnel domain for scanning")
    p.add_argument("--scan-on", action="append", required=True, metavar="[USER@]HOST[:PORT]",
                   help="Server(s) for scanning (repeatable)")
    p.add_argument("--realtest-on", action="append", required=True, metavar="[USER@]HOST[:PORT]",
                   help="Server(s) for realtest (repeatable)")
    p.add_argument("--deploy-on", action="append", required=True, metavar="[USER@]HOST[:PORT]",
                   help="Server(s) for deployment (repeatable)")
    p.add_argument("--deploy-domain", default=None,
                   help="Domain for deployed units (defaults to --domain)")
    p.add_argument("--auth", default=None, help="SOCKS5 auth as USER:PASS (default: user:pass)")
    p.add_argument("--scan-threads", type=int, default=200)
    p.add_argument("--scan-timeout-ms", type=int, default=800)
    p.add_argument("--start-port", type=int, default=5200)
    p.set_defaults(func=cmd_pipeline)
