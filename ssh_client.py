#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSH helper — wraps subprocess ssh/scp for remote command execution."""

import os
import shlex
import subprocess
from typing import Callable, List, Optional, Tuple


def parse_on(spec: str) -> Tuple[str, str, int]:
    """Parse ``[user@]host[:port]`` → (user, host, port).

    Defaults: user="root", port=22.
    """
    user = "root"
    host = spec
    port = 22

    if "@" in host:
        user, host = host.split("@", 1)

    if ":" in host:
        host, port_s = host.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            pass

    return user, host, port


class SSHClient:
    """Thin wrapper around the ``ssh`` / ``scp`` CLI."""

    SSH_OPTS = [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
    ]

    def __init__(self, host: str, user: str = "root", port: int = 22,
                 key: Optional[str] = None):
        self.host = host
        self.user = user
        self.port = port
        self.key = key

    # ---- internal helpers ---------------------------------------------------

    def _ssh_base(self) -> List[str]:
        cmd = ["ssh"] + self.SSH_OPTS + ["-p", str(self.port)]
        if self.key:
            cmd += ["-i", self.key]
        cmd.append(f"{self.user}@{self.host}")
        return cmd

    def _scp_base(self) -> List[str]:
        cmd = ["scp"] + self.SSH_OPTS + ["-P", str(self.port)]
        if self.key:
            cmd += ["-i", self.key]
        return cmd

    # ---- public API ---------------------------------------------------------

    def run(self, command: str) -> Tuple[str, str, int]:
        """Run *command* on the remote host, return (stdout, stderr, rc)."""
        cmd = self._ssh_base() + [command]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.stdout, proc.stderr, proc.returncode

    def upload(self, local_path: str, remote_path: str) -> None:
        """Upload a local file to the remote host via ``scp``."""
        cmd = self._scp_base() + [local_path,
                                   f"{self.user}@{self.host}:{remote_path}"]
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    def download(self, remote_path: str, local_path: str) -> None:
        """Download a remote file to the local machine via ``scp``."""
        cmd = self._scp_base() + [f"{self.user}@{self.host}:{remote_path}",
                                   local_path]
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    def run_streaming(self, command: str,
                      line_callback: Optional[Callable[[str], None]] = None
                      ) -> int:
        """Run *command* on the remote host, calling *line_callback* for every
        stdout line in real-time.  Returns the process exit code."""
        cmd = self._ssh_base() + [command]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            if proc.stdout:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if line_callback:
                        line_callback(line)
        finally:
            proc.wait()
        return proc.returncode

    def cleanup_remote(self, pattern: str = "/tmp/dnstt_*") -> None:
        """Remove temporary files on the remote host (best-effort)."""
        self.run(f"sudo rm -rf {shlex.quote(pattern)}")

    # ---- convenience --------------------------------------------------------

    @classmethod
    def from_spec(cls, spec: str, key: Optional[str] = None) -> "SSHClient":
        """Create an :class:`SSHClient` from a ``[user@]host[:port]`` string."""
        user, host, port = parse_on(spec)
        return cls(host, user=user, port=port, key=key)

    def __repr__(self) -> str:
        return f"SSHClient({self.user}@{self.host}:{self.port})"
