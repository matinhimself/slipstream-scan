# Slipstream Scan

A unified CLI tool for scanning, testing, and deploying DNS tunnel-based SOCKS5 proxies using Slipstream. Supports distributed scanning across multiple remote servers via SSH.

## Features

- **Fast UDP/53 Scanning**: Parallel scanning of IP ranges for DNS tunnel availability
- **RealTest Validation**: Verify working tunnels via actual SOCKS5 connectivity tests
- **Remote Execution**: Run scans and tests on remote servers via SSH
- **Distributed Testing**: Test IPs from multiple server locations simultaneously
- **Load Balancer Deployment**: Deploy HAProxy load balancers in multiple modes
- **Result Management**: Automatic result merging and deduplication
- **Rich UI**: Interactive progress dashboard with real-time statistics

## Installation

```bash
# Clone the repository
git clone https://github.com/matinhimself/slipstream-scan.git
cd slipstream-scan

# Install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### Basic Local Scan

```bash
# Scan a single IP
python3 dnstt.py scan --domain your.domain.com --targets 8.8.8.8

# Scan CIDR ranges
python3 dnstt.py scan --domain your.domain.com \
  --targets 46.38.143.0/24 94.183.150.0/24 \
  --threads 200
```

### Remote Distributed Scanning

```bash
# Scan from multiple servers (IPs split across servers)
python3 dnstt.py scan --domain your.domain.com \
  --targets 46.38.143.0/24 94.183.150.0/24 \
  --on ubuntu@server1.com \
  --on ubuntu@server2.com
```

### RealTest Validation

```bash
# Test IPs locally
python3 dnstt.py realtest --domain your.domain.com \
  --file results/scan_ok.txt \
  --auth username:password

# Test from remote servers (split mode)
python3 dnstt.py realtest --domain your.domain.com \
  --file results/scan_ok.txt \
  --on ubuntu@server1.com \
  --on ubuntu@server2.com \
  --auth username:password

# Test from multiple locations (each server tests ALL IPs)
python3 dnstt.py realtest --domain your.domain.com \
  --file results/scan_ok.txt \
  --test-from ubuntu@server1.com \
  --test-from ubuntu@server2.com \
  --auth username:password
```

### Deployment

```bash
# Deploy slipstream clients
python3 dnstt.py deploy \
  --file results/realtest_ok.txt \
  --on root@production.server.com \
  --domain your.domain.com \
  --auth username:password \
  --start-port 5200

# Deploy HAProxy load balancer (tunnel mode)
python3 dnstt.py deploy-lb \
  --mode tunnel-lb \
  --on root@production.server.com \
  --dns-resolver 46.38.143.236 \
  --dns-resolver 94.183.150.10 \
  --domain your.domain.com \
  --auth username:password \
  --lb-port 6200
```

## Command Reference

### `scan` - Fast IP Scanning

Scan IP addresses or CIDR ranges for DNS tunnel availability.

**Arguments:**
- `--domain DOMAIN` - Domain for DNS tunneling (required)
- `--targets IP [IP ...]` - Target IPs or CIDR ranges
- `--file FILE` - File containing targets (one per line)
- `--threads N` - Number of parallel threads (default: 200)
- `--timeout-ms MS` - Timeout in milliseconds (default: 1000)
- `--result-dir DIR` - Result directory (default: results/)
- `--on [USER@]HOST[:PORT]` - Run on remote server(s) via SSH
- `--auth USER:PASS` - SOCKS5 authentication credentials

**Examples:**
```bash
# Local scan
python3 dnstt.py scan --domain your.domain.com --targets 8.8.8.8 1.1.1.1

# CIDR scan with file input
python3 dnstt.py scan --domain your.domain.com --file ip-ranges.txt

# Remote distributed scan
python3 dnstt.py scan --domain your.domain.com \
  --targets 46.38.143.0/24 \
  --on ubuntu@server1 --on ubuntu@server2
```

### `realtest` - SOCKS5 Validation

Test IPs for actual SOCKS5 tunnel connectivity.

**Arguments:**
- `--domain DOMAIN` - Domain for DNS tunneling (required)
- `--file FILE` - File containing IPs to test
- `--auth USER:PASS` - SOCKS5 authentication (required)
- `--ready-timeout-ms MS` - Tunnel ready timeout (default: 20000)
- `--timeout-s SEC` - Test timeout in seconds (default: 25.0)
- `--result-dir DIR` - Result directory (default: results/)
- `--on [USER@]HOST[:PORT]` - Run on remote server(s), split IPs
- `--test-from [USER@]HOST[:PORT]` - Test from server(s), each tests ALL IPs

**Examples:**
```bash
# Local realtest
python3 dnstt.py realtest --domain your.domain.com \
  --file results/scan_ok.txt \
  --auth username:password

# Test from multiple locations (parallel, full list)
python3 dnstt.py realtest --domain your.domain.com \
  --file results/scan_ok.txt \
  --test-from ubuntu@us-server \
  --test-from ubuntu@eu-server \
  --auth username:password
```

**Result Files:**
- Local: `results/realtest_ok.txt`
- Remote (--test-from): `results/realtest_ok_{server_ip}.txt` per server

### `deploy` - Deploy Slipstream Clients

Deploy slipstream-client services on remote servers.

**Arguments:**
- `--file FILE` - File containing validated IPs
- `--on [USER@]HOST[:PORT]` - Target server(s) for deployment
- `--domain DOMAIN` - Domain for DNS tunneling (required)
- `--auth USER:PASS` - SOCKS5 authentication (required)
- `--start-port PORT` - Starting port number (default: 5200)

**Example:**
```bash
python3 dnstt.py deploy \
  --file results/realtest_ok.txt \
  --on root@prod.server.com \
  --domain tunnel.example.com \
  --auth username:password \
  --start-port 5200
```

### `deploy-lb` - Deploy HAProxy Load Balancer

Deploy HAProxy load balancer in various modes.

**Modes:**
- `socks-lb` - Load balance across SOCKS5 backends
- `multi-fe` - Multiple DNS frontends to shared resolver pool
- `tunnel-lb` - SOCKS frontend to multiple local tunnel backends

**Arguments:**
- `--mode MODE` - Load balancer mode (required)
- `--on [USER@]HOST[:PORT]` - Target server for deployment
- `--domain DOMAIN` - Domain for DNS tunneling
- `--auth USER:PASS` - SOCKS5 authentication
- `--lb-port PORT` - Load balancer listen port
- `--dns-resolver IP` - DNS resolver IP (repeatable)

**Examples:**
```bash
# Tunnel-lb mode (recommended)
python3 dnstt.py deploy-lb \
  --mode tunnel-lb \
  --on root@prod.server.com \
  --dns-resolver 46.38.143.236 \
  --dns-resolver 94.183.150.10 \
  --domain tunnel.example.com \
  --auth username:password \
  --lb-port 6200

# SOCKS-lb mode
python3 dnstt.py deploy-lb \
  --mode socks-lb \
  --on root@prod.server.com \
  --socks-backend 10.0.0.1:5200 \
  --socks-backend 10.0.0.2:5200 \
  --lb-port 6000
```

### `pipeline` - Automated Scan → Test → Deploy

Run the complete workflow automatically.

**Example:**
```bash
python3 dnstt.py pipeline \
  --file ip-ranges.txt \
  --domain tunnel.example.com \
  --scan-on ubuntu@scanner1 \
  --realtest-on ubuntu@tester1 \
  --deploy-on root@production \
  --deploy-domain prod.example.com \
  --auth username:password
```

### `servers test` - Test SSH Connectivity

Quick SSH connectivity test for remote servers.

**Example:**
```bash
python3 dnstt.py servers test ubuntu@server1.com root@server2.com
```

## Result Directory System

Results are automatically saved and merged in the `results/` directory (configurable with `--result-dir`).

**Scan Results:**
- Local/Remote: `results/scan_ok.txt` - All working IPs merged

**RealTest Results:**
- Local: `results/realtest_ok.txt`
- Remote (--test-from): `results/realtest_ok_{server_ip}.txt` - Per server

Results are deduplicated and sorted automatically across multiple runs.

## Remote Execution

The tool supports remote execution via SSH for scanning and testing. Ensure:

1. SSH key-based authentication is configured
2. Remote servers have Python 3 installed
3. User has sudo access (required for raw socket operations)
4. Required binaries are in `bin/` directory locally (auto-uploaded)

## Differences: `--on` vs `--test-from`

For `realtest` command:

**`--on` (Split Mode)**
- Splits IP list round-robin across servers
- Each server tests a subset of IPs
- Single merged result file
- Use when: Faster testing, don't need location-specific results

**`--test-from` (Parallel Full Mode)**
- Each server tests ALL IPs
- Servers run in parallel
- Separate result file per server (with server IP in filename)
- Use when: Testing from different locations/regions, want to know which IPs work where

## Tips

1. **Scanning**: Start with broader scans (`--threads 200 --timeout-ms 1000`) then narrow down
2. **RealTest**: Use `--test-from` to verify IPs work from deployment location
3. **Deployment**: Deploy on the same server where realtest succeeded
4. **Timeouts**: Increase `--ready-timeout-ms` and `--timeout-s` for unstable networks
5. **Load Balancing**: Use `tunnel-lb` mode for best performance and reliability

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Credits

Special thanks to [Slipstreamplus-CLI](https://github.com/payeh/Slipstreamplus-CLI.git) project for the original scanner implementation.

Enhanced with Claude Code
