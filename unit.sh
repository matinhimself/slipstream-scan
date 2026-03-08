#!/usr/bin/env bash
#
#  create_slipstream_units.sh
#
#  Split a source file that contains one IP per line into individual
#  directories and create a systemd service unit for each entry.
#
#  Usage:
#     sudo ./create_slipstream_units.sh <source_file>
#
#  The source file can contain comments (# …) and empty lines –
#  they are ignored.
#
set -euo pipefail

SRC_FILE=${1:-}
if [[ ! -r "$SRC_FILE" ]]; then
    echo "❌  Cannot read source file: $SRC_FILE"
    exit 1
fi

# --------------------------------------------------------------------------
# Configuration – change these if you want a different layout
BASE_DIR="/etc/slipservers/ip"              # where the IP files live
UNIT_DIR="/etc/systemd/system"               # systemd unit dir (default)
START_PORT=5200                              # first listening port
SERVICE_TEMPLATE="slipstream-client"         # base name of the unit

# --------------------------------------------------------------------------
# 1. Make sure the base directory exists
mkdir -p "$BASE_DIR"

# --------------------------------------------------------------------------
# 2. Count usable lines (skip empty & comment lines)
LINE_COUNT=$(grep -vE '^\s*#|^\s*$' "$SRC_FILE" | wc -l)
echo "📄  $LINE_COUNT usable lines found in $SRC_FILE"

# --------------------------------------------------------------------------
# 3. Process each line
i=1          # counter for directories & units
port=$START_PORT

# read the file line‑by‑line, ignoring comments/blank lines
while IFS= read -r raw_line || [[ -n $raw_line ]]; do
    # skip comments or empty lines
    if [[ "$raw_line" =~ ^\s*# || -z $raw_line ]]; then
        continue
    fi

    # 3a. Clean up the line (trim whitespace)
    ip=$(echo "$raw_line" | awk '{print $1}' | xargs)

    # 3b. Create destination directory and write the IP
    DEST_DIR="$BASE_DIR/$i"
    mkdir -p "$DEST_DIR"
    printf '%s\n' "$ip" >"$DEST_DIR/common-ips-real.txt"

    # 3c. Create the systemd unit file
    UNIT_NAME="${SERVICE_TEMPLATE}-${i}.service"
    UNIT_FILE="$UNIT_DIR/$UNIT_NAME"

    cat >"$UNIT_FILE" <<EOF
[Unit]
Description=SlipStream client for $ip
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/slipstream-client \
    --resolver $ip:53 \
    --domain your.domain.com -l $port

# Minimal capabilities: raw sockets only
CapabilityBoundingSet = CAP_NET_RAW
AmbientCapabilities   = CAP_NET_RAW
Restart=always          # always bring it back up if it dies

[Install]
WantedBy=multi-user.target
EOF

    echo "✅  Created $UNIT_FILE (listening on port $port)"
    ((i++))
    ((port++))

done < "$SRC_FILE"

# --------------------------------------------------------------------------
# 4. Reload systemd and enable all units
echo "📦  Reloading systemd daemon…"
systemctl daemon-reload

# Enable each unit (so it starts on boot)
for j in $(seq 1 $((i-1))); do
    unit="${SERVICE_TEMPLATE}-${j}.service"
    systemctl enable "$unit" &>/dev/null || true
    echo "🟢  Enabled $unit"
    systemctl start "$unit" &>/dev/null || true
    echo "🟢  Started $unit"
done
systemctl daemon-reload

# Enable each unit (so it starts on boot)
port=$START_PORT
for j in $(seq 1 $((i-1))); do
    hostip=$(hostname -i | awk '{print $1}')
    echo "socks5://username:password@$hostip:$port#slip-$port"
    echo "tg://socks?server=$hostip&port=$port&user=username&pass=password"
    ((port++))
done
echo "🎉  All done – $((i-1)) services created and enabled."