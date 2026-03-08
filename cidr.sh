#!/usr/bin/env bash
#
# generate_subnets.sh
#
# Usage:
#   ./generate_subnets.sh 156.154.70.1/8 [output_file] [subnet_mask]
#
#   - 156.154.70.1/8          : base network (the IP part is ignored, only the mask matters)
#   - output_file             : optional – default is "subnets.txt"
#   - subnet_mask             : optional – /16 or /24 (default is /24)
#
# The script will write one CIDR per line, e.g.
#   156.1.70.1/16
#   156.2.70.1/16
#   ...
#

set -euo pipefail

#########################
## 1. Parse arguments
#########################
BASE_CIDR="${1:-}"
OUTPUT_FILE="${2:-subnets.txt}"
TARGET_MASK="${3:-24}"

# sanity checks
if [[ -z "$BASE_CIDR" ]]; then
    echo "Error: You must supply a base CIDR (e.g. 156.154.70.1/8)" >&2
    exit 1
fi

if ! [[ "$TARGET_MASK" =~ ^(16|24)$ ]]; then
    echo "Error: target mask must be /16 or /24" >&2
    exit 1
fi

# extract the network part and the mask of the base CIDR
IFS='/' read -r BASE_IP BASE_MASK <<<"$BASE_CIDR"

# Validate the IP (we only need it for readability; the mask decides the range)
if ! [[ "$BASE_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Error: Invalid IP address part in $BASE_CIDR" >&2
    exit 1
fi

# --------------------------------------------------------------
# Helper: convert dotted‑quad to a single integer (big‑endian)
# --------------------------------------------------------------
ip_to_int() {
    local IFS=.
    read -r a b c d <<<"$1"
    printf '%d' "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

# --------------------------------------------------------------
# Helper: convert integer back to dotted‑quad
# --------------------------------------------------------------
int_to_ip() {
    local ip=$1
    printf '%d.%d.%d.%d' \
        $(( (ip >> 24) & 255 )) \
        $(( (ip >> 16) & 255 )) \
        $(( (ip >> 8)  & 255 )) \
        $(( ip & 255 ))
}

# --------------------------------------------------------------
# 2. Determine the numeric range that the base CIDR covers
# --------------------------------------------------------------
BASE_NET_INT=$(ip_to_int "$BASE_IP")
MASK_BITS=$(( 32 - BASE_MASK ))
# The network address is the base IP ANDed with a mask of ones in the
# first BASE_MASK bits.
NET_MASK=$(( ~0 << MASK_BITS & 0xffffffff ))
BASE_NET_INT=$(( BASE_NET_INT & NET_MASK ))

# The first usable host inside the network is usually base+1,
# but for generating sub‑CIDRs we just need to iterate over the
# full address space of that network.
FIRST_ADDR=$BASE_NET_INT
LAST_ADDR=$(( BASE_NET_INT | (~NET_MASK & 0xffffffff) ))

# --------------------------------------------------------------
# 3. Generate the sub‑CIDRs
# --------------------------------------------------------------
echo "Generating /$TARGET_MASK subnets inside $BASE_CIDR ..."
> "$OUTPUT_FILE"

# Number of host bits in the target subnet
TARGET_HOST_BITS=$(( 32 - TARGET_MASK ))
# Number of subnets we will create = 2^(TARGET_HOST_BITS - (32-BASE_MASK))
SUBNET_COUNT=$(( 1 << (TARGET_HOST_BITS - (32 - BASE_MASK)) ))

# We can simply iterate over the first octet of the target mask
# (for /16 – 256 values, for /24 – 65536 values)
if [[ $TARGET_MASK -eq 16 ]]; then
    # /16: we vary the second octet (0‑255)
    for i in $(seq 0 255); do
        # Build the IP: A.i.C.D (C and D come from the base network)
        IFS='.' read -r a _ c d <<<"$BASE_IP"
        NEW_IP="$a.$i.$c.$d"
        echo "$NEW_IP/$TARGET_MASK" >>"$OUTPUT_FILE"
    done
elif [[ $TARGET_MASK -eq 24 ]]; then
    # /24: we vary the third octet (0‑255) and keep the last octet from base
    for i in $(seq 0 255); do
        IFS='.' read -r a b _ d <<<"$BASE_IP"
        NEW_IP="$a.$b.$i.$d"
        echo "$NEW_IP/$TARGET_MASK" >>"$OUTPUT_FILE"
    done
fi

echo "Done – $SUBNET_COUNT subnets written to $OUTPUT_FILE"