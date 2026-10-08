#!/bin/sh
# Virtual lab gateway: the DSN backend container routes between the lab device
# network and the lab services network (broker), captures that traffic, and
# enforces quarantine with nftables. Fails closed: if the egress lock can't be
# installed, the container does not start.
set -eu
DEVICES="${DSN_LAB_DEVICE_NET:-10.77.1.0/24}"
SERVICES="${DSN_LAB_SERVICE_NET:-10.77.2.0/24}"

# Egress lock: lab traffic may only move between the two lab subnets. Anything
# else (e.g. a beacon to a public C2 address) is captured on ingress, then dropped.
nft -f - <<EOF
add table inet dsn_lab
delete table inet dsn_lab
table inet dsn_lab {
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr $DEVICES ip daddr $SERVICES accept
    ip saddr $SERVICES ip daddr $DEVICES accept
    ip saddr $DEVICES drop
    ip daddr $DEVICES drop
  }
}
EOF

# Capture on the interface that faces the devices.
IFACE="$(ip -o -4 addr show | awk -v ip="${DSN_LAB_GATEWAY_IP:-10.77.1.2}" '$4 ~ "^"ip"/" {print $2}')"
[ -n "$IFACE" ] || { echo "lab gateway: no interface with ${DSN_LAB_GATEWAY_IP:-10.77.1.2}" >&2; exit 1; }
export DSN_PASSIVE_CAPTURE_IFACE="$IFACE"

# Run the app as the unprivileged dsn user, keeping only NET_ADMIN (firewall) and
# NET_RAW (capture, nmap) as ambient capabilities; 1883 = broker-log reader group.
exec setpriv --reuid=dsn --regid=dsn --groups=1883 \
  --inh-caps=-all,+net_admin,+net_raw --ambient-caps=-all,+net_admin,+net_raw \
  --bounding-set=-all,+net_admin,+net_raw \
  python -m app
