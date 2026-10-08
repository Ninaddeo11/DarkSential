#!/bin/sh
# Lab client entrypoint (runs as root with a handful of capabilities):
# 1. lock routing: the gateway is the ONLY on-link neighbour. Everything else,
#    other devices and the Docker host bridge (.1) included, has to cross the
#    gateway, which captures it and forwards only device <-> broker traffic;
# 2. copy this client's credentials + the lab CA into a tmpfs readable only by the
#    lab user (the bind-mounted secrets are host-owned 0600);
# 3. drop root and every capability (so the routes can't be changed), then run.
set -eu
GW="${DSN_LAB_GATEWAY:?DSN_LAB_GATEWAY must be set}"
DEV="$(ip -o route get "$GW" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
NET="$(ip -o -4 route show dev "$DEV" proto kernel scope link | awk '{print $1}')"
ip route replace "$GW/32" dev "$DEV" scope link
ip route replace default via "$GW" dev "$DEV"
[ -z "$NET" ] || ip route del "$NET" dev "$DEV"
install -d -o 10001 -g 10001 -m 0700 /tmp/lab
install -o 10001 -g 10001 -m 0400 /run/lab-src/client.json /tmp/lab/client.json
install -o 10001 -g 10001 -m 0444 /run/lab-src/ca.crt /tmp/lab/ca.crt
export DSN_LAB_CREDENTIALS=/tmp/lab/client.json DSN_LAB_CA=/tmp/lab/ca.crt
exec setpriv --reuid=10001 --regid=10001 --clear-groups \
  --inh-caps=-all --bounding-set=-all --no-new-privs \
  python -m app.lab "$@"
