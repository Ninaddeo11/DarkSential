#!/bin/sh
# Install broker secrets with the ownership/permissions Mosquitto requires
# (future versions refuse world-readable or foreign-owned password/ACL files),
# then start the broker. Sources are mounted read-only at /mosquitto/src.
set -eu
install -d -o mosquitto -g mosquitto -m 0700 /mosquitto/secure
for f in passwd acl; do
  install -o mosquitto -g mosquitto -m 0600 "/mosquitto/src/$f" /mosquitto/secure/
done
for f in ca.crt server.crt server.key; do
  install -o mosquitto -g mosquitto -m 0600 "/mosquitto/src/certs/$f" /mosquitto/secure/
done
mkdir -p /mosquitto/log /mosquitto/data
chown -R mosquitto:mosquitto /mosquitto/log /mosquitto/data
# Mosquitto creates its log itself; umask 022 keeps it readable by the DSN backend
# (it contains client ids/IPs/topics, no secrets).
umask 022
exec /usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf
