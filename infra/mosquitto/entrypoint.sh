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
# The DSN backend tails the log (client ids/IPs/topics, no secrets). Mosquitto
# creates files 0600 itself, so pre-create it group-readable. The reader joins
# LOG_READER_GID: default is the mosquitto group (1883), which the broker accepts
# without warnings (compose: backend group_add 1883). Existing logs are kept.
LOG_GID="${LOG_READER_GID:-mosquitto}"
LOG=/mosquitto/log/mosquitto.log
[ -f "$LOG" ] || install -m 0640 /dev/null "$LOG"
chown "mosquitto:$LOG_GID" /mosquitto/log "$LOG"
chmod 0750 /mosquitto/log
chmod 0640 "$LOG"
exec /usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf
