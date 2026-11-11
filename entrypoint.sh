#!/bin/sh
set -e

mkdir -p /root/.ssh
chmod 700 /root/.ssh

if [ -f /app/keys/id_ed25519.pub ]; then
  cat /app/keys/id_ed25519.pub > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi

if [ -f /app/keys/id_ed25519 ]; then
  cp /app/keys/id_ed25519 /root/.ssh/id_ed25519
  chmod 600 /root/.ssh/id_ed25519
fi

# Start internal container sshd on port 2222
/usr/sbin/sshd -p 2222

exec node /app/server.js
