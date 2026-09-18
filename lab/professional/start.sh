#!/bin/sh
set -eu
mkdir -p /run/sshd /root/.ssh
chmod 700 /root/.ssh
ssh-keygen -A
python /app/lab/server.py &
python /app/lab/professional/dns_server.py &
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o PermitRootLogin=prohibit-password -o AllowTcpForwarding=no -o PermitTunnel=no
