#!/bin/sh
set -eu
mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1
/usr/sbin/sshd -o PermitRootLogin=no -o PasswordAuthentication=no
exec python /app/lab/server.py
