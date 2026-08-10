#!/usr/bin/env bash
# tests/integration/test_ap_handshake.sh
#
# Verifies the AP handshake end-to-end: server proves its identity via a
# CA-signed cert + PSS signature over the client's random nonce, then a
# file transfers byte-for-byte afterward.
#
# Uses _lib.sh's reset_recv_files/dump_logs/cleanup, but starts the AP
# server manually (below) since _lib.sh's start_server() is hardcoded to
# ./ServerWithoutSecurity.

set -euo pipefail

source ./tests/integration/_lib.sh
trap cleanup EXIT

SRC="files/file.txt"
DST="recv_files/recv_file.txt"

if [ ! -f "$SRC" ]; then
  echo "FAIL: fixture $SRC missing."
  exit 1
fi

if [ ! -x ./ServerWithSecurityAP ] || [ ! -x ./ClientWithSecurityAP ]; then
  echo "ERROR: AP binaries not found. Run 'make AP' first."
  exit 1
fi

reset_recv_files

./ServerWithSecurityAP "$PORT" localhost > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

# Same bind-probe technique as _lib.sh's start_server(), just pointed at
# ServerWithSecurityAP instead of ServerWithoutSecurity.
for i in $(seq 1 50); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: AP server died before binding. Server log:"
    cat "$LOG_DIR/server.log"
    exit 1
  fi
  if python3 -c "
import socket, sys
s = socket.socket()
try:
    s.bind(('localhost', $PORT)); s.close(); sys.exit(1)
except OSError:
    sys.exit(0)
" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

set +e
printf '%s\n-1\n' "$SRC" | timeout 10s ./ClientWithSecurityAP \
  "$PORT" localhost > "$LOG_DIR/client.log" 2>&1
CLIENT_RC=$?
set -e

for i in $(seq 1 20); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
  sleep 0.1
done

if [ "$CLIENT_RC" -ne 0 ]; then
  echo "FAIL: client exited with status $CLIENT_RC"
  dump_logs
  exit 1
fi

if ! grep -q "^Connected$" "$LOG_DIR/client.log"; then
  echo "FAIL: client log shows no successful authentication"
  dump_logs
  exit 1
fi

if [ ! -f "$DST" ]; then
  echo "FAIL: expected destination $DST was not created"
  dump_logs
  exit 1
fi

if ! cmp -s "$SRC" "$DST"; then
  echo "FAIL: $DST differs from $SRC"
  dump_logs
  exit 1
fi

echo "PASS: AP handshake + file transfer"