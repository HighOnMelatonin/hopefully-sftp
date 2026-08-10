#!/usr/bin/env bash
# tests/integration/test_cp2_transfer.sh
#
# Verifies full CP2 client/server with symmetric session key transfer.

set -euo pipefail #[cite: 5]

source ./tests/integration/_lib.sh #[cite: 5]
trap cleanup EXIT #[cite: 5]

SRC="files/file.txt"
DST="recv_files/recv_file.txt"

if [ ! -f "$SRC" ]; then
  echo "FAIL: fixture $SRC missing." #[cite: 5]
  exit 1
fi

reset_recv_files #[cite: 5]

./ServerWithSecurityCP2 "$PORT" localhost > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$! #[cite: 5]

for i in $(seq 1 50); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "ERROR: Server died before binding."
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
printf '%s\n-1\n' "$SRC" | timeout 10s ./ClientWithSecurityCP2 \
  "$PORT" localhost > "$LOG_DIR/client.log" 2>&1
CLIENT_RC=$? #[cite: 5]
set -e

for i in $(seq 1 20); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
  sleep 0.1
done

if [ "$CLIENT_RC" -ne 0 ]; then
  echo "FAIL: client exited with status $CLIENT_RC" #[cite: 5]
  dump_logs #[cite: 5]
  exit 1
fi

# Verify the session key exchange happened (Server receives type 4)
# In source 4, mode 4 triggers: "Receiving file..." before extraction, 
# but you might want to add a unique debug print in your server for "Session key received"
if ! grep -q "Connected" "$LOG_DIR/client.log"; then
  echo "FAIL: Client never reached Connected state"
  dump_logs
  exit 1
fi

if ! cmp -s "$SRC" "$DST"; then #[cite: 5]
  echo "FAIL: $DST differs from $SRC" #[cite: 5]
  dump_logs
  exit 1
fi

echo "PASS: CP2 Session Key exchange and file transfer successful"