#!/usr/bin/env bash
# tests/integration/test_cp1_encryption_verify.sh
#
# Confirms CP1 actually encrypts file data before sending it — not just
# that the file round-trips correctly. Complements test_cp1_transfer.sh.

set -euo pipefail

source ./tests/integration/_lib.sh
trap cleanup EXIT

SRC="files/file.txt"

if [ ! -f "$SRC" ]; then
  echo "FAIL: fixture $SRC missing."
  exit 1
fi

reset_recv_files
rm -f "send_files_enc/enc_file.txt"

./ServerWithSecurityCP1 "$PORT" localhost > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

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
printf '%s\n-1\n' "$SRC" | timeout 10s ./ClientWithSecurityCP1 \
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

if [ ! -f "send_files_enc/enc_file.txt" ]; then
  echo "FAIL: encrypted file not saved to send_files_enc/"
  dump_logs
  exit 1
fi

if cmp -s "$SRC" "send_files_enc/enc_file.txt"; then
  echo "FAIL: send_files_enc/enc_file.txt is identical to plaintext — file was not encrypted"
  dump_logs
  exit 1
fi

echo "PASS: CP1 encryption verified — send_files_enc/enc_file.txt differs from plaintext"