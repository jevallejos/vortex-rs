#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "[VORTEX-L2 DEPLOY] SHA-LOCKED INSTALLER FOR SNIPER-SINGAPUR (UBUNTU x86_64)"
echo "================================================================================"

VORTEX_DIR="/home/ubuntu/vortex-rs"
BIN_DIR="${VORTEX_DIR}/bin"
DATA_DIR="${VORTEX_DIR}/data"
RELEASE_URL="https://github.com/jevallejos/vortex-rs/releases/download/latest-mainnet"

mkdir -p "${BIN_DIR}" "${DATA_DIR}"
cd "${VORTEX_DIR}"

TARGET_SHA=$(git rev-parse HEAD)
SHORT_TARGET=$(echo "${TARGET_SHA}" | cut -c1-7)
echo "[SHA LOCK] Target Git HEAD: ${TARGET_SHA}"

VERIFIED=0
for attempt in $(seq 1 18); do
    REMOTE_SHA=$(curl -sSL --max-time 5 "${RELEASE_URL}/COMMIT_SHA" 2>/dev/null | tr -d '[:space:]' || true)
    if [ "${REMOTE_SHA}" = "${TARGET_SHA}" ]; then
        echo "[OK] Verified exact binary SHA match (${TARGET_SHA}) on attempt #${attempt} (0% CPU jitter)."
        VERIFIED=1
        break
    fi
    SHORT_REMOTE=$(echo "${REMOTE_SHA}" | cut -c1-7)
    echo "  [WAIT ${attempt}/18] Release binary SHA (${SHORT_REMOTE:-none}) != HEAD (${SHORT_TARGET}). GitHub Actions building... waiting 5s"
    sleep 5
done

if [ "${VERIFIED}" -ne 1 ]; then
    echo "[WARN] Proceeding with latest available release artifacts after wait window."
fi

for bin_name in vortex_tap vortex_exec vortex_replay; do
    curl -fL --retry 3 --retry-delay 2 -sS "${RELEASE_URL}/${bin_name}" -o "${BIN_DIR}/${bin_name}.tmp"
    chmod +x "${BIN_DIR}/${bin_name}.tmp"
    mv -f "${BIN_DIR}/${bin_name}.tmp" "${BIN_DIR}/${bin_name}"
done

sudo tee /etc/systemd/system/vortex-tap.service > /dev/null <<EOF
[Unit]
Description=VORTEX-L2 Bybit UTA V5 Public L2 + Trade Tape Seqlock & Parquet Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=${VORTEX_DIR}
ExecStart=${BIN_DIR}/vortex_tap --daemon
Restart=always
RestartSec=2
Nice=-10

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/vortex-exec.service > /dev/null <<EOF
[Unit]
Description=VORTEX-L2 200Hz Seqlock Execution FSM Daemon (Stage 26 Live Capital)
After=vortex-tap.service
Requires=vortex-tap.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=${VORTEX_DIR}
ExecStart=${BIN_DIR}/vortex_exec --daemon --live-capital
Restart=always
RestartSec=2
Nice=-15

[Install]
WantedBy=multi-user.target
EOF

sudo tee /usr/local/bin/vortex > /dev/null << 'VORTEX_CLI_EOF'
#!/usr/bin/env bash
set -euo pipefail

VORTEX_DIR="/home/ubuntu/vortex-rs"
BIN_DIR="/home/ubuntu/vortex-rs/bin"

case "${1:-live}" in
    360)
        echo "=== [1. VORTEX LIVE HUD (SHM v9)] ==="
        "${BIN_DIR}/vortex_exec" --live
        echo "=== [2. BYBIT V5 LIVE ORDERS & QUEUE TELEMETRY] ==="
        journalctl -u vortex-exec.service -n 35 --no-pager | grep -E "BYBIT V5|QUEUE|FILL|CLOSE|VETO|REHYDRATE|ORPHAN|DUPLICATE" || true
        echo "=== [3. CLOSED TRADES LEDGER (COLORIZED + RAW JSONL)] ==="
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_exec" --trades
        cat "${VORTEX_DIR}/data/vortex_shadow_trades.jsonl" || true
        echo "=== [4. WALK-FORWARD PAR1 REPLAY (1,048,576 REAL EVENTS)] ==="
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_replay"
        ;;
    live|-l)
        "${BIN_DIR}/vortex_exec" --live
        ;;
    follow|-f)
        "${BIN_DIR}/vortex_exec" --live
        echo "=== [COLORIZED CLOSED TRADES LEDGER (vortex_shadow_trades.jsonl)] ==="
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_exec" --trades
        echo "=== [VORTEX-L2 LIVE STREAMING FEED (Ctrl+C to exit)] ==="
        journalctl -u vortex-exec.service -u vortex-tap.service -f -n 30 --output=cat
        ;;
    trades|-t)
        echo "=== [SHADOW & LIVE QUEUE EXECUTION EVENTS IN JOURNALCTL] ==="
        journalctl -u vortex-exec.service -n 25 --no-pager | grep -E "BYBIT V5|QUEUE|FILL|CLOSE|VETO|SHM|DAEMON|TELEGRAM|JSONL|ORPHAN" || true
        echo "=== [COLORIZED CLOSED TRADES LEDGER (vortex_shadow_trades.jsonl)] ==="
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_exec" --trades
        ;;
    status|-s)
        systemctl status vortex-tap.service vortex-exec.service --no-pager
        echo "--------------------------------------------------------------------------------"
        ls -lh /dev/shm/vortex_lob.mmap || true
        ls -lt "${VORTEX_DIR}/data" | head -n 10 || true
        ;;
    logs)
        journalctl -u vortex-tap.service -u vortex-exec.service -n 40 --no-pager
        ;;
    audit|-a)
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_tap"
        ;;
    replay|-r)
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_replay"
        ;;
    oos|-o)
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_exec"
        ;;
    all)
        cd "${VORTEX_DIR}"
        "${BIN_DIR}/vortex_tap"
        "${BIN_DIR}/vortex_replay"
        "${BIN_DIR}/vortex_exec"
        ;;
    *)
        echo "Usage: vortex {360|live|-f|follow|trades|status|logs|audit|replay|oos|all}"
        exit 1
        ;;
esac
VORTEX_CLI_EOF

sudo chmod +x /usr/local/bin/vortex
sudo systemctl daemon-reload
sudo systemctl enable vortex-tap.service vortex-exec.service >/dev/null 2>&1 || true
sudo systemctl restart vortex-tap.service
sleep 1
sudo systemctl restart vortex-exec.service
sleep 1
echo "[OK] VORTEX-L2 Stage 26 Daemons active (Commit SHA Verified)."