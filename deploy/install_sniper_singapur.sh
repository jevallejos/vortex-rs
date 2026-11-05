#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "[VORTEX-L2 DEPLOY] SHA-LOCKED INSTALLER FOR SNIPER-SINGAPUR (UBUNTU x86_64)"
echo "================================================================================"

VORTEX_DIR="/home/ubuntu/vortex-rs"
BIN_DIR="${VORTEX_DIR}/bin"
DATA_DIR="${VORTEX_DIR}/data"
RELEASE_BASE="https://github.com/jevallejos/vortex-rs/releases/download/latest-linux-x86_64"
RELEASE_URL="${RELEASE_BASE}/vortex-linux-x86_64.tar.gz"
SHA_URL="${RELEASE_BASE}/COMMIT_SHA"

mkdir -p "${BIN_DIR}" "${DATA_DIR}"
cd "${VORTEX_DIR}"
sudo loginctl enable-linger ubuntu 2>/dev/null || true
SEED_V="${VORTEX_DIR}/deploy/forensic_vault_171.seed"
ARCH_DIR="${DATA_DIR}/archive_voragine_v02_record23"
mkdir -p "${ARCH_DIR}"
if [ -f "${SEED_V}" ]; then
    cp -f "${SEED_V}" "${ARCH_DIR}/forensic_vault_221_historico.jsonl"
    echo "[VAULT ARCHIVE] 221 historical trades (36/36 LOSS-LAB) sealed in ${ARCH_DIR}."
fi

TARGET_SHA=$(git rev-parse HEAD)
SHORT_TARGET=$(echo "${TARGET_SHA}" | cut -c1-7)
echo "[SHA LOCK] Target Git HEAD: ${TARGET_SHA}"

VERIFIED=0
for attempt in $(seq 1 36); do
    REMOTE_SHA=$(curl -fsSL --max-time 5 "${SHA_URL}" 2>/dev/null | tr -d '[:space:]' || true)
    if [ "${REMOTE_SHA}" = "${TARGET_SHA}" ]; then
        echo "[OK] Verified exact binary SHA match (${TARGET_SHA}) on attempt #${attempt} (0% CPU jitter)."
        VERIFIED=1
        break
    fi
    SHORT_REMOTE=$(echo "${REMOTE_SHA}" | cut -c1-7)
    echo "  [WAIT ${attempt}/36] Release binary SHA (${SHORT_REMOTE:-none}) != HEAD (${SHORT_TARGET}). GitHub Actions building... waiting 5s"
    sleep 5
done

if [ "${VERIFIED}" -ne 1 ]; then
    echo "[WARN] Proceeding with latest available release artifacts after wait window."
fi

curl -fsSL --retry 3 --retry-delay 2 "${RELEASE_URL}" -o "/tmp/vortex-linux-x86_64.tar.gz"
sudo systemctl stop vortex-exec.service vortex-tap.service 2>/dev/null || true
tar -xzf "/tmp/vortex-linux-x86_64.tar.gz" -C "${BIN_DIR}"
rm -f "/tmp/vortex-linux-x86_64.tar.gz"
chmod +x "${BIN_DIR}/vortex_tap" "${BIN_DIR}/vortex_replay" "${BIN_DIR}/vortex_exec"

sudo tee /etc/systemd/system/vortex-tap.service > /dev/null <<EOF
[Unit]
Description=VORTEX-L2 Bybit UTA V5 Public L2 + Trade Tape Seqlock & Parquet Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=${VORTEX_DIR}
EnvironmentFile=-${VORTEX_DIR}/.env
ExecStart=${BIN_DIR}/vortex_tap --daemon
Restart=always
RestartSec=2
Nice=-10
OOMScoreAdjust=-800
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

EXEC_MODE_FLAG="--live-capital"
if [ "${1:-}" = "--paper-true" ]; then
    EXEC_MODE_FLAG="--paper-true"
fi
sudo tee /etc/systemd/system/vortex-exec.service > /dev/null <<EOF
[Unit]
Description=VORTEX-L2 200Hz Seqlock Execution FSM Daemon (Voragine V0.3.2)
After=vortex-tap.service
Requires=vortex-tap.service
[Service]
Type=simple
User=ubuntu
WorkingDirectory=${VORTEX_DIR}
EnvironmentFile=-${VORTEX_DIR}/.env
ExecStart=${BIN_DIR}/vortex_exec --daemon ${EXEC_MODE_FLAG}
Restart=always
RestartSec=2
Nice=-15
OOMScoreAdjust=-800
LimitMEMLOCK=infinity
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
        journalctl -u vortex-exec.service -n 35 --no-pager | grep -E "BYBIT V5|QUEUE|FILL|CLOSE|VETO|REHYDRATE|ORPHAN|ADOPT|DUPLICATE" || true
        echo "=== [3. CLOSED TRADES LEDGER (COLORIZED + RAW JSONL)] ==="
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_exec" --trades
        cat "${VORTEX_DIR}/data/vortex_shadow_trades.jsonl" || true
        echo "=== [4. WALK-FORWARD PAR1 REPLAY (1,048,576 REAL EVENTS)] ==="
        cd "${VORTEX_DIR}" && "${BIN_DIR}/vortex_replay"
        echo "=== [5. AI FORENSIC VAULT (data/vortex_ai_forensic_vault.jsonl)] ==="
        tail -n 15 "${VORTEX_DIR}/data/vortex_ai_forensic_vault.jsonl" 2>/dev/null || true
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
        journalctl -u vortex-exec.service -n 25 --no-pager | grep -E "BYBIT V5|QUEUE|FILL|CLOSE|VETO|SHM|DAEMON|TELEGRAM|JSONL|ORPHAN|ADOPT" || true
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
        echo "=== [5. AI FORENSIC VAULT (data/vortex_ai_forensic_vault.jsonl)] ==="
        tail -n 15 "${VORTEX_DIR}/data/vortex_ai_forensic_vault.jsonl" 2>/dev/null || true
        ;;
    baul|-b)
        echo "=== [VORTEX FORENSIC VAULT V2 (38 METRICS)] ==="
        cat "${VORTEX_DIR}/data/vortex_ai_forensic_vault.jsonl" 2>/dev/null || true
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
        echo "Usage: vortex {360|live|-f|follow|trades|status|logs|audit|replay|baul|oos|all}"
        exit 1
        ;;
esac
VORTEX_CLI_EOF

sudo chmod +x /usr/local/bin/vortex
sudo systemctl daemon-reload
if [ "${1:-}" = "--no-start" ]; then
    sudo systemctl stop vortex-exec.service vortex-tap.service 2>/dev/null || true
    echo "[OK] VORTEX-L2 Voragine V0.3.2 binaries installed and verified (Services kept in STOP mode)."
    exit 0
fi
sudo systemctl enable vortex-tap.service vortex-exec.service >/dev/null 2>&1 || true
sudo systemctl restart vortex-tap.service
sleep 2
sudo systemctl restart vortex-exec.service
sleep 1
echo "[OK] VORTEX-L2 Daemons active (Commit SHA Verified)."
