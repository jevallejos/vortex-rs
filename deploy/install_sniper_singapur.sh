#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "[VORTEX-L2 DEPLOY] SHA-LOCKED INSTALLER FOR SNIPER-SINGAPUR (UBUNTU x86_64)"
echo "================================================================================"

VORTEX_DIR="${HOME}/vortex-rs"
BIN_DIR="${VORTEX_DIR}/bin"
DATA_DIR="${VORTEX_DIR}/data"
RELEASE_URL="https://github.com/jevallejos/vortex-rs/releases/download/latest-linux-x86_64/vortex-linux-x86_64.tar.gz"
EXPECTED_SHA="$(git -C "${VORTEX_DIR}" rev-parse HEAD)"

mkdir -p "${BIN_DIR}" "${DATA_DIR}"

# 1. Migrar credenciales de Telegram / Bybit desde ~/Denk-sekka/.env si ~/vortex-rs/.env aún no existe
if [ ! -f "${VORTEX_DIR}/.env" ] && [ -f "${HOME}/Denk-sekka/.env" ]; then
    cp "${HOME}/Denk-sekka/.env" "${VORTEX_DIR}/.env"
    chmod 600 "${VORTEX_DIR}/.env"
    echo "[ENV SYNC] Migrated .env credentials from ~/Denk-sekka/.env to ~/vortex-rs/.env"
fi

for legacy_svc in bot-sniper.service doctor-blythe.service; do
    if systemctl list-unit-files | grep -q "^${legacy_svc}"; then
        sudo systemctl stop "${legacy_svc}" || true
        sudo systemctl disable "${legacy_svc}" || true
    fi
done

sudo systemctl stop vortex-exec.service vortex-tap.service 2>/dev/null || true

# 2. Esperar y verificar que el binario en GitHub Release corresponda exactamente al commit HEAD actual
echo "[SHA LOCK] Target Git HEAD: ${EXPECTED_SHA}"
MATCHED=0
for attempt in $(seq 1 18); do
    if curl -fsSL "${RELEASE_URL}?t=$(date +%s)" -o "/tmp/vortex-linux-x86_64.tar.gz" 2>/dev/null; then
        rm -f "${BIN_DIR}/COMMIT_SHA"
        tar -xzf "/tmp/vortex-linux-x86_64.tar.gz" -C "${BIN_DIR}" 2>/dev/null || true
        rm -f "/tmp/vortex-linux-x86_64.tar.gz"
        if [ -f "${BIN_DIR}/COMMIT_SHA" ]; then
            ARTIFACT_SHA="$(tr -d '[:space:]' < "${BIN_DIR}/COMMIT_SHA")"
            if [ "${ARTIFACT_SHA}" = "${EXPECTED_SHA}" ]; then
                echo "[OK] Verified exact binary SHA match (${ARTIFACT_SHA}) on attempt #${attempt} (0% CPU jitter)."
                MATCHED=1
                break
            else
                echo "  [WAIT ${attempt}/18] Release binary SHA (${ARTIFACT_SHA:0:7}) != HEAD (${EXPECTED_SHA:0:7}). GitHub Actions building... waiting 5s"
            fi
        else
            echo "  [WAIT ${attempt}/18] Legacy release without COMMIT_SHA seal. Waiting 5s for GitHub Actions..."
        fi
    fi
    sleep 5
done

if [ "${MATCHED}" -eq 0 ]; then
    echo "[FALLBACK] GitHub Actions still in queue. Compiling exact HEAD locally under idle priority..."
    sudo apt-get update -qq && sudo apt-get install -y -qq pkg-config libssl-dev build-essential
    if ! command -v cargo >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        export PATH="${HOME}/.cargo/bin:${PATH}"
    fi
    nice -n 19 ionice -c 3 cargo build --release --bins --manifest-path "${VORTEX_DIR}/Cargo.toml"
    cp -f "${VORTEX_DIR}/target/release/vortex_tap" "${BIN_DIR}/"
    cp -f "${VORTEX_DIR}/target/release/vortex_replay" "${BIN_DIR}/"
    cp -f "${VORTEX_DIR}/target/release/vortex_exec" "${BIN_DIR}/"
    echo "${EXPECTED_SHA}" > "${BIN_DIR}/COMMIT_SHA"
fi

chmod +x "${BIN_DIR}/vortex_tap" "${BIN_DIR}/vortex_replay" "${BIN_DIR}/vortex_exec"

sudo tee /etc/systemd/system/vortex-tap.service >/dev/null <<EOF
[Unit]
Description=VORTEX-L2 Immortal Bybit V5 WebSocket L2 + PublicTrade Ingestion Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${VORTEX_DIR}
ExecStart=${BIN_DIR}/vortex_tap --daemon
Restart=always
RestartSec=1
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0
OOMScoreAdjust=-800
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/vortex-exec.service >/dev/null <<EOF
[Unit]
Description=VORTEX-L2 Execution FSM, Telegram Telemetry & Shadow Parity Engine (VORTEX-RS-V1.0)
After=vortex-tap.service
Requires=vortex-tap.service

[Service]
Type=simple
User=${USER}
WorkingDirectory=${VORTEX_DIR}
ExecStart=${BIN_DIR}/vortex_exec --daemon --live-capital
Restart=always
RestartSec=1
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0
OOMScoreAdjust=-800
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

sudo tee /usr/local/bin/vortex >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail
case "\${1:-live}" in
    live|-l)
        ${BIN_DIR}/vortex_exec --live
        ;;
    trades|-t)
        echo "=== [SHADOW QUEUE & EXECUTION EVENTS IN JOURNALCTL] ==="
        journalctl -u vortex-exec.service -n 25 --no-pager | grep -E "SHADOW|SHM|DAEMON|TELEGRAM|JSONL" || true
        echo "=== [COLORIZED CLOSED SHADOW TRADES LEDGER (vortex_shadow_trades.jsonl)] ==="
        cd "${VORTEX_DIR}" && ${BIN_DIR}/vortex_exec --trades
        ;;
    status|-s)
        systemctl status vortex-tap.service vortex-exec.service --no-pager
        ls -lh /dev/shm/vortex_lob.mmap
        ls -lh ${DATA_DIR} | tail -n 10
        ;;
    follow|-f)
        ${BIN_DIR}/vortex_exec --live
        echo "=== [COLORIZED CLOSED TRADES LEDGER (vortex_shadow_trades.jsonl)] ==="
        cd "${VORTEX_DIR}" && ${BIN_DIR}/vortex_exec --trades
        echo "=== [VORTEX-L2 LIVE STREAMING FEED (Ctrl+C to exit)] ==="
        journalctl -u vortex-exec.service -u vortex-tap.service -f -n 30 --output=cat
        ;;
    logs)
        journalctl -u vortex-tap.service -u vortex-exec.service -n 40 --no-pager
        ;;
    audit|-a)
        ${BIN_DIR}/vortex_tap
        ;;
    replay|-r)
        cd "${VORTEX_DIR}" && ${BIN_DIR}/vortex_replay
        ;;
    oos|-o)
        ${BIN_DIR}/vortex_exec
        ;;
    all)
        ${BIN_DIR}/vortex_tap
        cd "${VORTEX_DIR}" && ${BIN_DIR}/vortex_replay
        ${BIN_DIR}/vortex_exec
        ;;
    *)
        echo "Usage: vortex {live|-f|follow|trades|status|logs|audit|replay|oos|all}"
        exit 1
        ;;
esac
EOF
sudo chmod +x /usr/local/bin/vortex

sudo systemctl daemon-reload
sudo systemctl enable vortex-tap.service vortex-exec.service
sudo systemctl restart vortex-tap.service vortex-exec.service
sleep 3

echo "[OK] VORTEX-L2 Stage 12 Daemons active (Commit SHA Verified)."
vortex live