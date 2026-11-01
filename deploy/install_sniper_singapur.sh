#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "[VORTEX-L2 DEPLOY] ZERO-ASSUMPTION INSTALLER FOR SNIPER-SINGAPUR (UBUNTU x86_64)"
echo "================================================================================"

VORTEX_DIR="${HOME}/vortex-rs"
BIN_DIR="${VORTEX_DIR}/bin"
DATA_DIR="${VORTEX_DIR}/data"
SHM_PATH="/dev/shm/vortex_lob.mmap"
RELEASE_URL="https://github.com/jevallejos/vortex-rs/releases/download/latest-linux-x86_64/vortex-linux-x86_64.tar.gz"

mkdir -p "${BIN_DIR}" "${DATA_DIR}"

# 1. Detener y deshabilitar demonios antiguos en Python para evitar colisión de órdenes en Bybit
for legacy_svc in bot-sniper.service doctor-blythe.service; do
    if systemctl list-unit-files | grep -q "^${legacy_svc}"; then
        echo "[CLEANUP] Stopping and disabling legacy Python service: ${legacy_svc}"
        sudo systemctl stop "${legacy_svc}" || true
        sudo systemctl disable "${legacy_svc}" || true
    fi
done

# 2. Descargar binarios Linux x86_64 pre-compilados desde GitHub Release (o compilar con nice -n 19 si aún no termina Actions)
echo "[BINARY FETCH] Attempting zero-jitter download of pre-built Linux x86_64 binaries..."
if curl -fsSL "${RELEASE_URL}" -o "/tmp/vortex-linux-x86_64.tar.gz"; then
    tar -xzf "/tmp/vortex-linux-x86_64.tar.gz" -C "${BIN_DIR}"
    rm -f "/tmp/vortex-linux-x86_64.tar.gz"
    echo "[OK] Pre-built LTO binaries installed into ${BIN_DIR} (0% compilation CPU jitter)."
else
    echo "[FALLBACK] Release artifact still building in GitHub Actions. Building once under idle CPU priority..."
    if ! command -v cargo >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        export PATH="${HOME}/.cargo/bin:${PATH}"
    fi
    nice -n 19 ionice -c 3 cargo build --release --bins --manifest-path "${VORTEX_DIR}/Cargo.toml"
    cp -f "${VORTEX_DIR}/target/release/vortex_tap" "${BIN_DIR}/"
    cp -f "${VORTEX_DIR}/target/release/vortex_replay" "${BIN_DIR}/"
    cp -f "${VORTEX_DIR}/target/release/vortex_exec" "${BIN_DIR}/"
fi

chmod +x "${BIN_DIR}/vortex_tap" "${BIN_DIR}/vortex_replay" "${BIN_DIR}/vortex_exec"

# 3. Configurar unidades systemd de bajo jitter (vortex-tap.service y vortex-exec.service)
sudo tee /etc/systemd/system/vortex-tap.service >/dev/null <<EOF
[Unit]
Description=VORTEX-L2 Immortal L2 + PublicTrade Ingestion & Pair Eligibility Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=${USER}
WorkingDirectory=${VORTEX_DIR}
ExecStart=${BIN_DIR}/vortex_tap
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
Description=VORTEX-L2 Execution FSM & Parity Sync Engine (VORTEX-RS-V1.0)
After=vortex-tap.service
Requires=vortex-tap.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=${USER}
WorkingDirectory=${VORTEX_DIR}
ExecStart=${BIN_DIR}/vortex_exec
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0
OOMScoreAdjust=-800
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# 4. Instalar CLI global `/usr/local/bin/vortex`
sudo tee /usr/local/bin/vortex >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail
case "\${1:-status}" in
    status|-s)
        systemctl status vortex-tap.service vortex-exec.service --no-pager
        ;;
    audit|-a)
        ${BIN_DIR}/vortex_tap
        ;;
    replay|-r)
        ${BIN_DIR}/vortex_replay
        ;;
    oos|-o)
        ${BIN_DIR}/vortex_exec
        ;;
    all)
        ${BIN_DIR}/vortex_tap
        ${BIN_DIR}/vortex_replay
        ${BIN_DIR}/vortex_exec
        ;;
    *)
        echo "Usage: vortex {status|audit|replay|oos|all}"
        exit 1
        ;;
esac
EOF
sudo chmod +x /usr/local/bin/vortex

sudo systemctl daemon-reload
sudo systemctl enable vortex-tap.service vortex-exec.service
sudo systemctl restart vortex-tap.service vortex-exec.service

echo "[OK] VORTEX-L2 systemd services enabled and active."
vortex all