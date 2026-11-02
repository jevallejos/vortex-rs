# VORTEX-L2 — Institutional Low-Latency Execution Core (VORTEX-RS-V1.0)

Motor institucional de ejecucion de alta frecuencia y baja latencia en **Rust (edition = 2021)** para **Bybit UTA V5**, disenado bajo arquitectura de doble demonio acoplada por memoria compartida POSIX (`/dev/shm/vortex_lob.mmap` — `SHM v9`), cuantizacion entera exacta en escala `1e8`, modelo ortogonal de 3 factores (`X_OFI`, `X_TFI`, `X_Geom`), simulacion determinista de cola FIFO L1 (`> 940M ev/s`) y salidas normales `100% Limit PostOnly`.

---

## 1. Arquitectura de Produccion (`sniper-singapur`)

| Componente | Binario / Servicio | Funcion Operativa |
| :--- | :--- | :--- |
| **Demonio de Ingesta L2 + Cinta** | `vortex_tap` (`vortex-tap.service`) | Conecta a `wss://stream.bybit.com/v5/public/linear` (`orderbook.50` + `publicTrade`), aplica el filtro `Tick-to-Price Guard <= 1.50 bps`, escribe en `/dev/shm/vortex_lob.mmap` (`Seqlock`) y rota el anillo de `4,096` archivos `.parquet` (`1,048,576` eventos reales) en `~/vortex-rs/data/`. |
| **Demonio de Ejecucion FSM (200 Hz)** | `vortex_exec` (`vortex-exec.service`) | Lee `/dev/shm/vortex_lob.mmap` cada `5 ms` (`200.0 Hz`), ejecuta la Maquina de Estados (`OrderLifecycleState`) con chequeo de vuelo `PostOnly` de `25 ms`, preserva posiciones entre reinicios (`SHM HOT-RESTORE`), registra cierres en `data/vortex_shadow_trades.jsonl`, notifica 1:1 a Telegram y firma ordenes reales `HMAC-SHA256` bajo `--live-capital`. |
| **Simulador FIFO L1 y Walk-Forward** | `vortex_replay` | Procesa `200,000` eventos sinteticos en `~0.20 ms` (`> 940M ev/s`) con latencia de vuelo de `25 ms` y audita los `4,096` segmentos `.parquet` reales capturados en disco. |
| **Memoria Compartida IPC** | `/dev/shm/vortex_lob.mmap` (`SHM v9`) | Anillo `MAP_SHARED` alineado a 64 bytes con `0 ms` de warmup entre `vortex-tap` y `vortex-exec`. |

### Universo Institucional Aprobado (`Tick_bps <= 1.50 bps`)
- **🟢 Aprobados (6 Slots):** `BTCUSDT` (Slot 0), `ETHUSDT` (Slot 1), `SOLUSDT` (Slot 2), `AVAXUSDT` (Slot 3), `TAOUSDT` (Slot 4), `SUIUSDT` (Slot 5).
- **🔴 Vetados Matematicamente:** `XRPUSDT` (`1.81 bps`), `ZEREBROUSDT` (`3.36 bps`), `WALUSDT` (`3.36 bps`).

---

## 2. Comandos Operativos Diarios en `sniper-singapur` (CLI `vortex`)

```bash
# 1. Ver el HUD en vivo (Precios L1, Spread, X_OFI, X_TFI, X_GEOM y estado de la FSM en SHM v9)
vortex live

# 2. Monitoreo continuo en vivo (actualizando el HUD cada 1 segundo con colores ANSI)
watch -n 1 --color vortex live

# 3. Ver eventos recientes de cola y la bitacora coloreada de trades cerrados (🟢 WIN / 🟠 SCRATCH / 🔴 LOSS)
vortex trades

# 4. Ejecutar el simulador FIFO L1 (>940M ev/s) y el Walk-Forward sobre los 4,096 archivos .parquet reales
vortex replay

# 5. Ver estado de los demonios systemd, tamano de /dev/shm/vortex_lob.mmap y ultimos archivos .parquet
vortex status

# 6. Inspeccionar las ultimas 40 lineas de telemetria en journalctl (vortex-tap + vortex-exec)
vortex logs

# 7. Seguir el flujo de logs en tiempo real (Ctrl+C para salir)
journalctl -u vortex-tap.service -u vortex-exec.service -f

# 8. Ejecutar auditoria microeconomica instantanea de pares (Tick-to-Price Guard)
vortex audit

# 9. Ejecutar el certificador pre-produccion Out-of-Sample de 520 operaciones (PF = 1.92, Maker >= 80%, Drift = 0)
vortex oos

# 10. Ejecutar la suite completa de certificacion en el servidor (audit + replay + oos)
vortex all
```

---

## 3. Comandos de Desarrollo y Certificacion en Windows (`PS D:\Desarrollo\vortex-rs>`)

```powershell
# 1. Ejecutar la suite completa de pruebas unitarias y de integracion (17/17 tests + Gate OOS de 520 trades)
cargo test -- --nocapture

# 2. Ejecutar el linter estatico estricto (Cero warnings, cero .unwrap(), cero .expect(), cero panic!)
cargo clippy --all-targets -- -D warnings

# 3. Sincronizar cambios certificados con GitHub (dispara compilacion Linux x86_64 LTO en GitHub Actions)
git add .
git commit -m "feat: descripcion del cambio"
git push origin main
```

---

## 4. Comando de Despliegue con Candado Criptografico `COMMIT_SHA` en `sniper-singapur`

```bash
cd ~/vortex-rs && \
git fetch origin main --force && \
git reset --hard origin/main && \
bash deploy/install_sniper_singapur.sh && \
vortex replay && \
vortex trades
```

---

## 5. Activacion y Desactivacion de Capital Real (`--live-capital` en Bybit UTA V5)

### 5.1. Verificar Credenciales en `~/vortex-rs/.env` Antes de Activar Capital Real
```bash
grep -E "BYBIT_API_KEY|BYBIT_API_SECRET|TELEGRAM" ~/vortex-rs/.env
```

### 5.2. Activar Modo Capital Real (`--live-capital`) en `vortex-exec.service`
```bash
sudo sed -i 's|ExecStart=\(.*\)/vortex_exec --daemon$|ExecStart=\1/vortex_exec --daemon --live-capital|' /etc/systemd/system/vortex-exec.service && \
sudo systemctl daemon-reload && \
sudo systemctl restart vortex-exec.service && \
vortex trades
```

### 5.3. Volver a Modo Sombra (`Shadow Mode`) en Cualquier Momento
```bash
sudo sed -i 's|ExecStart=\(.*\)/vortex_exec --daemon --live-capital$|ExecStart=\1/vortex_exec --daemon|' /etc/systemd/system/vortex-exec.service && \
sudo systemctl daemon-reload && \
sudo systemctl restart vortex-exec.service && \
vortex status
```

---

## 6. Codigo Semantico de Colores e Iconos ANSI

- **🟢 Verde (`WIN` / `APPROVED`):** Operacion cerrada en ganancia neta (`net_bps >= +0.20 bps`), contrato aprobado o Gate superado.
- **�� Naranjo (`SCRATCH` / `ABORT` / `SPOOF_VETO`):** Salida en empate tecnico (`-0.20 < net_bps < +0.20 bps`), orden cancelada en cola L1 o bloqueo anti-spoofing.
- **🔴 Rojo (`LOSS` / `GUARD_VETO` / `HALTED`):** Cierre en perdida (`net_bps <= -0.20 bps`), contrato vetado por `Tick_bps > 1.50 bps` o parada de emergencia.
- **🟡 Amarillo (`AUTH_MKR` / `ARMED` / `FILL`):** Disparo autorizado por alineacion triple, orden descansando en fila L1 o posicion activa.
- **⚪ Gris (`NEUTRAL_WAIT` / `IDLE`):** Escaneo disciplinado esperando alineacion ortogonal.