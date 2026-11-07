# VORTEX-L2 (Voragine V0.3.2) - Institutional Low-Latency Execution Core (VORTEX-RS-V1.0)

## 1. Resumen Ejecutivo

**VORTEX-L2 (`VORTEX-RS-V1.0` / Epoca `Voragine V0.3.2` - Stage 36.4)** es un motor institucional de
negociacion automatizada de alta frecuencia (*High-Frequency Trading* - HFT) y creacion de
mercado direccional (*Directional Market Making*) compilado 100% en **Rust** (`lto = "fat"`,
`codegen-units = 1`, `panic = "abort"`, cero asignaciones en el *heap* sobre la ruta critica,
`TCP_NODELAY = true`) para futuros perpetuos lineales USDT en **Bybit Unified Trading Account
(UTA V5)** sobre el nodo de produccion **`sniper-singapur`** (`AWS ap-southeast-1`, Ubuntu
x86_64).

El sistema opera bajo una topologia desacoplada de **Doble Demonio (`vortex-tap.service` +
`vortex-exec.service`)** comunicados a traves de un segmento de memoria compartida POSIX
(`MAP_SHARED`) sin bloqueos (**`SHM v9`: `/dev/shm/vortex_lob.mmap`**) mediante un protocolo
**Seqlock** atomico a **`200.0 Hz` (`5 ms`)** con cache local de instantaneas por ciclo
(`cached_snaps`), **Multiplexor de 6 Sesiones en Paralelo (`6 / 6` del Universo Aprobado)**,
**Canal Persistente Dual (`Bybit V5 WebSocket Trade API` + `Pool TLS 1.3 HTTP/1.1 Keep-Alive`)**,
persistencia forense columnar en un anillo circular de **`4,096` segmentos `.parquet`**
(`1,048,576` eventos reales `orderbook.50` y `publicTrade`), rotacion sin borrado hacia
**`data/lakehouse_par1/`** (`32,768` archivos = `8.38M` eventos) y aislamiento de las
bitacoras contables y forenses en **`data/vault/`**.

### Hitos Certificados (Voragine V0.3.2 - 46 / 46 Pruebas Unitarias, 0 Warnings y Racha 86 / 200)

* **Multiplexor Institucional de 6 Sesiones Simultaneas (`6 / 6` Universo `SHM v9`) y Meta `200`:**
  * Opera en paralelo los 6 contratos aprobados (`BTCUSDT [0.001]`, `ETHUSDT [0.02]`,
    `SOLUSDT [0.2]`, `AVAXUSDT [2.6]`, `TAOUSDT [0.1]` y `SUIUSDT [25]`) con adopcion en
    caliente sin cierres a mercado (`[BYBIT V5 LIVE SYNC]` y `[PARALLEL SESSION ADOPTED]`).
  * Barra de progreso unificada **`Meta 200 (Evol)`** (`86 / 200` cerrados en vivo = `43.0%`,
    `81 WIN [94.2%]`, `5 SCRATCH [5.8%]`, `0 LOSS [0.0%]`, `+181.69 bps` netos, `PF = 9.99`,
    Captura Media de MFE = `92.1%`).
* **Las 4 Mejoras Institucionales Activas en Produccion (`Commit 95975f6`):**
  1. **Fondo de Saneamiento Cruzado (*Cross-Session Profit Sinking Fund*, `30% / 70%`):**
     Retiene el `30%` de cada ganancia neta realizada en `sinking_fund_scaled_bps` (blindando
     el `70%` restante en billetera) para subsidiar hasta `35.00 bps` del piso de salida pasivo
     en cualquier sesion abierta que supere los `15 minutos` (`900s`), destrabando posiciones
     lentas y manteniendo la convergencia `Wallet == Equity`.
  2. **Cosecha Parcial Financiadora (*Self-Funded Partial Runner* `50% / 50%`):**
     En los 5 contratos multi-lote (`ETH`, `SOL`, `AVAX`, `TAO`, `SUI`), cobra el `50%` en
     `>= +5.20 bps` brutos (`Limit PostOnly reduceOnly`) y reduce automaticamente el piso
     requerido de la segunda mitad de `+5.00 bps` a **`+3.40 bps` brutos** (`base_runner_bps = 340`).
  3. **Guardia de Neutralidad Delta con Prioridad de Cobertura Asimetrica (`+35% Hedge Boost`):**
     Otorga un multiplicador de prioridad de `1.35x` a las senales que equilibran el Delta
     direccional de las sesiones abiertas (`opp_dir > same_dir`) sin bloquear el tope `6 / 6`.
  4. **Canal de Red Persistente Dual (`Bybit V5 WebSocket Trade API` + `TLS 1.3 Keep-Alive`):**
     Envia ordenes `/v5/order/create` por WebSocket autenticado (`wss://stream.bybit.com/v5/trade`)
     y ejecuta cancelaciones `/v5/order/cancel-all` y consultas por socket TLS Keep-Alive
     (`api.bybit.com:443`, `TCP_NODELAY = true`), reduciendo la latencia de red a `< 1 ms`.
* **Modo Drenaje Controlado (*Graceful Session Drain* - `vortex drain` / `vortex normal`):**
  * Permite apagar el motor de forma ordenada (`DRAIN_MODE.lock`): bloquea nuevas entradas,
    custodia en verde las sesiones abiertas hasta `0` posiciones en Bybit (`Wallet == Equity`,
    `UPL = $0.0000`) y detiene limpiamente el servicio (`DRAIN_COMPLETE_STOPPED`).
* **Gobernanza Algoritmica bajo las 10 Leyes Operativas Inquebrantables (`46 / 46` Tests):**
  * Certificacion unificada de las `62 / 62` perdidas historicas del cuaderno (`37/37` Seed +
    `9/9` V2 Live + `16/16` PAR1 Replay = `100.0%`) y `2,160 / 2,160` combinaciones toxicas
    bloqueadas a costo `$0.00`.

---

## 2. Arquitectura de Archivos en `data/vault/` y los Modulos en Rust

| Archivo / Directorio | Proposito en el Motor | Se Reinicia al Limpiar Racha? |
| :--- | :--- | :---: |
| `data/vault/vortex_shadow_trades.jsonl` | Libro Mayor Contable de la sesion activa (`15` campos) para `vortex trades`, Cuadro Ejecutivo `360` y Fondo de Saneamiento (`30%/70%`). | Si (al archivar sesion) |
| `data/vault/vortex_ai_forensic_vault.jsonl` | Baul Forense Principal de IA V2 (`38` metricas microestructurales de todos los tiros cerrados). | Si (al archivar sesion) |
| `data/vault/vortex_red_loss_box.jsonl` | **Caja Forense Roja Inmutable (`54` metricas)** exclusiva para tiros `LOSS` (`quantum_floor_ticks`, `kin_energy_in_bps`, `loss_root_diagnosis`). | **NUNCA (Inmutable)** |
| `data/vault/vortex_governor_scar_memory.jsonl` | Memoria Perpetua de Cicatrices y Anclas de Precio leida al arrancar por `vortex_exec` y `vortex_replay` (deduplicada por `ts_ns`). | **NUNCA (Inmutable)** |
| `data/vault/DRAIN_MODE.lock` | Candado de **Drenaje Controlado** activado con `vortex drain` (y removido con `vortex normal`) para cerrar en verde hasta `0` posiciones. | Al ejecutar `vortex normal` |
| `data/vault/HALTED_ON_LOSS.lock` | Candado fisico de seguridad creado automaticamente si ocurre un `LOSS` para mantener detenido a `vortex-exec.service`. | Al auditar / `vortex normal` |
| `data/*.parquet` y `data/lakehouse_par1/` | Anillo vivo de `4,096` segmentos `.parquet` (`1,048,576` eventos) y archivo historico de `32,768` segmentos (`8.38M` eventos). | Rotacion continua |

---

## 3. Lista Completa de Comandos Utilizados

### 3.1. Comandos Operativos del CLI `vortex` en `sniper-singapur` (`/usr/local/bin/vortex`)

| Comando Principal | Atajo | Proposito Operativo | Descripcion Detallada de su Salida |
| :--- | :--- | :--- | :--- |
| `vortex 360` | - | **Auditoria Integral 360 (6 Secciones)** | Imprime: (1) HUD en vivo (`SHM v9`), (2) ordenes Bybit V5 y cola L1 en `journalctl`, (3) Libro Mayor + Cuadro Ejecutivo con billetera Bybit, `Meta 200 (Evol)`, `Meta 65 USDT` y **Fondo de Saneamiento (`30% Reserva / 70% Blindado`)**, (4) `vortex_replay` (`1,048,576` eventos), (5) Baul Forense IA (`38` metricas), y (6) **Caja Forense Roja (`54` metricas)**. |
| `vortex drain` | `vortex drenar` | **Activar Modo Drenaje Controlado** | Crea `data/vault/DRAIN_MODE.lock`, cancela ordenes en cola no llenadas, bloquea nuevas entradas y custodia en verde las posiciones abiertas (`DRAINING_OPEN_SESSIONS`) hasta llegar a `0` posiciones y apagar limpiamente el motor (`DRAIN_COMPLETE_STOPPED`). |
| `vortex normal` | `vortex resume` | **Restaurar Operacion Normal (`6/6`)** | Elimina `DRAIN_MODE.lock` y `HALTED_ON_LOSS.lock`, inicia `vortex-exec.service` si estaba detenido y reactiva las 6 sesiones en paralelo. |
| `vortex redbox` | `vortex -rb` | **Caja Forense Roja (`54` Metricas)** | Imprime todos los registros de autopsia profunda de perdidas almacenados en `data/vault/vortex_red_loss_box.jsonl`. |
| `vortex baul` | `vortex -b` | **Baul Forense V2 (`38` Metricas)** | Imprime todos los registros JSONL enriquecidos (`38` campos) en `data/vault/vortex_ai_forensic_vault.jsonl`. |
| `vortex timemachine` | `vortex -tm` | **Maquina del Tiempo + 70/30 OOS + Stats** | Ejecuta `vortex_replay --timemachine`: certifica 70% Train / 30% Blind OOS sobre los 222 tiros semilla, evalua los 42 tiros V2 de Bybit (`9/9 SLs` bloqueados) e imprime las 3 tablas de tendencias y *markout* L2. |
| `vortex stats` | `vortex -st` | **Analizador de Tendencias y Markout L2** | Ejecuta `vortex_replay --stats`: imprime (1) Matriz de los 3 Regimenes Cinematicos, (2) Perfil y Horizonte Optimo de MFE de los 6 pares, y (3) Curvas de *Markout* L2 en `+5s, +15s, +30s, +60s, +180s`. |
| `vortex -f` | `vortex follow` | **Monitor Continuo en Tiempo Real** | Muestra el HUD instantaneo, la tabla de operaciones cerradas y deja abierta la transmision en vivo (`journalctl -f`) de cada orden, llenado, aborto o cierre en Bybit. |
| `vortex live` | `vortex -l` | **Foto Instantanea del Libro y FSM (HUD)** | Lee `/dev/shm/vortex_lob.mmap` en `< 1 ms` sin bloquear a los demonios e imprime los 6 slots y el estado de `EXEC FSM LIVE`. |
| `vortex trades` | `vortex -t` | **Libro Mayor y Cuadro Ejecutivo** | Muestra los ultimos 25 eventos de ejecucion en `journalctl` seguidos de la tabla coloreada de operaciones cerradas y el Cuadro Ejecutivo Consolidado. |
| `vortex status` | `vortex -s` | **Salud de Demonios y Almacenamiento** | Ejecuta `systemctl status` sobre `vortex-tap.service` y `vortex-exec.service`, verifica `/dev/shm/vortex_lob.mmap` y lista `~/vortex-rs/data`. |
| `vortex logs` | - | **Bitacora Tecnica Rapida (40 lineas)** | Imprime las ultimas 40 lineas combinadas de `vortex-tap.service` y `vortex-exec.service`. |
| `vortex replay` | `vortex -r` | **Simulador Walk-Forward (`PAR1`)** | Ejecuta `vortex_replay` sobre los `4,096` archivos `.parquet` (`1,048,576` eventos reales) sincronizado con `data/vault/vortex_governor_scar_memory.jsonl`. |
| `vortex audit` | `vortex -a` | **Auditoria del Filtro de Pares** | Ejecuta la validacion de contratos en `vortex_tap` (`Tick_bps <= 1.50 bps`: 6 aprobados, 3 vetados). |
| `vortex oos` | `vortex -o` | **Certificacion Matematica OOS (520 Trades)** | Corre el examen interno fuera de muestra de `520` operaciones de `vortex_exec` (`PF = 4.18`, `PARITY_SYNC = 0`). |
| `vortex all` | - | **Triada de Certificacion Local** | Ejecuta en secuencia `vortex audit` + `vortex replay` + `vortex oos`. |

### 3.2. Comandos de Administracion y Despliegue en `sniper-singapur` (Ubuntu SSH)

* **1. Activar Drenaje Controlado antes de un Mantenimiento (`0` Nuevas Entradas hasta `0` Posiciones):**
  ```bash
  vortex drain
  ```
* **2. Restaurar Modo Normal (`6 / 6` Sesiones Activas):**
  ```bash
  vortex normal
  ```
* **3. Despliegue en Caliente con Candado `COMMIT_SHA` Conservando la Sesion Actual:**
  ```bash
  rm -f ~/vortex-rs/data/vault/HALTED_ON_LOSS.lock ~/vortex-rs/data/vault/DRAIN_MODE.lock && \
  cd ~/vortex-rs && git fetch origin --tags --force && git reset --hard origin/main && bash deploy/install_sniper_singapur.sh --live-capital && sleep 2 && vortex 360
  ```

### 3.3. Comandos de Desarrollo y Simulacion en Windows (`PowerShell` - Antigravity IDE)

* **1. Verificar `0 Warnings` en Clippy:**
  ```powershell
  cargo clippy --all-targets -- -D warnings
  ```
* **2. Ejecutar los `46 / 46` Tests Unitarios + `62/62` Losses del Cuaderno + `2,160` Combos + Barras CSV Bybit (`301` Tiros):**
  ```powershell
  cargo test --lib --bins -- --test-threads=1 --nocapture
  ```
* **3. Sellar Commit, Rama `checkpoint/voragine-v0.3-inflection` y Tag `voragine-v0.3` hacia GitHub:**
  ```powershell
  git add -A; git commit -m "docs(voragine-v0.3.2): update README.md with 6/6 sessions, 4 institutional upgrades & drain mode"; git branch -f checkpoint/voragine-v0.3-inflection HEAD; git tag -f voragine-v0.3; git push origin main checkpoint/voragine-v0.3-inflection --tags --force
  ```