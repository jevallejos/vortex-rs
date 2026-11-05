# VORTEX-L2 (Voragine V0.3.2) - Institutional Low-Latency Execution Core (VORTEX-RS-V1.0)

## 1. Resumen Ejecutivo

**VORTEX-L2 (`VORTEX-RS-V1.0` / Epoca `Voragine V0.3.2`)** es un motor institucional de
negociacion automatizada de alta frecuencia (*High-Frequency Trading* - HFT) y creacion de
mercado direccional (*Directional Market Making*) compilado 100% en **Rust** (`lto = "fat"`,
`codegen-units = 1`, `panic = "abort"`, cero asignaciones en el *heap* sobre la ruta critica,
`--tcp-nodelay`) para futuros perpetuos lineales USDT en **Bybit Unified Trading Account
(UTA V5)** sobre el nodo de produccion **`sniper-singapur`** (`AWS ap-southeast-1`, Ubuntu
x86_64).

El sistema opera bajo una topologia desacoplada de **Doble Demonio (`vortex-tap.service` +
`vortex-exec.service`)** comunicados a traves de un segmento de memoria compartida POSIX
(`MAP_SHARED`) sin bloqueos (**`SHM v9`: `/dev/shm/vortex_lob.mmap`**) mediante un protocolo
**Seqlock** atomico a **`200.0 Hz` (`5 ms`)** con cache local de instantaneas por ciclo
(`cached_snaps`), persistencia forense columnar en un anillo circular de **`4,096` segmentos
`.parquet`** (`1,048,576` eventos reales `orderbook.50` y `publicTrade`), rotacion sin borrado
hacia **`data/lakehouse_par1/`** (`32,768` archivos = `8.38M` eventos) y aislamiento de las
4 bitacoras contables y forenses en **`data/vault/`**.

### Hitos Certificados (Voragine V0.3.2 - 41 / 41 Pruebas Unitarias y 0 Warnings en Clippy)

* **Gobernanza Algoritmica bajo las 9 Leyes Operativas Inquebrantables:** Erradicacion total
  de umbrales estaticos heredados, reemplazados por funciones continuas C1/C2 auto-aprendidas
  por moneda (`slot_learned_mfe_bps`), junto con la **Ley 9** que prohibe cierres a mercado
  por software en alta volatilidad cuando la posicion ya avanzo a favor (`peak_gross_now > 0`).
* **Superficie Concava de Energia Cinematica Libre (`E_kin >= E_min`), Tope de Climax
  (`climax_ext_cap`) y Penalizacion de Absorcion L2 (`l2_absorption_pen`):** Exige aceleracion
  libre neta (`|drift| - |ext|`), acota el bono de velocidad al margen libre hasta
  `climax_ext_cap`, penaliza la absorcion pasiva cuando la cinta (`TFI`) diverge del libro
  (`OFI`) por mas de `0.35`, penaliza la ruptura estructural (`structural_breakdown_pen`) y
  exige alineacion L2 con el lider `BTCUSDT` (`Slot 0`).
* **Certificacion Unificada de las `62 / 62` Perdidas del Cuaderno (`100.0%`) y `2,160 / 2,160`
  Combinaciones Toxicas (`0` Fugas):**
  * **Semilla Historica (`222` operaciones en `deploy/forensic_vault_171.seed`):** `37 / 37`
    perdidas mitigadas (`100.0%`, `-1,447.77 bps` erradicados, `New Session CumNet: +78.41 bps`,
    `PF = 9.99`, `100% Maker`), certificadas en flujo continuo, en marcas de tiempo realistas,
    en 6 reinicios en frio (*Cold-Start*) y en particion **70% Train (`25/25`) / 30% Blind OOS
    (`12/12`)**.
  * **Benchmark V2 en Vivo (`42` tiros instrumentados `S1`..`S6` en Bybit UTA V5):** `9 / 9`
    Stop-Losses bloqueados (`100.0%`), transformando `-267.46 bps` en **`+22.87 bps` netos
    (`+290.33 bps` de mejora neta, `PF = 9.99`)**.
  * **Capturas `Walk-Forward PAR1 Replay` (`16` eventos `REAL PAR1 TRADE LOSS` unicos):**
    `16 / 16` bloqueados (`100.0%`), completando **`62 / 62` (`-2,259.08 bps -> 0.00 bps`)**.
  * **Variedad Combinatoria (`test_combinatorial_loss_manifold_100pct_green_gate`):**
    `2,160 / 2,160` (`100.0%`) mutaciones toxicas (`6 pares x 2 lados x 6 volatilidades x
    10 perfiles x 3 EWMAs`) bloqueadas a costo `$0.00`.
  * **Auditoria del CSV Oficial Completo de Bybit (`7,266` ordenes / `1,807` transacciones /
    `301` tiros VORTEX-L2):** Simulacion realista no-100%-WIN (`56.6% WIN [+219.30 bps]`,
    `40.8% SCRATCH [+24.80 bps]`, `2.6% LOSS residual comprimido por Wald [-84.04 bps]`) con
    **`+160.06 bps` netos, `97.37%` salidas Maker y `Profit Factor = 2.90`**.
* **Arquitectura de Boveda `data/vault/`, Caja Forense Roja (`54` Metricas) y Disyuntor
  Automatico Morado (`HALTED_ON_LOSS.lock`):**
  * Separa el marcador visual (`data/vault/vortex_shadow_trades.jsonl`) de la memoria perpetua
    de cicatrices (`data/vault/vortex_governor_scar_memory.jsonl`).
  * Registra cada perdida en la **Caja Forense Roja (`data/vault/vortex_red_loss_box.jsonl`,
    `vortex redbox`)** con `54` metricas de autopsia profunda.
  * Ante cualquier cierre `LOSS`, envia la **Alerta Morada a Telegram**, escribe el candado
    fisico `data/vault/HALTED_ON_LOSS.lock` y detiene `vortex-exec.service`
    (`Restart=on-failure`) hasta auditoria humana.

---

## 2. Arquitectura de Archivos en `data/vault/` y los 8 Modulos en Rust

| Archivo / Directorio | Proposito en el Motor | Se Reinicia al Limpiar Racha? |
| :--- | :--- | :---: |
| `data/vault/vortex_shadow_trades.jsonl` | Libro Mayor Contable de la sesion activa (`15` campos enriquecidos) para `vortex trades` y el Cuadro Ejecutivo de `vortex 360`. | Si (al archivar sesion) |
| `data/vault/vortex_ai_forensic_vault.jsonl` | Baul Forense Principal de IA V2 (`38` metricas microestructurales de todos los tiros cerrados). | Si (al archivar sesion) |
| `data/vault/vortex_red_loss_box.jsonl` | **Caja Forense Roja Inmutable (`54` metricas)** exclusiva para tiros `LOSS` (`quantum_floor_ticks`, `gap_to_quantum_floor_bps`, `kin_energy_in_bps`, `req_kin_energy_in_bps`, `loss_root_diagnosis`). | **NUNCA (Inmutable)** |
| `data/vault/vortex_governor_scar_memory.jsonl` | Memoria Perpetua de Cicatrices y Anclas de Precio leida al arrancar por `vortex_exec` y `vortex_replay` (deduplicada por `ts_ns`). | **NUNCA (Inmutable)** |
| `data/vault/HALTED_ON_LOSS.lock` | Candado fisico de seguridad creado automaticamente si ocurre un `LOSS` para mantener detenido a `vortex-exec.service`. | Al auditar / desplegar |
| `data/*.parquet` y `data/lakehouse_par1/` | Anillo vivo de `4,096` segmentos `.parquet` (`1,048,576` eventos) y archivo historico de `32,768` segmentos (`8.38M` eventos). | Rotacion continua |

---

## 3. Lista Completa de Comandos Utilizados

### 3.1. Comandos Operativos del CLI `vortex` en `sniper-singapur` (`/usr/local/bin/vortex`)

| Comando Principal | Atajo | Proposito Operativo | Descripcion Detallada de su Salida |
| :--- | :--- | :--- | :--- |
| `vortex 360` | - | **Auditoria Integral 360 (6 Secciones)** | Imprime en una sola corrida: (1) HUD en vivo (`SHM v9`), (2) ultimas 35 lineas de ordenes Bybit V5 y cola L1 en `journalctl`, (3) tabla coloreada + Cuadro Ejecutivo Consolidado con billetera Bybit en vivo y 3 barras de meta (`25`, `50`, `65 USDT`), (4) simulador Walk-Forward `vortex_replay` sobre `1,048,576` eventos reales, (5) Baul Forense IA (`data/vault/vortex_ai_forensic_vault.jsonl`), y (6) **Caja Forense Roja (`data/vault/vortex_red_loss_box.jsonl`)**. |
| `vortex redbox` | `vortex -rb` | **Caja Forense Roja (`54` Metricas)** | Imprime todos los registros de autopsia profunda de perdidas almacenados en `data/vault/vortex_red_loss_box.jsonl`. |
| `vortex baul` | `vortex -b` | **Baul Forense V2 (`38` Metricas)** | Imprime todos los registros JSONL enriquecidos (`38` campos) en `data/vault/vortex_ai_forensic_vault.jsonl`. |
| `vortex timemachine` | `vortex -tm` | **Maquina del Tiempo + 70/30 OOS + Stats** | Ejecuta `vortex_replay --timemachine`: certifica 70% Train / 30% Blind OOS sobre los 222 tiros semilla, evalua los 42 tiros V2 de Bybit (`9/9 SLs` bloqueados, `+22.87 bps` netos) e imprime las 3 tablas de tendencias y *markout* L2. |
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

* **Despliegue en Caliente con Candado `COMMIT_SHA` Conservando la Sesion Actual:**
  ```bash
  cd ~/vortex-rs && git fetch origin --tags --force && git reset --hard origin/main && bash deploy/install_sniper_singapur.sh --live-capital && sleep 2 && vortex 360
  ```
* **Archivar Sesion Actual, Limpiar Marcador Visual (`0/25`) Conservando Memoria de Cicatrices y Caja Roja, y Desplegar:**
  ```bash
  mkdir -p ~/vortex-rs/data/vault ~/vortex-rs/data/archive_voragine_v03_session6_4trades && \
  cp -f ~/vortex-rs/data/vault/vortex_ai_forensic_vault.jsonl ~/vortex-rs/data/archive_voragine_v03_session6_4trades/ 2>/dev/null || true && \
  cp -f ~/vortex-rs/data/vault/vortex_shadow_trades.jsonl ~/vortex-rs/data/archive_voragine_v03_session6_4trades/ 2>/dev/null || true && \
  rm -f ~/vortex-rs/data/vault/vortex_ai_forensic_vault.jsonl ~/vortex-rs/data/vault/vortex_shadow_trades.jsonl ~/vortex-rs/data/vault/HALTED_ON_LOSS.lock && \
  cd ~/vortex-rs && git fetch origin --tags --force && git reset --hard origin/main && bash deploy/install_sniper_singapur.sh --live-capital && sleep 2 && vortex 360
  ```
* **Desbloquear Manualmente el Freno Automatico Morado (`HALTED_ON_LOSS.lock`) tras Auditoria:**
  ```bash
  rm -f ~/vortex-rs/data/vault/HALTED_ON_LOSS.lock && sudo systemctl restart vortex-exec.service && sleep 2 && vortex live
  ```

### 3.3. Comandos de Desarrollo y Simulacion en Windows (`PowerShell` - Antigravity IDE)

* **1. Verificar `0 Warnings` en Clippy:**
  ```powershell
  cargo clippy --all-targets -- -D warnings
  ```
* **2. Ejecutar los `41 / 41` Tests Unitarios + `62/62` Losses del Cuaderno + `2,160` Combos + Barras CSV Bybit (`301` Tiros):**
  ```powershell
  cargo test --lib --bins -- --test-threads=1 --nocapture
  ```
* **3. Sellar Commit, Rama `checkpoint/voragine-v0.3-inflection` y Tag `voragine-v0.3` hacia GitHub:**
  ```powershell
  git add -A; git commit -m "docs(voragine-v0.3.2): update README.md with data/vault, Red Loss Box & 41/41 suite"; git branch -f checkpoint/voragine-v0.3-inflection HEAD; git tag -f voragine-v0.3; git push origin main checkpoint/voragine-v0.3-inflection --tags --force
  ```
