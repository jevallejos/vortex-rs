# VORTEX-L2 (Vorágine V0.3) — Institutional Low-Latency Execution Core (VORTEX-RS-V1.0)

---

## 1. Resumen Ejecutivo

VORTEX-L2 (VORTEX-RS-V1.0 / Época Vorágine V0.3, Commit 8ae0f3a1) es un motor institucional de negociación automatizada de alta frecuencia (High-Frequency Trading — HFT) y creación de mercado direccional (Directional Market Making) compilado 100% en Rust (lto = "fat", codegen-units = 1, panic = "abort", cero asignaciones en el heap sobre la ruta crítica) para futuros perpetuos lineales USDT en Bybit Unified Trading Account (UTA V5) sobre el nodo de producción sniper-singapur (AWS ap-southeast-1, Ubuntu x86_64).

El sistema opera bajo una topología desacoplada de Doble Demonio (vortex-tap.service + vortex-exec.service) comunicados a través de un segmento de memoria compartida POSIX (MAP_SHARED) sin bloqueos (SHM v9: /dev/shm/vortex_lob.mmap) mediante un protocolo Seqlock atómico a 200.0 Hz (5 ms) y persistencia forense columnar en un anillo circular de 4,096 segmentos .parquet (1,048,576 eventos reales orderbook.50 y publicTrade).

### Hitos Certificados en Producción (Vorágine V0.3)

* Gobernanza Algorítmica Sin Sesgos (No-Sesgo / No-Maquillaje) y Superficie Continua C1/C2: Erradicación total de umbrales estáticos heredados (440 / 600 ScaledBps), reemplazados por una bifurcación elástica entre Flujo Sano (structural_win_floor: 500..550 ScaledBps = +1.00 a +1.50 bps netos) y Régimen Adverso (zero_loss_scratch_floor: piso cuántico comisión + 1 tick), junto con un piso anti-ruido de -28.50 bps en el Stop-Loss de servidor.
* Certificación Contrafactual LOSS-LAB (36 / 36 = 100.0%): Sobre el consolidado maestro deduplicado de 221 operaciones históricas reales (deploy/forensic_vault_171.seed) y la auditoría cruzada contra 6,373 órdenes del extracto oficial de Bybit UTA V5, los 6 Escudos Estructurales del OnlineAdaptiveGovernor y el piso continuo mitigan el 100% de las 29 pérdidas históricas (19 ServerMarkPriceStopLoss y 10 MakerSubFee).
* Rendimiento Determinista del Simulador Walk-Forward (vortex_replay): Procesamiento vectorizado de 750M a 1.26B eventos/segundo (200,000 eventos en 0.158–0.221 ms) con simulación exacta de prioridad de cola FIFO L1.

---

## 2. Características Principales del Producto

1. Arquitectura de Doble Demonio con Restauración en Caliente ([SHM HOT-RESTORE]):
   * vortex-tap.service (Demonio Inmortal de Ingesta L2 + Cinta): Mantiene la conexión WebSocket hacia wss://stream.bybit.com/v5/public/linear (orderbook.50 + publicTrade), reconstruye 50 niveles del libro en stack ([BookLevel; 50]), calcula los 3 factores ortogonales en línea y rota el anillo de 4,096 archivos .parquet.
   * vortex-exec.service (Demonio Ejecutor de 200.0 Hz Intercambiable en < 5 ms): Muestrea /dev/shm/vortex_lob.mmap cada 5 ms, ejecuta la máquina de estados finitos (ExecutionFsm), firma peticiones privadas con HMAC-SHA256 nativo (RFC 2104 / FIPS 180-4) y preserva posiciones abiertas entre actualizaciones mediante el bloqueo permanente de ABI VORTEX_SHM_VERSION = 9.

2. Topología Canónica Minimalista de 8 Archivos en Rust:
   * Compuesta exclusivamente por src/lib.rs, src/types.rs, src/lob_shm.rs, src/alpha_3factor.rs, src/execution_fsm.rs, src/forensic_parquet.rs y los 3 binarios src/bin/vortex_tap.rs, src/bin/vortex_exec.rs y src/bin/vortex_replay.rs.

3. Seguridad Dimensional en Tiempo de Compilación (Newtype Pattern en src/types.rs):
   * Encapsulación estricta en enteros de punto fijo (PriceTicks(i64), LotQty(i64), ScaledBps(i64), SymbolId(u16), TimestampNs(i64), BoundedScore) en escala 1e8, haciendo imposible en tiempo de compilación mezclar precios con lotes o sufrir imprecisiones de punto flotante IEEE-754.

4. Filtro Institucional de Elegibilidad por Geometría de Tick (Tick-to-Price Guard <= 1.50 bps):
   * Autoriza únicamente los 6 contratos perpetuos institucionales cuyo tamaño de tick es <= 1.50 bps: BTCUSDT (Slot 0), ETHUSDT (Slot 1), SOLUSDT (Slot 2), AVAXUSDT (Slot 3), TAOUSDT (Slot 4) y SUIUSDT (Slot 5).
   * Veta matemáticamente pares con tick degradado (XRPUSDT 1.81 bps, ZEREBROUSDT 3.36 bps, WALUSDT 3.36 bps).

5. Candado Global de Cuenta (settleCoin=USDT), Lado Pasivo Legal y Custodia Sin Abandono:
   * Verifica toda la cuenta lineal USDT en Bybit (/v5/position/list?category=linear&settleCoin=USDT) garantizando máximo 1 posición abierta global en todo momento.
   * Coloca órdenes de salida Limit PostOnly reduceOnly en el lado pasivo legal (BestAsk asks[0] para cerrar un Largo Side::Bid; BestBid bids[0] para cerrar un Corto Side::Ask), prohibiendo transicionar a Idle hasta que Bybit confirme size == 0.00.

6. Candado Criptográfico COMMIT_SHA en CI/CD y Doble Bitácora Auditable (JSONL):
   * Compilación externa en GitHub Actions (0% CPU jitter en servidor) y doble registro en data/vortex_shadow_trades.jsonl y data/vortex_ai_forensic_vault.jsonl.

---

## 3. Investigaciones de Frontera y Fundamentos Matemáticos Implementados

1. Modelo Microestructural de 3 Factores Ortogonales y Selector Multi-Par por SNR (src/alpha_3factor.rs):
   * X_OFI (Order Flow Imbalance de Cont-Kukanov-Stoikov): Mide el desequilibrio neto de adiciones, cancelaciones y ejecuciones en los niveles superiores del libro L2.
   * X_TFI (Trade Flow Imbalance / VPIN direccional): Mide la asimetría entre compras y ventas agresivas ejecutadas en la cinta publicTrade.
   * X_GEOM (L2 Book Geometry & Slope): Evalúa la pendiente de liquidez acumulada en los primeros 10 niveles (L1..L10).
   * Score Compuesto SNR (snr_composite_score) y Veto Anti-Spoofing (SpoofingVeto): Pondera cada factor por su cuadrado (w_i = c_i + X_i^2), selecciona entre los 6 pares el candidato con mayor relación señal-ruido (best_cand) y bloquea en tiempo real órdenes trampa cuando X_OFI contradice a X_TFI.

2. Barrera de Fricción 3x y Volatilidad Invariante a la Escala del Tick (passes_3x_friction_barrier):
   * Exige que la excursión esperada supere al menos 3x el costo redondo esperado (Maker_2bps + E[ExitFee] + tick_bps).
   * Actualiza realized_vol_5m mediante actividad adimensional en ticks (active_ticks = delta_ticks.min(20) + spread_ticks.clamp(1, 10)).

3. Valoración de Cola L1 de Moallemi-Yuan, Geometría de Stoikov y Sondeo Proactivo (RestingEntryQueue):
   * Filtro de Muralla L1 (queue_wall_blocked): Verifica own_q / tot_q <= 0.72..0.78 y own_q <= 12,000 lots para evitar murallas pasivas que solo se llenan por selección adversa.
   * Drenaje FIFO Híbrido + Sondeo Proactivo (periodic_poll) + FILL-ON-ABORT RECOVERED: Descuenta el 100% de publicTrade, el 25% de caídas L1, sondea llenados reales en L1 y adopta cualquier fill ocurrido durante un aborto.

4. Física de Salida Continua (C1/C2), Piso Cuántico Dinámico y Trinquete Convexo de MFE (step_open_position):
   * Piso Cuántico (defensive_zero_loss_maker_exit_price): Cubre exactamente 4.00 bps de comisión Maker-Maker más +1 tick discreto de ganancia neta.
   * Bifurcación Elástica (adverse_regime vs. structural_win_floor): En flujo sano exige structural_win_floor (500..550 ScaledBps = +1.00 a +1.50 bps netos); en régimen adverso desbloquea zero_loss_scratch_floor para evacuar en verde con +1 tick neto.
   * Trinquete Convexo (convex_ratchet_floor): Retiene entre el 35% y el 76% del pico neto alcanzado (net_peak) en Zona de Vuelo Libre.

5. Barrera de Supervivencia Secuencial de Abraham Wald con Piso Anti-Ruido (-28.50 bps):
   * Distancia inicial elástica del Stop-Loss en [3_500, 4_500] ScaledBps, contracción monotónica (<= 22%) tras wald_grace_ns (75s..120s) y piso anti-ruido en -28.50 bps (min_noise_sl_dist).

6. Gobernador Bayesiano Auto-Aprendido en Línea (OnlineAdaptiveGovernor) y sus 6 Escudos Estructurales:
   * Matriz 6x2 con deriva macro (ewma_fast_px_1e4 vs. ewma_slow_px_1e4), deuda real (cum_net_bps_x100), ancla dinámica de extremo de ola (wider_origin) y 6 escudos: VETO_SLOT_COOLDOWN, VETO_GLOBAL_WAVE_OR_SL_BREATHER, VETO_WAVE_STAIRCASE_25BPS, VETO_DEEP_SCAR_DEBT_QUARANTINE, VETO_ALTCOIN_COUNTER_CASCADE y VETO_POST_SL_OPPOSITE_DOMINANCE.

---

## 4. Lista Completa de Comandos Utilizados

### 4.1. Comandos Operativos del CLI vortex en sniper-singapur (/usr/local/bin/vortex)

| Comando Principal | Atajo | Propósito Operativo | Descripción Detallada de su Salida |
| :--- | :--- | :--- | :--- |
| vortex 360 | — | Auditoría Integral 360° (5 Secciones) | Imprime en una sola corrida: (1) HUD en vivo (SHM v9), (2) últimas 35 líneas de órdenes Bybit V5 y cola L1 en journalctl, (3) tabla coloreada + JSONL crudo de vortex_shadow_trades.jsonl, (4) simulador Walk-Forward vortex_replay sobre 1,048,576 eventos reales, y (5) Baúl Forense IA (data/vortex_ai_forensic_vault.jsonl). |
| vortex -f | vortex follow | Monitor Continuo en Tiempo Real | Muestra el HUD instantáneo, la tabla de operaciones cerradas y deja abierta la transmisión en vivo (journalctl -f) de cada orden, llenado, aborto o cierre en Bybit (salir con Ctrl + C). |
| vortex live | vortex -l | Foto Instantánea del Libro y FSM (HUD) | Lee /dev/shm/vortex_lob.mmap en < 1 ms sin bloquear a los demonios e imprime los 6 slots (BEST_BID, BEST_ASK, SPR_T, X_OFI, X_TFI, X_GEOM, VERDICT) y el estado de la máquina de ejecución (EXEC FSM LIVE). |
| vortex trades | vortex -t | Libro Mayor de Operaciones y Cola | Muestra los últimos 25 eventos de ejecución en journalctl seguidos de la tabla coloreada de operaciones cerradas (🟢 WIN, 🟠 SCRATCH, 🔴 LOSS) y el resumen neto acumulado (CumNet). |
| vortex status | vortex -s | Salud de Demonios y Almacenamiento | Ejecuta systemctl status sobre vortex-tap.service y vortex-exec.service, verifica /dev/shm/vortex_lob.mmap y lista los archivos más recientes en ~/vortex-rs/data. |
| vortex logs | — | Bitácora Técnica Rápida (40 líneas) | Imprime las últimas 40 líneas combinadas de vortex-tap.service y vortex-exec.service y devuelve el control a la terminal. |
| vortex replay | vortex -r | Simulador Walk-Forward (PAR1) | Ejecuta vortex_replay sobre los 4,096 archivos .parquet (1,048,576 eventos reales), reportando velocidad determinista (ev/s), desglose de trades simulados, MakerExit % y Profit Factor. |
| vortex audit | vortex -a | Auditoría del Filtro de Pares (Tick Guard) | Ejecuta la validación de contratos en vortex_tap, mostrando cuáles pares cumplen Tick_bps <= 1.50 bps (🟢 APPROVED) y cuáles son rechazados (🔴 VETOED BY GUARD). |
| vortex oos | vortex -o | Certificación Matemática OOS (520 Trades) | Corre el examen interno fuera de muestra de 520 operaciones de vortex_exec verificando los umbrales institucionales de Profit Factor, Fee Drag y conservación de capital. |
| vortex all | — | Tríada de Certificación Local | Ejecuta en secuencia vortex audit + vortex replay + vortex oos. |

### 4.2. Comandos de Administración de Servicios (systemd) y Despliegue en sniper-singapur (Ubuntu SSH)

* Despliegue en Caliente con Candado COMMIT_SHA y Auditoría vortex 360:
  cd ~/vortex-rs && git fetch origin --tags --force && git reset --hard origin/main && bash deploy/install_sniper_singapur.sh --live-capital && sleep 3 && vortex 360
* Detener de Inmediato el Motor Ejecutor (Pausa Segura):
  sudo systemctl stop vortex-exec.service
* Detener Ambos Demonios (Ejecutor + Ingesta WebSocket):
  sudo systemctl stop vortex-exec.service vortex-tap.service
* Reiniciar el Motor Ejecutor Conservando SHM v9 (HOT-RESTORE):
  sudo systemctl restart vortex-exec.service
* Reiniciar Ambos Demonios:
  sudo systemctl restart vortex-tap.service && sleep 2 && sudo systemctl restart vortex-exec.service
* Reiniciar Contadores en Vivo desde Cero (Ejecutar Solo en Estado IDLE):
  rm -f ~/vortex-rs/data/vortex_shadow_trades.jsonl ~/vortex-rs/data/vortex_ai_forensic_vault.jsonl && sudo systemctl restart vortex-exec.service

### 4.3. Comandos de Desarrollo, Calidad (Clippy + Tests) y Publicación en Windows (PowerShell)

* 1. Verificar 0 Warnings en Clippy:
  cargo clippy --all-targets -- -D warnings
* 2. Compilar y Ejecutar los 29 / 29 Tests Unitarios + LOSS-LAB (36/36):
  cargo test -- --test-threads=1 --nocapture
* 3. Sellar Commit, Rama de Punto de Inflexión y Tag hacia GitHub:
  git add -A; git commit -m "feat(voragine-v0.3): ..."; git branch -f checkpoint/voragine-v0.3-inflection HEAD; git tag -f voragine-v0.3; git push origin main checkpoint/voragine-v0.3-inflection --tags --force

---

## 5. Tabla Completa de Mensajes de Telegram y Telemetría Semántica

| Evento / Categoría | Icono y Encabezado del Mensaje | Condición de Disparo | Variables y Datos Reportados | Significado Operativo |
| :--- | :--- | :--- | :--- | :--- |
| 1. Encendido del Motor en Vivo | 🟢 [VORTEX-L2 ONLINE] | Al inicializar vortex_exec --daemon con credenciales válidas en .env. | Modo (LIVE CAPITAL BYBIT V5 / SHADOW), ABI (SHM v9), frecuencia (200.0 Hz) y estado de rehidratación. | Confirma que el demonio ejecutor y el enlace asíncrono con Telegram están en línea en sniper-singapur. |
| 2. Orden Pasiva Enviada a Bybit | 🟡 [BYBIT V5 LIVE ORDER SENT] | Cuando una señal supera los 3 factores, los 6 escudos y el filtro de cola L1, y Bybit acepta el POST /v5/order/create (Limit PostOnly). | symbol, side (Buy/Sell), qty (lote óptimo 10x), entry_price (USDT), SL (MarkPrice), EWMA (bps) y rachas (W / SL). | La orden pasiva ya descansa en la fila L1 de Bybit con Stop-Loss de servidor adjunto. |
| 3. Entrada Pasiva Ejecutada (Fill) | 🟡 [VORTEX MAKER FILL] / 🟡 [MAKER FILL] | Cuando get_open_position_size confirma que la orden Limit PostOnly fue llenada en Bybit (REAL FILL CONFIRMED o FILL-ON-ABORT RECOVERED). | symbol, side (Bid/Ask), entry_price en USDT y en ticks (t), TP estructural (tp_maker_price) y SL (sl_trigger_price). | Posición real abierta en Bybit pagando tarifa Maker (2.00 bps); comienza la custodia activa sin abandono. |
| 4. Cierre en Victoria Estructural (WIN) | 🟢 [VORTEX TRADE CLOSED — WIN] | Al confirmar size == 0.00 en Bybit con ganancia neta net_bps >= +1.00 bps. | symbol, side, kind (MakerPassiveUnwind / MakerStructuralTp), entry -> exit (USDT), Net: +X.XX bps (+% @10x, +USDT), Total Trades, PF y CumNetPnL. | Ganancia estructural neta tras descontar los 4.00 bps de comisión Maker-Maker. Incrementa win_streak. |
| 5. Cierre Defensivo Cero-Pérdida (SCRATCH) | 🟠 [VORTEX TRADE CLOSED — SCRATCH] | Al confirmar size == 0.00 en Bybit con -0.50 bps <= net_bps < +1.00 bps (+0.02 a +0.95 bps netos en rescate cuántico). | symbol, side, MakerPassiveUnwind, entry -> exit (USDT), Net: +0.XX bps (+USDT), Total Trades, PF y CumNetPnL. | Evacuación defensiva exitosa en verde cubriendo el 100% de las comisiones. No incrementa win_streak (clasificación honesta 🟠 SCRATCH). |
| 6. Cierre por Stop-Loss (LOSS) | 🔴 [VORTEX TRADE CLOSED — LOSS] | Cuando una posición toca el ServerMarkPriceStopLoss (o cierra con net_bps < -0.50 bps). | symbol, side, ServerMarkPriceStopLoss, entry -> exit (USDT), Net: -XX.XX bps (-% @10x, -USDT), Total Trades, PF y CumNetPnL. | Pérdida acotada por barrera de servidor (7.50 bps de tarifa total Maker+Taker). Incrementa sl_streak y activa cuarentena exponencial. |
| 7. Aborto Preventivo de Cola L1 | 🟠 [QUEUE ABORT] | Cuando el flujo L2/cinta se invierte o el BBO huye antes de que la orden en cola L1 se llene. | symbol, side, OFI, TFI, BestBid, BestAsk, Entry y 15s Slot Cooldown. | Orden cancelada sin costo (0.00 USDT) antes del llenado; se registra en journalctl sin saturar Telegram para mantener paridad 1:1. |

---

## 6. Glosario Completo de Términos, Siglas y Variables de VORTEX-L2

* adverse_regime (Régimen Adverso): Condición booleana en step_open_position (joint_adverse || deep_joint_adverse || flow_conviction <= -0.12 || (hold_elapsed >= elastic_zombie_ns && !strong_trend_continuation)) que autoriza relajar el piso de salida desde structural_win_floor hasta el piso cuántico zero_loss_scratch_floor.
* active_win_floor (Piso Activo de Victoria): Nivel de ganancia bruta en ScaledBps interpolado al 55% entre zero_loss_scratch_floor y adaptive_base_target, acotado inferiormente por structural_win_floor (>= 500..550 ScaledBps).
* AUTH_LONG_MKR / AUTH_SHORT_MKR (🟡): Veredicto en el HUD que indica que los 3 factores ortogonales (X_OFI, X_TFI, X_GEOM) están alineados y superan la Barrera de Fricción 3x para abrir un Largo (Bid) o un Corto (Ask) pasivo.
* BBO (Best Bid and Offer): El mejor precio de compra (bids[0]) y el mejor precio de venta (asks[0]) en la punta del libro de órdenes (Nivel 1 / L1).
* bps (Basis Points / Puntos Básicos): Unidad financiera donde 1 bps = 0.01% (100 bps = 1.00%). A apalancamiento 10x, +10.00 bps equivalen a +1.00% sobre el margen utilizado.
* COMMIT_SHA (Candado Criptográfico de Despliegue): Hash SHA-1 de 40 caracteres del commit de Git incrustado dentro del paquete compilado por GitHub Actions para garantizar que sniper-singapur jamás ejecute un binario desfasado.
* convex_ratchet_floor (Trinquete Convexo de MFE): Piso dinámico que sube de forma convexa a medida que crece la ganancia máxima alcanzada (peak_gross_bps), reteniendo entre el 35% y el 76% del beneficio neto máximo para dejar correr tendencias largas sin devolver lo ganado.
* cum_net_bps_x100 / global_dir_debt_bps_x100: Contadores de deuda/ganancia neta acumulada por par/dirección y por dirección global dentro del OnlineAdaptiveGovernor.
* epsilon_elastico: Margen adicional sobre el piso base de salida que decae hiperbólicamente con el cuadrado del tiempo normalizado y el cuadrado de la presión adversa.
* Fee Drag % (Arrastre de Comisión): Porcentaje de la ganancia bruta que se destina a pagar las comisiones del exchange (fee_bps / gross_bps * 100%).
* FILL-ON-ABORT RECOVERED: Mecanismo de rescate atómico que detecta cuando una orden en la cola L1 fue llenada en Bybit milisegundos antes de que llegara la petición de cancelación, adoptando inmediatamente la posición bajo custodia Maker.
* L1 / L2 (Level 1 / Level 2 Order Book): L1 es la mejor punta del libro (BestBid / BestAsk); L2 es la profundidad completa de los 50 niveles de precios y volúmenes (orderbook.50).
* Limit PostOnly (Orden Pasiva Creadora de Liquidez): Tipo de orden que garantiza que siempre entras o sales como Maker (tarifa reducida de 2.00 bps). Si cruzara el spread al llegar al servidor de Bybit, Bybit la rechaza automáticamente en vez de cobrarte como Taker (5.50 bps).
* LOSS-LAB (Laboratorio Contrafactual de Pérdidas): Prueba automatizada en src/execution_fsm.rs que reproduce las 221 operaciones históricas reales (deploy/forensic_vault_171.seed) y certifica que las 29 pérdidas históricas son mitigadas al 100% (33/33).
* MakerPassiveUnwind: Cierre normal de una posición mediante una orden pasiva Limit PostOnly reduceOnly colocada en el lado legal del BBO (BestAsk para cerrar un Largo, BestBid para cerrar un Corto).
* MFE (Maximum Favorable Excursion): La máxima ganancia bruta en ScaledBps o ticks (peak_favorable_price) que una posición abierta ha llegado a tocar a tu favor desde su apertura.
* OOS (Out-of-Sample / Fuera de Muestra): Validación estadística sobre datos que no fueron utilizados para calibrar los parámetros, evitando el sobreajuste (overfitting).
* PAR1 (Anillo Forense Apache Parquet Columnar): Formato binario columnar con verificación de integridad CRC en el que vortex_tap graba en disco los últimos 4,096 segmentos (1,048,576 eventos reales de Bybit) para auditoría Walk-Forward en vortex_replay.
* PF (Profit Factor / Factor de Beneficio): Razón entre la suma de todas las ganancias netas y el valor absoluto de todas las pérdidas netas (Sum Net Wins / |Sum Net Losses|). Cuando hay 0 pérdidas, se acota en 9.99 (pf_x100 = 999).
* PriceTicks y LotQty: Unidades discretas indivisibles de precio y cantidad de cada contrato en Bybit (por ejemplo, en BTCUSDT, 1 PriceTick = 0.10 USDT y 1 LotQty = 0.001 BTC).
* Quantum Floor (quantum_floor_px / zero_loss_scratch_floor): Piso físico mínimo de conservación de capital que equivale exactamente a la comisión redonda Maker-Maker (4.00 bps) más +1 tick discreto a favor.
* ScaledBps: Entero de 64 bits que representa centésimas de punto básico (100 ScaledBps = 1.00 bps = 0.01%; 400 ScaledBps = 4.00 bps).
* Seqlock (Sequence Lock en SHM v9): Protocolo atómico de sincronización en /dev/shm/vortex_lob.mmap donde el escritor (vortex_tap) incrementa un contador de secuencia impar/par y el lector (vortex_exec) lee sin usar mutex ni bloquear el kernel en < 50 ns.
* ServerMarkPriceStopLoss: Orden de protección de emergencia alojada directamente en los servidores de Bybit que se activa por el Precio de Marca (MarkPrice) para evitar liquidaciones por mechas manipuladas.
* SHM HOT-RESTORE: Capacidad de vortex_exec de reiniciarse o actualizar su binario en milisegundos leyendo el estado vivo en /dev/shm/vortex_lob.mmap y reconciliándolo con Bybit ([BYBIT V5 LIVE SYNC]) sin abandonar jamás una posición abierta.
* SPOOF_VETO (🟠): Bloqueo automático cuando aparece volumen falso en el libro L2 (X_OFI) mientras las ejecuciones reales en la cinta (X_TFI) van en dirección contraria.
* SPRT (Sequential Probability Ratio Test de Abraham Wald): Prueba estadística secuencial que evalúa en cada milisegundo si la trayectoria de una posición abierta sigue perteneciendo al régimen de tendencia favorable o al de estancamiento/reversión.
* structural_win_floor: Piso mínimo de cosecha en flujo sano ((400 + vol_5m / 60).clamp(500, 550).max(zero_loss_scratch_floor)), que asegura al menos +1.00 a +1.50 bps netos por operación y evita el troceo de olas en BTCUSDT y ETHUSDT.
* wider_origin (Ancla de Extremo Real de Ola): Regla en seed_historical_price que actualiza wave_anchor_px_1e4 cada vez que el mercado marca un origen más amplio (en_1e4 < prev_anc en Bid, en_1e4 > prev_anc en Ask), garantizando que el escudo anti-escalera (VETO_WAVE_STAIRCASE_25BPS) mida siempre la excursión total real de la ola vigente.
* X_OFI, X_TFI, X_GEOM: Los tres puntajes normalizados en [-1.00, +1.00] que miden respectivamente la presión del libro L2 (OFI), la agresión en la cinta de transacciones (TFI) y la inclinación geométrica de los primeros 10 niveles (GEOM).
