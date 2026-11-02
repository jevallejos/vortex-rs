# VORTEX-L2 - Institutional Low-Latency Execution Core (VORTEX-RS-V1.0 | Stage 35 Certified)

Motor institucional HFT en Rust (edition = 2021) para Bybit UTA V5 con memoria compartida POSIX (/dev/shm/vortex_lob.mmap - SHM v9), modelo ortogonal de 3 factores (X_OFI, X_TFI, X_Geom), simulador FIFO L1 (> 2,050M ev/s), Gobernador con 6 Escudos Anti-Perdida, Salida de 5 Fases Anti-Zombi y Trinquete Convexo Progresivo.

## 1. Punto de Inflexion Certificado (Stage 35 - 21/21 Tests & 0 Warnings Clippy)
- Rama de Respaldo en GitHub: checkpoint/stage-35-inflection-point
- Tag Inmutable en GitHub: v1.0-stage35-inflection
- Test #17 (OOS Gate): 520 trades verificados (80.00% Maker, PF = 1.92, Drift = 0).
- Test #18 (LOSS-LAB 138 Trades): 20/20 (100.0%) perdidas historicas mitigadas (-870.32 bps erradicados), pasando de -613.94 bps (PF 0.29) a +96.06 bps base (+203.37 bps con expansion de olas, PF 9.99).
- Test #19 y #20 (Anti-Zombie 5 Fases & Red-Team 5 Vectores): Rescate breakeven a 120s (+0.05 bps), evacuacion en entry_price a 180s (-4.00 bps) y bailout bajo el agua en BBO a 210s + bloqueo de 10,000 rafagas de Spoofing.
- Test #21 (Stage 35 Winner Expansion): Elimina guillotina de 35s y aplica colchon de 2.50 bps en Zona 2 (800..1150) + trinquete 70% (> 1150), expandiendo olas ganadoras de +2.50 bps a +15.00 bps netos (6.0x).

## 2. Los 6 Escudos Estructurales de Entrada (OnlineAdaptiveGovernor)
1. VETO_SLOT_COOLDOWN: Enfriamiento por celda tras victoria (60s -> 150s -> 360s), 90s tras SCRATCH y cuarentena exponencial tras SL (300s -> 2400s).
2. VETO_GLOBAL_WAVE_OR_SL_BREATHER: Pausa global de 180s en toda la direccion (Bid o Ask) tras 3 victorias globales consecutivas o tras un SL.
3. VETO_WAVE_STAIRCASE_25BPS: Bloquea persecucion de ola cuando win_streak >= 2 y el precio se alejo > +25.00 bps del ancla.
4. VETO_DEEP_SCAR_DEBT_QUARANTINE: Bloquea celdas con sl_streak >= 1 y deuda <= -45.00 bps.
5. VETO_ALTCOIN_COUNTER_CASCADE & VETO_POST_SL_OPPOSITE_DOMINANCE: Impide que Altcoins abran contra cascadas activas sin confirmacion de BTCUSDT (Slot 0).
6. VETO_SYMBOL_AND_GLOBAL_DEBT_CONTAGION: Bloquea lados virgenes en Altcoins con deficit neto <= -25.00 bps cuando la deuda global supera -100.00 bps.

## 3. Clasificacion Semantica Honesta (Consola, Ledger y Telegram)
- WIN (Verde): net_bps >= +1.00 bps (Ganancia estructural real).
- SCRATCH (Naranjo): -0.50 bps <= net_bps < +1.00 bps (Rescate defensivo, icono naranjo en Telegram, no infla win_streak).
- LOSS (Rojo): net_bps < -0.50 bps.

## 4. Comandos en Antigravity (Windows PowerShell)
    cargo test -- --test-threads=1 --nocapture
    cargo clippy --all-targets -- -D warnings

## 5. Protocolo de Rollback Instantaneo al Punto de Inflexion (Stage 35)
    git fetch origin --tags --force
    git checkout main
    git reset --hard origin/checkpoint/stage-35-inflection-point
    git push origin main --force

## 6. Comandos de Servicio en sniper-singapur (Ubuntu SSH)
    sudo systemctl stop vortex-exec.service vortex-tap.service vortex-maint.timer
    sudo systemctl start vortex-tap.service vortex-exec.service && vortex status
