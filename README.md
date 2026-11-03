# VORTEX-L2 (Voragine V0.2) - Institutional Low-Latency Execution Core

Motor institucional HFT en Rust (edition = 2021) para Bybit UTA V5 con SHM v9,
modelo ortogonal SNR (X_OFI, X_TFI, X_Geom), superficie continua C1/C2,
autoaprendizaje MFE real y Gobernador con 6 Escudos (29/29 perdidas mitigadas).

## 1. Punto de Inflexion Certificado (Voragine V0.2 - 21/21 Tests & 0 Warnings)
- Rama de Respaldo Actual: checkpoint/voragine-v0.2-inflection
- Rama de Respaldo Previa: checkpoint/stage-35-inflection-point
- Tag en GitHub: voragine-v0.2
- Test #17 (OOS Gate): 520 trades (80.00% Maker, PF = 2.17, +67.1060 USDT, Drift = 0).
- Test #18 (LOSS-LAB 171 Trades): 29/29 (100.0%) perdidas historicas mitigadas.
- Walk-Forward PAR1 Replay (1,048,576 eventos): +14.32 bps netos, 100% Maker, PF = 9.99.

## 2. Comandos en Antigravity (Windows PowerShell)
    cargo test -- --test-threads=1 --nocapture
    cargo clippy --all-targets -- -D warnings

## 3. Protocolo de Rollback Instantaneo a Voragine V0.2
    git fetch origin --tags --force
    git checkout main
    git reset --hard origin/checkpoint/voragine-v0.2-inflection
    git push origin main --force
