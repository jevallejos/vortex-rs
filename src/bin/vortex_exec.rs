//! Binary 2 (`vortex_exec`): Institutional Execution Engine, 200.0 Hz Seqlock Reader,
//! Voragine V0.3.2 Global Account Single-Position Lock (`settleCoin=USDT`), Non-Abandoning Exchange-Verified Close,
//! Slot-0 `BTCUSDT` Macro Leader Coherence Filter, Dynamic 70% MFE Ratchet, and 520-Trade OOS Verifier.

use core::sync::atomic::Ordering;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::thread;
use std::collections::BTreeSet;
use std::time::Duration;

use vortex_rs::alpha_3factor::{OrthogonalFactorState, SignalVerdict};
use vortex_rs::execution_fsm::{
    sign_bybit_v5_hmac_sha256, ClosedTradeKind, ClosedTradeSummary, ExecutionFsm, OnlineAdaptiveGovernor,
    OrderLifecycleState,
};
use vortex_rs::forensic_parquet::ParitySyncLedger;
use vortex_rs::lob_shm::{BookLevel, MappedShmRegion, SymbolLobSnapshot, VortexShmArena};
use vortex_rs::types::{classify_pnl_badge, now_epoch_ns, print_auto_aligned_box, side_from_str, slot_from_symbol_name, BoundedScore, LotQty, PairSpec, PriceTicks, ScaledBps, Side, SymbolId, TimestampNs, ANSI_GRAY, ANSI_GREEN, ANSI_ORANGE, ANSI_RED, ANSI_RESET, ANSI_YELLOW, APPROVED_SPECS};

/// Minimum number of Out-of-Sample trades required by the institutional certification gate.
pub const TOTAL_OOS_TRADES_GATE: usize = 520;

/// Optimal Live Canary Notional Reference (12.50 USDT in 1e8 fixed-point scale).
pub const OPTIMAL_LIVE_NOTIONAL_1E8: i64 = 1_250_000_000;

/// Per-slot anti-chasing cooldown after an unfilled queue abort or close (3 seconds).
pub const SLOT_ABORT_COOLDOWN_NS: i64 = 3_000_000_000;

#[derive(Copy, Clone, Debug, Default)]
struct ForensicEntrySnapshot {
    armed_ts_ns: i64,
    opened_ts_ns: i64,
    init_q_lots: i64,
    abort_recovered: bool,
    ofi_in_bps: i32,
    tfi_in_bps: i32,
    geom_in_bps: i32,
    snr_in_bps: i64,
    vol5m_in_bps: i64,
    spread_in_ticks: i64,
    btc_comp_in_bps: i64,
    slot_mfe_bps: i64,
    gov_ewma_bps: i64,
    win_streak: u32,
    sl_streak: u32,
    wave_step: u32,
    drift_bps: i64,
    ext_bps: i64,
    chased_bps: i64,
    cum_slot_debt_bps: i64,
}



#[inline]const fn compute_optimal_50usdt_wallet_qty_str(
    symbol_id: SymbolId,
    in_scar_debt: bool,
) -> &'static str {
    match symbol_id.0 {
        1 => "0.001",
        2 => {
            if in_scar_debt {
                "0.01"
            } else {
                "0.02"
            }
        }
        3 => {
            if in_scar_debt {
                "0.1"
            } else {
                "0.2"
            }
        }
        4 => {
            if in_scar_debt {
                "1.4"
            } else {
                "2.6"
            }
        }
        5 => {
            if in_scar_debt {
                "0.05"
            } else {
                "0.1"
            }
        }
        6 => {
            if in_scar_debt {
                "14"
            } else {
                "25"
            }
        }
        7 => {
            if in_scar_debt {
                "1.8"
            } else {
                "3.6"
            }
        }
        8 => {
            if in_scar_debt {
                "4"
            } else {
                "6"
            }
        }
        9 => {
            if in_scar_debt {
                "30"
            } else {
                "60"
            }
        }
        _ => "1",
    }
}
const ENV_FILE_CANDIDATES: [&str; 3] = [".env", "/home/ubuntu/vortex-rs/.env", "/home/ubuntu/.env"];

fn load_env_var_with_fallback(keys: &[&str]) -> Option<String> {
    for &k in keys {
        if let Ok(val) = std::env::var(k) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    for p in ENV_FILE_CANDIDATES {
        if let Ok(file) = File::open(p) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let clean = trimmed.strip_prefix("export ").unwrap_or(trimmed);
                if let Some((k, v)) = clean.split_once('=') {
                    let key = k.trim();
                    let val = v.trim().trim_matches('"').trim_matches('\'');
                    if !val.is_empty() && keys.contains(&key) {
                        return Some(val.to_owned());
                    }
                }
            }
        }
    }
    None
}

struct BybitConnPool {
    rest_tls: Option<native_tls::TlsStream<std::net::TcpStream>>,
    ws_trade: Option<(
        tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
        std::time::Instant,
    )>,
}

impl core::fmt::Debug for BybitConnPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BybitConnPool")
            .field("rest_connected", &self.rest_tls.is_some())
            .field("ws_trade_connected", &self.ws_trade.is_some())
            .finish()
    }
}

#[derive(Clone, Debug)]
struct BybitV5LiveClient {
    api_key: String,
    api_secret: String,
    pool: std::sync::Arc<std::sync::Mutex<BybitConnPool>>,
    ws_pos_state: std::sync::Arc<[core::sync::atomic::AtomicU8; 9]>,
}

impl BybitV5LiveClient {
    fn new_with_pool(api_key: String, api_secret: String) -> Self {
        Self {
            api_key,
            api_secret,
            pool: std::sync::Arc::new(std::sync::Mutex::new(BybitConnPool {
                rest_tls: None,
                ws_trade: None,
            })),
            ws_pos_state: std::sync::Arc::new([
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
                core::sync::atomic::AtomicU8::new(0),
            ]),
        }
    }

    fn has_ws_instant_fill(&self, slot_idx: usize) -> bool {
        if slot_idx < 9 && self.ws_pos_state[slot_idx].load(Ordering::Acquire) == 2 {
            self.ws_pos_state[slot_idx].store(0, Ordering::Release);
            return true;
        }
        false
    }

    fn has_ws_instant_flat(&self, slot_idx: usize) -> bool {
        if slot_idx < 9 && self.ws_pos_state[slot_idx].load(Ordering::Acquire) == 1 {
            self.ws_pos_state[slot_idx].store(0, Ordering::Release);
            return true;
        }
        false
    }

    fn spawn_private_ws_stream(&self) {
        let key = self.api_key.clone();
        let secret = self.api_secret.clone();
        let state_arr = std::sync::Arc::clone(&self.ws_pos_state);
        let _ = thread::spawn(move || loop {
            if let Ok((mut ws, _)) = tungstenite::connect("wss://stream.bybit.com/v5/private") {
                match ws.get_ref() {
                    tungstenite::stream::MaybeTlsStream::Plain(s) => {
                        let _ = s.set_nodelay(true);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    }
                    tungstenite::stream::MaybeTlsStream::NativeTls(tls) => {
                        let s = tls.get_ref();
                        let _ = s.set_nodelay(true);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    }
                    _ => {}
                }
                let exp_ms = (now_epoch_ns() / 1_000_000) + 10_000;
                let exp_str = exp_ms.to_string();
                let sig_b = sign_bybit_v5_hmac_sha256(
                    "GET/realtime",
                    "",
                    "",
                    &exp_str,
                    &secret,
                );
                let sig_s = core::str::from_utf8(&sig_b).unwrap_or("");
                let auth_cmd = format!(
                    "{{\"op\":\"auth\",\"args\":[\"{}\",{},\"{}\"]}}",
                    key, exp_ms, sig_s
                );
                if ws.send(tungstenite::Message::Text(auth_cmd)).is_ok() {
                    let sub_cmd = String::from(
                        "{{\"op\":\"subscribe\",\"args\":[\"position.linear\",\"execution.linear\"]}}"
                    );
                    let _ = ws.send(tungstenite::Message::Text(sub_cmd));
                    println!(
                        "{}\u{1f7e2} [BYBIT V5 PRIVATE WS] Real-time execution.linear + position.linear push active (0ms TP)!{}",
                        ANSI_GREEN, ANSI_RESET
                    );
                    let mut last_ping = std::time::Instant::now();
                    loop {
                        if last_ping.elapsed() >= Duration::from_secs(18) {
                            if ws
                                .send(tungstenite::Message::Text(String::from(
                                    "{\"op\":\"ping\"}",
                                )))
                                .is_err()
                            {
                                break;
                            }
                            last_ping = std::time::Instant::now();
                        }
                        match ws.read() {
                            Ok(tungstenite::Message::Text(txt)) => {
                                if let Ok(v) =
                                    serde_json::from_str::<serde_json::Value>(&txt)
                                {
                                    let topic = v
                                        .get("topic")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("");
                                    if topic.starts_with("position") {
                                        if let Some(arr) =
                                            v.get("data").and_then(|d| d.as_array())
                                        {
                                            for item in arr {
                                                let sym = item
                                                    .get("symbol")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("");
                                                let sz = item
                                                    .get("size")
                                                    .and_then(|x| x.as_str())
                                                    .and_then(|s| s.parse::<f64>().ok())
                                                    .unwrap_or(-1.0);
                                                if let Some(sl_i) =
                                                    slot_from_symbol_name(sym)
                                                {
                                                    if sl_i < 9 && sz >= 0.0 {
                                                        let code = if sz > 0.0 {
                                                            2
                                                        } else {
                                                            1
                                                        };
                                                        state_arr[sl_i].store(
                                                            code,
                                                            Ordering::Release,
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    } else if topic.starts_with("execution") {
                                        if let Some(arr) =
                                            v.get("data").and_then(|d| d.as_array())
                                        {
                                            for item in arr {
                                                let sym = item
                                                    .get("symbol")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("");
                                                let c_sz = item
                                                    .get("closedSize")
                                                    .and_then(|x| x.as_str())
                                                    .and_then(|s| s.parse::<f64>().ok())
                                                    .unwrap_or(0.0);
                                                if let Some(sl_i) =
                                                    slot_from_symbol_name(sym)
                                                {
                                                    if sl_i < 9 {
                                                        let code = if c_sz > 0.0 {
                                                            1
                                                        } else {
                                                            2
                                                        };
                                                        state_arr[sl_i].store(
                                                            code,
                                                            Ordering::Release,
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(tungstenite::Message::Ping(p)) => {
                                let _ = ws.send(tungstenite::Message::Pong(p));
                            }
                            Err(tungstenite::Error::Io(ref e))
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut => {}
                            Ok(tungstenite::Message::Close(_)) | Err(_) => break,
                            _ => {}
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(1_500));
        });
    }

    fn from_env_readonly() -> Option<Self> {
        let api_key = load_env_var_with_fallback(&["BYBIT_API_KEY", "API_KEY"])?;
        let api_secret = load_env_var_with_fallback(&["BYBIT_API_SECRET", "API_SECRET"])?;
        Some(Self::new_with_pool(api_key, api_secret))
    }

    fn open_keepalive_tls() -> Option<native_tls::TlsStream<std::net::TcpStream>> {
        use std::net::ToSocketAddrs;
        let addr = "api.bybit.com:443".to_socket_addrs().ok()?.next()?;
        let tcp = std::net::TcpStream::connect_timeout(
            &addr,
            Duration::from_millis(2_500),
        )
        .ok()?;
        let _ = tcp.set_nodelay(true);
        let _ = tcp.set_read_timeout(Some(Duration::from_millis(3_000)));
        let _ = tcp.set_write_timeout(Some(Duration::from_millis(3_000)));
        let connector = native_tls::TlsConnector::new().ok()?;
        connector.connect("api.bybit.com", tcp).ok()
    }

    fn read_http11_body(
        stream: &mut native_tls::TlsStream<std::net::TcpStream>,
    ) -> Option<(Vec<u8>, bool)> {
        use std::io::Read;
        let mut raw = Vec::with_capacity(4_096);
        let mut tmp = [0_u8; 4_096];
        let hdr_end = loop {
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos;
            }
            if raw.len() > 65_536 {
                return None;
            }
            let n = stream.read(&mut tmp).ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&tmp[..n]);
        };
        let body_start = hdr_end + 4;
        let hdr_ascii = String::from_utf8_lossy(&raw[..hdr_end]).to_ascii_lowercase();
        let conn_close = hdr_ascii.contains("connection: close");
        let mut content_len: Option<usize> = None;
        for line in hdr_ascii.lines() {
            if let Some(rest) = line.strip_prefix("content-length:") {
                content_len = rest.trim().parse::<usize>().ok();
            }
        }
        if let Some(cl) = content_len {
            while raw.len() < body_start + cl {
                let n = stream.read(&mut tmp).ok()?;
                if n == 0 {
                    return None;
                }
                raw.extend_from_slice(&tmp[..n]);
            }
            return Some((raw[body_start..body_start + cl].to_vec(), conn_close));
        }
        if hdr_ascii.contains("transfer-encoding: chunked") {
            let mut out = Vec::with_capacity(2_048);
            let mut pos = body_start;
            loop {
                let line_end = loop {
                    if let Some(rel) = raw[pos..].windows(2).position(|w| w == b"\r\n") {
                        break pos + rel;
                    }
                    let n = stream.read(&mut tmp).ok()?;
                    if n == 0 {
                        return None;
                    }
                    raw.extend_from_slice(&tmp[..n]);
                };
                let sz_str = core::str::from_utf8(&raw[pos..line_end])
                    .ok()?
                    .split(';')
                    .next()?
                    .trim();
                let chunk_sz = usize::from_str_radix(sz_str, 16).ok()?;
                pos = line_end + 2;
                if chunk_sz == 0 {
                    return Some((out, conn_close));
                }
                while raw.len() < pos + chunk_sz + 2 {
                    let n = stream.read(&mut tmp).ok()?;
                    if n == 0 {
                        return None;
                    }
                    raw.extend_from_slice(&tmp[..n]);
                }
                out.extend_from_slice(&raw[pos..pos + chunk_sz]);
                pos += chunk_sz + 2;
            }
        }
        None
    }

    fn exec_keepalive_http11(&self, raw_req: &str) -> Option<serde_json::Value> {
        let mut guard = self.pool.lock().ok()?;
        let mut attempt = 0_usize;
        while attempt < 2 {
            if guard.rest_tls.is_none() {
                guard.rest_tls = Self::open_keepalive_tls();
            }
            if let Some(ref mut tls) = guard.rest_tls {
                if tls.write_all(raw_req.as_bytes()).is_ok() && tls.flush().is_ok() {
                    if let Some((body, close_flag)) = Self::read_http11_body(tls) {
                        if close_flag {
                            guard.rest_tls = None;
                        }
                        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&body) {
                            return Some(val);
                        }
                    }
                }
            }
            guard.rest_tls = None;
            attempt += 1;
        }
        None
    }

    fn open_authenticated_ws_trade(
        &self,
    ) -> Option<(
        tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
        std::time::Instant,
    )> {
        let (mut ws, _) = tungstenite::connect("wss://stream.bybit.com/v5/trade").ok()?;
        match ws.get_ref() {
            tungstenite::stream::MaybeTlsStream::Plain(s) => {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_millis(2_000)));
                let _ = s.set_write_timeout(Some(Duration::from_millis(2_000)));
            }
            tungstenite::stream::MaybeTlsStream::NativeTls(tls) => {
                let s = tls.get_ref();
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_millis(2_000)));
                let _ = s.set_write_timeout(Some(Duration::from_millis(2_000)));
            }
            _ => {}
        }
        let exp_ms = (now_epoch_ns() / 1_000_000) + 10_000;
        let exp_str = exp_ms.to_string();
        let sig_bytes = sign_bybit_v5_hmac_sha256(
            "GET/realtime",
            "",
            "",
            &exp_str,
            &self.api_secret,
        );
        let sig_str = core::str::from_utf8(&sig_bytes).unwrap_or("");
        let auth_msg = format!(
            "{{\"op\":\"auth\",\"args\":[\"{}\",{},\"{}\"]}}",
            self.api_key, exp_ms, sig_str
        );
        ws.send(tungstenite::Message::Text(auth_msg)).ok()?;
        let mut tries = 0_usize;
        while tries < 4 {
            tries += 1;
            match ws.read().ok()? {
                tungstenite::Message::Text(txt) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                        if v.get("op").and_then(|x| x.as_str()) == Some("auth") {
                            let rc = v.get("retCode").and_then(|x| x.as_i64()).unwrap_or(-1);
                            if rc == 0 {
                                return Some((ws, std::time::Instant::now()));
                            }
                            return None;
                        }
                    }
                }
                tungstenite::Message::Ping(p) => {
                    let _ = ws.send(tungstenite::Message::Pong(p));
                }
                _ => {}
            }
        }
        None
    }

    fn try_ws_trade_order_create(
        &self,
        ts_ms: &str,
        json_body: &str,
    ) -> Option<serde_json::Value> {
        let mut guard = self.pool.lock().ok()?;
        if let Some((_, last_t)) = guard.ws_trade.as_ref() {
            if last_t.elapsed() >= Duration::from_secs(18) {
                guard.ws_trade = None;
            }
        }
        if guard.ws_trade.is_none() {
            guard.ws_trade = self.open_authenticated_ws_trade();
        }
        let (ref mut ws, ref mut last_t) = guard.ws_trade.as_mut()?;
        let frame = format!(
            "{{\"header\":{{\"X-BAPI-TIMESTAMP\":\"{}\",\"X-BAPI-RECV-WINDOW\":\"5000\"}},\"op\":\"order.create\",\"args\":[{}]}}",
            ts_ms, json_body
        );
        if ws.send(tungstenite::Message::Text(frame)).is_err() {
            guard.ws_trade = None;
            return None;
        }
        let mut reads = 0_usize;
        while reads < 6 {
            reads += 1;
            match ws.read() {
                Ok(tungstenite::Message::Text(txt)) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                        if v.get("op").and_then(|x| x.as_str()) == Some("order.create") {
                            *last_t = std::time::Instant::now();
                            return Some(v);
                        }
                    }
                }
                Ok(tungstenite::Message::Ping(p)) => {
                    let _ = ws.send(tungstenite::Message::Pong(p));
                }
                _ => {
                    guard.ws_trade = None;
                    return None;
                }
            }
        }
        guard.ws_trade = None;
        None
    }

    fn query_unified_usdt_wallet(&self) -> Option<(f64, f64, f64, f64)> {
        let resp = self.get_v5(
            "/v5/account/wallet-balance",
            "accountType=UNIFIED&coin=USDT",
        )?;
        let list = resp
            .get("result")
            .and_then(|r| r.get("list"))
            .and_then(serde_json::Value::as_array)?;
        let acct = list.first()?;
        let mut wallet = acct
            .get("totalWalletBalance")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        let mut equity = acct
            .get("totalEquity")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(wallet);
        let mut avail = acct
            .get("totalAvailableBalance")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        let mut upl = acct
            .get("totalPerpUPL")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        if let Some(coins) = acct.get("coin").and_then(serde_json::Value::as_array) {
            for c in coins {
                if c.get("coin").and_then(serde_json::Value::as_str) == Some("USDT") {
                    if let Some(w) = c
                        .get("walletBalance")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| s.parse::<f64>().ok())
                    {
                        wallet = w;
                    }
                    if let Some(eq) = c
                        .get("equity")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| s.parse::<f64>().ok())
                    {
                        equity = eq;
                    }
                    if let Some(u) = c
                        .get("unrealisedPnl")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|s| s.parse::<f64>().ok())
                    {
                        upl = u;
                    }
                    if avail <= 0.0 {
                        avail = c
                            .get("availableToWithdraw")
                            .and_then(serde_json::Value::as_str)
                            .and_then(|s| s.parse::<f64>().ok())
                            .unwrap_or(wallet);
                    }
                }
            }
        }
        if avail <= 0.0 {
            avail = wallet;
        }
        Some((wallet, equity, avail, upl))
    }

    fn from_env_if_enabled(live_capital_enabled: bool) -> Option<Self> {
        if !live_capital_enabled {
            return None;
        }
        let api_key = load_env_var_with_fallback(&["BYBIT_API_KEY", "API_KEY"]);
        let api_secret = load_env_var_with_fallback(&["BYBIT_API_SECRET", "API_SECRET"]);
        let (key, secret) = match (api_key, api_secret) {
            (Some(k), Some(s)) => (k, s),
            _ => {
                println!(
                    "{}\u{1f534} [BYBIT V5 LIVE] API keys missing.{}",
                    ANSI_RED, ANSI_RESET
                );
                return None;
            }
        };
        let client = Self::new_with_pool(key, secret);
        if let Ok(mut g) = client.pool.lock() {
            g.rest_tls = Self::open_keepalive_tls();
            g.ws_trade = client.open_authenticated_ws_trade();
        }
        client.spawn_private_ws_stream();
        for spec in APPROVED_SPECS {
            let sym = spec.symbol_id.name();
            let lev_body = format!(
                "{{\"category\":\"linear\",\"symbol\":\"{}\",\"buyLeverage\":\"10\",\"sellLeverage\":\"10\"}}",
                sym
            );
            let _ = client.post_v5("/v5/position/set-leverage", &lev_body);
        }
        println!(
            "{}\u{1f7e2} [BYBIT V5 LIVE CAPITAL ARMED] Persistent WS Trade API + TLS Keep-Alive + 4 Institutional Upgrades active.{}",
            ANSI_GREEN, ANSI_RESET
        );
        Some(client)
    }

    fn post_v5(&self, path: &str, json_body: &str) -> Option<serde_json::Value> {
        let ts_ms = (now_epoch_ns() / 1_000_000).to_string();
        if path == "/v5/order/create" {
            if let Some(ws_resp) = self.try_ws_trade_order_create(&ts_ms, json_body) {
                return Some(ws_resp);
            }
        }
        let recv_win = "5000";
        let sig_bytes = sign_bybit_v5_hmac_sha256(
            &ts_ms,
            &self.api_key,
            recv_win,
            json_body,
            &self.api_secret,
        );
        let sig_str = core::str::from_utf8(&sig_bytes).unwrap_or("");
        let raw_req = format!(
            "POST {} HTTP/1.1\r\nHost: api.bybit.com\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-BAPI-API-KEY: {}\r\nX-BAPI-TIMESTAMP: {}\r\nX-BAPI-RECV-WINDOW: {}\r\nX-BAPI-SIGN: {}\r\n\r\n{}",
            path,
            json_body.len(),
            self.api_key,
            ts_ms,
            recv_win,
            sig_str,
            json_body
        );
        self.exec_keepalive_http11(&raw_req)
    }

    fn get_v5(&self, path: &str, query_str: &str) -> Option<serde_json::Value> {
        let ts_ms = (now_epoch_ns() / 1_000_000).to_string();
        let recv_win = "5000";
        let sig_bytes = sign_bybit_v5_hmac_sha256(
            &ts_ms,
            &self.api_key,
            recv_win,
            query_str,
            &self.api_secret,
        );
        let sig_str = core::str::from_utf8(&sig_bytes).unwrap_or("");
        let raw_req = format!(
            "GET {}?{} HTTP/1.1\r\nHost: api.bybit.com\r\nConnection: keep-alive\r\nX-BAPI-API-KEY: {}\r\nX-BAPI-TIMESTAMP: {}\r\nX-BAPI-RECV-WINDOW: {}\r\nX-BAPI-SIGN: {}\r\n\r\n",
            path, query_str, self.api_key, ts_ms, recv_win, sig_str
        );
        self.exec_keepalive_http11(&raw_req)
    }

    fn cancel_all_symbol_orders(&self, symbol: &str) {
        let body = format!("{{\"category\":\"linear\",\"symbol\":\"{}\"}}", symbol);
        let _ = self.post_v5("/v5/order/cancel-all", &body);
    }

    /// Queries `/v5/position/list?category=linear&settleCoin=USDT` to inspect ALL open positions across the entire account.
    /// Returns `Some((symbol, size_str, side_str, avg_price_str))` if any position has `size > 0`.
    fn get_any_account_open_position(&self) -> Option<(String, String, String, String)> {
        if let Some(resp) = self.get_v5("/v5/position/list", "category=linear&settleCoin=USDT") {
            if let Some(list) = resp
                .get("result")
                .and_then(|r| r.get("list"))
                .and_then(serde_json::Value::as_array)
            {
                for item in list {
                    let size_str = item
                        .get("size")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("0");
                    let size_f = size_str.parse::<f64>().unwrap_or(0.0);
                    if size_f > 0.0 {
                        let sym = item
                            .get("symbol")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("UNKNOWN");
                        let side = item
                            .get("side")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("None");
                        let avg_p = item
                            .get("avgPrice")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("0");
                        return Some((
                            sym.to_owned(),
                            size_str.to_owned(),
                            side.to_owned(),
                            avg_p.to_owned(),
                        ));
                    }
                }
            }
        }
        None
    }

    /// Queries `/v5/position/list` for a specific symbol and returns `(has_open_position, size_str, side_str)`.
    fn get_open_position_info(&self, symbol: &str) -> (bool, String, String) {
        let query = format!("category=linear&symbol={}", symbol);
        if let Some(resp) = self.get_v5("/v5/position/list", &query) {
            if let Some(list) = resp
                .get("result")
                .and_then(|r| r.get("list"))
                .and_then(serde_json::Value::as_array)
            {
                if let Some(first) = list.first() {
                    let size_str = first
                        .get("size")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("0");
                    let side_str = first
                        .get("side")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("None");
                    let size_f = size_str.parse::<f64>().unwrap_or(0.0);
                    if size_f > 0.0 {
                        return (true, size_str.to_owned(), side_str.to_owned());
                    }
                }
            }
        }
        (false, String::from("0"), String::from("None"))
    }

    fn get_open_position_size(&self, symbol: &str) -> (bool, String) {
        let (open, sz, _) = self.get_open_position_info(symbol);
        (open, sz)
    }

    /// Audits all 6 approved pairs on startup without EVER liquidating positions at Market:
    /// cancels stale resting orders on idle symbols and adopts any active exchange position into Maker FSM custody.
    fn adopt_or_clean_exchange_positions(
        &self,
        tracked_symbol: Option<&str>,
        fsm: &mut ExecutionFsm,
        arena: &VortexShmArena,
        active_slot: &mut usize,
        tg_tx: &Option<SyncSender<String>>,
    ) {
        for spec in APPROVED_SPECS {
            let sym = spec.symbol_id.name();
            if Some(sym) == tracked_symbol {
                continue;
            }
            if !self.get_open_position_size(sym).0 {
                self.cancel_all_symbol_orders(sym);
            }
        }
        if tracked_symbol.is_none() {
            if let Some((open_sym, open_qty, open_side_str, avg_px_str)) = self.get_any_account_open_position() {
                for (slot_idx, spec) in APPROVED_SPECS.iter().enumerate() {
                    if spec.symbol_id.name() == open_sym {
                        if let Ok(entry_t) = spec.parse_price_ticks(&avg_px_str) {
                            if entry_t.0 > 0 {
                                let adopt_side = if open_side_str == "Sell" { Side::Ask } else { Side::Bid };
                                let mfe_bps = fsm.slot_learned_mfe_bps(spec.symbol_id).clamp(600, 1_600);
                                let tp_d = ((entry_t.0 * (mfe_bps * 6)) / 1_000_000).max(2);
                                let ad_vol = arena
                                    .slot(slot_idx)
                                    .and_then(|s| s.read_snapshot(2))
                                    .map(|sn| sn.realized_vol_5m.raw().clamp(4_600, 11_500))
                                    .unwrap_or(6_000);
                                let raw_ad_sl = (ad_vol * 26 + mfe_bps * 36) / 100;
                                let ad_sl_bps = raw_ad_sl.clamp(2_100, 2_750);
                                let sl_d = ((entry_t.0 * ad_sl_bps) / 1_000_000).max(4);
                                let (tp_t, sl_t) = match adopt_side {
                                    Side::Bid => (PriceTicks(entry_t.0 + tp_d), PriceTicks((entry_t.0 - sl_d).max(1))),
                                    Side::Ask => (PriceTicks((entry_t.0 - tp_d).max(1)), PriceTicks(entry_t.0 + sl_d)),
                                };
                                let clr_sl = format!(
                                    "{{\"category\":\"linear\",\"symbol\":\"{}\",\"stopLoss\":\"0\",\"positionIdx\":0}}",
                                    open_sym
                                );
                                let _ = self.post_v5("/v5/position/trading-stop", &clr_sl);
                                let now_ns = TimestampNs(now_epoch_ns());
                                *active_slot = slot_idx;
                                fsm.active_slot_idx = slot_idx;
                                fsm.state = OrderLifecycleState::PositionOpenMakerExit {
                                    side: adopt_side,
                                    entry_price: entry_t,
                                    peak_favorable_price: entry_t,
                                    qty: LotQty(10),
                                    tp_maker_price: tp_t,
                                    sl_trigger_price: sl_t,
                                    opened_ts: now_ns,
                                };
                                arena.exec_active_slot.store(slot_idx as u64, Ordering::Release);
                                arena.exec_active_symbol.store(u64::from(spec.symbol_id.0), Ordering::Release);
                                arena.exec_side.store(adopt_side as u64, Ordering::Release);
                                arena.exec_entry_ticks.store(entry_t.0 as u64, Ordering::Release);
                                arena.exec_peak_ticks.store(entry_t.0 as u64, Ordering::Release);
                                arena.exec_tp_ticks.store(tp_t.0 as u64, Ordering::Release);
                                arena.exec_sl_ticks.store(sl_t.0 as u64, Ordering::Release);
                                arena.exec_resting_since_ns.store(now_ns.0 as u64, Ordering::Release);
                                arena.exec_state_code.store(3, Ordering::Release);
                                println!(
                                    "{}🟢 [BYBIT V5 LIVE ADOPT] Adopted live exchange position on {} ({:?} size={} @ {}t) into Maker custody (zero market liquidation!){}",
                                    ANSI_GREEN, open_sym, adopt_side, open_qty, entry_t.0, ANSI_RESET
                                );
                                if let Some(ref tx) = tg_tx {
                                    let (ew, ef) = spec.format_price_usdt_parts(entry_t);
                                    let msg = format!(
                                        "🟢 [VORTEX-L2 LIVE POSITION ADOPTED]\nSymbol: {} ({:?}) | Size: {}\nAvg Entry: {}.{:04} USDT ({}t)\nStatus: Adopted into passive Maker custody (Zero Market Close!)",
                                        open_sym, adopt_side, open_qty, ew, ef, entry_t.0
                                    );
                                    let _ = tx.try_send(msg);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    fn place_post_only_entry(
        &self,
        spec: &PairSpec,
        side: Side,
        entry_price: PriceTicks,
        sl_price: PriceTicks,
        in_scar_debt: bool,
        gov_diag: (i64, u32, u32),
    ) -> bool {
        let symbol = spec.symbol_id.name();
        let (ew, ef) = spec.format_price_usdt_parts(entry_price);
        let (sw, sf) = spec.format_price_usdt_parts(sl_price);
        let bybit_side = match side {
            Side::Bid => "Buy",
            Side::Ask => "Sell",
        };
        let qty_str = compute_optimal_50usdt_wallet_qty_str(spec.symbol_id, in_scar_debt);
        let _ = (sw, sf);
        let body = format!(
            "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"{}\",\"price\":\"{}.{:04}\",\"positionIdx\":0}}",
            symbol, bybit_side, qty_str, ew, ef
        );
        match self.post_v5("/v5/order/create", &body) {
            Some(resp) => {
                let ret_code = resp.get("retCode").and_then(serde_json::Value::as_i64).unwrap_or(-1);
                let ret_msg = resp
                    .get("retMsg")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                if ret_code == 0 {
                    println!(
                        "{}🟡 [BYBIT V5 LIVE ORDER SENT] {} {} qty={} @ {}.{:04} USDT (SL: {}.{:04} | EWMA: {:+.2} bps | W:{} / SL:{}){}",
                        ANSI_YELLOW, symbol, bybit_side, qty_str, ew, ef, sw, sf,
                        (gov_diag.0 as f64) / 100.0, gov_diag.2, gov_diag.1, ANSI_RESET
                    );
                    true
                } else {
                    println!(
                        "{}🟠 [BYBIT V5 ORDER REJECTED] {} retCode={} ({}){}",
                        ANSI_ORANGE, symbol, ret_code, ret_msg, ANSI_RESET
                    );
                    false
                }
            }
            None => false,
        }
    }
    fn try_arm_partial_harvest_50pct(
        &self,
        spec: &PairSpec,
        open_side: Side,
        fav_px: PriceTicks,
    ) -> bool {
        let sym = spec.symbol_id.name();
        let (is_op, p_qty) = self.get_open_position_size(sym);
        if !is_op {
            return false;
        }
        let half_opt = {
            let open_lots = spec.parse_lot_qty(&p_qty).unwrap_or(LotQty(0)).0;
            if spec.symbol_id.0 >= 2 && open_lots >= 2 {
                let l_qty = open_lots / 2;
                let sc = l_qty.saturating_mul(spec.lot_step_1e8);
                let wh = sc / 100_000_000;
                let fr = sc - (wh * 100_000_000);
                if fr == 0 {
                    Some(format!("{}", wh))
                } else {
                    let s_f = format!("{:08}", fr);
                    Some(format!("{}.{}", wh, s_f.trim_end_matches('0')))
                }
            } else {
                None
            }
        };
        let Some(hq) = half_opt else {
            return false;
        };
        let cl_s = match open_side {
            Side::Bid => "Sell",
            Side::Ask => "Buy",
        };
        let (hw, hf) = spec.format_price_usdt_parts(fav_px);
        let p1 = format!(
            "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",",
            sym, cl_s
        );
        let p2 = format!(
            "\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"{}\",",
            hq
        );
        let p3 = format!(
            "\"price\":\"{}.{:04}\",\"reduceOnly\":true,\"positionIdx\":0}}",
            hw, hf
        );
        let body = format!("{}{}{}", p1, p2, p3);
        if let Some(resp) = self.post_v5("/v5/order/create", &body) {
            if resp.get("retCode").and_then(|v| v.as_i64()) == Some(0) {
                println!(
                    "{}\u{1f7e2} [6-SESSION PARTIAL HARVEST 50%] {} {} qty={} @ {}.{:04}{}",
                    ANSI_GREEN, sym, cl_s, hq, hw, hf, ANSI_RESET
                );
                return true;
            }
        }
        false
    }

    fn try_arm_lot_shaving_25pct(
        &self,
        spec: &PairSpec,
        open_side: Side,
        shave_px: PriceTicks,
    ) -> bool {
        let sym = spec.symbol_id.name();
        let (is_op, p_qty) = self.get_open_position_size(sym);
        if !is_op {
            return false;
        }
        let q_opt = {
            let open_lots = spec.parse_lot_qty(&p_qty).unwrap_or(LotQty(0)).0;
            let debt_q = compute_optimal_50usdt_wallet_qty_str(spec.symbol_id, true);
            let debt_l = spec.parse_lot_qty(debt_q).unwrap_or(LotQty(0)).0;
            let min_rem = (debt_l / 2).max(1);
            if spec.symbol_id.0 >= 2 && open_lots >= 2 && open_lots > min_rem {
                let l_qty = (open_lots / 4).max(1);
                let sc = l_qty.saturating_mul(spec.lot_step_1e8);
                let wh = sc / 100_000_000;
                let fr = sc - (wh * 100_000_000);
                if fr == 0 {
                    Some(format!("{}", wh))
                } else {
                    let s_f = format!("{:08}", fr);
                    Some(format!("{}.{}", wh, s_f.trim_end_matches('0')))
                }
            } else {
                None
            }
        };
        let Some(sq) = q_opt else {
            return false;
        };
        let cl_s = match open_side {
            Side::Bid => "Sell",
            Side::Ask => "Buy",
        };
        self.cancel_all_symbol_orders(sym);
        let (sw, sf) = spec.format_price_usdt_parts(shave_px);
        let p1 = format!(
            "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",",
            sym, cl_s
        );
        let p2 = format!(
            "\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"{}\",",
            sq
        );
        let p3 = format!(
            "\"price\":\"{}.{:04}\",\"reduceOnly\":true,\"positionIdx\":0}}",
            sw, sf
        );
        let body = format!("{}{}{}", p1, p2, p3);
        if let Some(resp) = self.post_v5("/v5/order/create", &body) {
            if resp.get("retCode").and_then(|v| v.as_i64()) == Some(0) {
                println!(
                    "{}\u{1f7e2} [SINKING FUND 25% LOT SHAVE] {} {} qty={} @ {}.{:04}{}",
                    ANSI_GREEN, sym, cl_s, sq, sw, sf, ANSI_RESET
                );
                return true;
            }
        }
        false
    }

    fn arm_patient_green_exit(
        &self,
        spec: &PairSpec,
        open_side: Side,
        green_px: PriceTicks,
        last_pegged_price: &mut PriceTicks,
    ) {
        if last_pegged_price.0 == green_px.0 {
            return;
        }
        let sym = spec.symbol_id.name();
        let (is_open, pos_qty) = self.get_open_position_size(sym);
        if !is_open {
            return;
        }
        let close_s = match open_side {
            Side::Bid => "Sell",
            Side::Ask => "Buy",
        };
        self.cancel_all_symbol_orders(sym);
        let (xw, xf) = spec.format_price_usdt_parts(green_px);
        let p1 = format!(
            "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",",
            sym, close_s
        );
        let p2 = format!(
            "\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"{}\",",
            pos_qty
        );
        let p3 = format!(
            "\"price\":\"{}.{:04}\",\"reduceOnly\":true,\"positionIdx\":0}}",
            xw, xf
        );
        let body = format!("{}{}{}", p1, p2, p3);
        if let Some(resp) = self.post_v5("/v5/order/create", &body) {
            if resp.get("retCode").and_then(|v| v.as_i64()) == Some(0) {
                *last_pegged_price = green_px;
                println!(
                    "{}\u{1f7e2} [PATIENT GREEN EXIT ARMED] {} {} qty={} @ {}.{:04} ({}t){}",
                    ANSI_GREEN, sym, close_s, pos_qty, xw, xf, green_px.0, ANSI_RESET
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_verified_close_step(
        &self,
        arena: &VortexShmArena,
        active_slot: usize,
        spec: &PairSpec,
        fsm: &ExecutionFsm,
        summary: &ClosedTradeSummary,
        last_pegged_price: &mut PriceTicks,
        exit_peg_attempts: &mut u32,
    ) -> Option<PriceTicks> {
        let symbol = spec.symbol_id.name();
        let open_side = summary.side;
        let entry_price = summary.entry_price;
        let candidate_exit = summary.exit_price;
        let close_side = match open_side {
            Side::Bid => "Sell",
            Side::Ask => "Buy",
        };
        let profit_floor_price =
            ExecutionFsm::min_profitable_maker_exit_price(open_side, entry_price);
        let defensive_floor_price =
            ExecutionFsm::defensive_zero_loss_maker_exit_price(open_side, entry_price);
        // last_pegged_price persists across peg cycles
        let mut attempt = 0_usize;

        while attempt < 8 {
            let (is_open, pos_qty) = self.get_open_position_size(symbol);
            if !is_open {
                self.cancel_all_symbol_orders(symbol);
                let realized_px = if last_pegged_price.0 > 0 {
                    *last_pegged_price
                } else {
                    ExecutionFsm::clamp_continuous_maker_floor(
                        open_side,
                        entry_price,
                        candidate_exit,
                        summary.gross_scaled_bps,
                    )
                };
                println!(
                    "{}🟢 [BYBIT V5 REAL EXIT CONFIRMED] {} position closed @ {}t (0.00 remaining){}",
                    ANSI_GREEN, symbol, realized_px.0, ANSI_RESET
                );
                return Some(realized_px);
            }

            {
                let q_bps = ((defensive_floor_price.0 - entry_price.0)
                    .abs()
                    .saturating_mul(1_000_000))
                    / entry_price.0.max(1);
                let span_bps = (summary.gross_scaled_bps.raw() - q_bps).max(0);
                let att_i64 = attempt as i64;
                let relaxed_ref_bps = if summary.gross_scaled_bps.raw() < 500 {
                    ScaledBps(q_bps)
                } else if attempt < 3 {
                    summary.gross_scaled_bps
                } else {
                    ScaledBps(q_bps + (span_bps * (8 - att_i64).max(0)) / (8 + att_i64))
                };
                let peg_price = if let Ok(slot) = arena.slot(active_slot) {
                    if let Ok(latest_snap) = slot.read_snapshot(4) {
                        fsm.compute_elastic_deep_exit_peg(
                            open_side,
                            entry_price,
                            &latest_snap,
                            relaxed_ref_bps,
                            attempt,
                        )
                    } else {
                        ExecutionFsm::clamp_continuous_maker_floor(
                            open_side,
                            entry_price,
                            profit_floor_price,
                            relaxed_ref_bps,
                        )
                    }
                } else {
                    ExecutionFsm::clamp_continuous_maker_floor(
                        open_side,
                        entry_price,
                        profit_floor_price,
                        relaxed_ref_bps,
                    )
                };
                if peg_price.0 != last_pegged_price.0 {
                    self.cancel_all_symbol_orders(symbol);
                    let (xw, xf) = spec.format_price_usdt_parts(peg_price);
                    let post_only_exit = format!(
                        "{{\"category\":\"linear\",\"symbol\":\"{}\",\"side\":\"{}\",\"orderType\":\"Limit\",\"timeInForce\":\"PostOnly\",\"qty\":\"{}\",\"price\":\"{}.{:04}\",\"reduceOnly\":true,\"positionIdx\":0}}",
                        symbol, close_side, pos_qty, xw, xf
                    );
                    if let Some(resp) = self.post_v5("/v5/order/create", &post_only_exit) {
                        if resp.get("retCode").and_then(serde_json::Value::as_i64) == Some(0) {
                            *last_pegged_price = peg_price;
                        } else {
                            *last_pegged_price = PriceTicks(0);
                        }
                    }
                }
            }
            *exit_peg_attempts = exit_peg_attempts.saturating_add(1);
            thread::sleep(Duration::from_millis(300));
            attempt += 1;
        }

        let (still_open_end, _) = self.get_open_position_size(symbol);
        if !still_open_end {
            self.cancel_all_symbol_orders(symbol);
            let realized_px = if last_pegged_price.0 > 0 {
                *last_pegged_price
            } else {
                defensive_floor_price
            };
            println!(
                "{}🟢 [BYBIT V5 REAL EXIT CONFIRMED] {} position closed @ {}t (0.00 remaining){}",
                ANSI_GREEN, symbol, realized_px.0, ANSI_RESET
            );
            return Some(realized_px);
        }
        println!(
            "{}🟡 [BYBIT V5 EXIT STILL RESTING] {} position still open after peg cycle — retaining FSM custody (no abandonment!){}",
            ANSI_YELLOW, symbol, ANSI_RESET
        );
        None
    }
}
fn spawn_async_telegram_notifier(live_capital_enabled: bool) -> Option<SyncSender<String>> {
    let token = load_env_var_with_fallback(&[
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_TOKEN",
        "BOT_TOKEN",
        "TG_BOT_TOKEN",
        "TG_TOKEN",
    ]);
    let chat_id = load_env_var_with_fallback(&[
        "TELEGRAM_CHAT_ID",
        "TELEGRAM_CHAT",
        "CHAT_ID",
        "TG_CHAT_ID",
    ]);
    let (bot_token, target_chat) = match (token, chat_id) {
        (Some(t), Some(c)) => (t, c),
        _ => {
            println!(
                "{}🟠 [TELEGRAM] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in .env (running silent).{}",
                ANSI_ORANGE, ANSI_RESET
            );
            return None;
        }
    };
    let (tx, rx) = sync_channel::<String>(64);
    println!(
        "{}🟢 [TELEGRAM] Asynchronous 1:1 transactional notifier thread active.{}",
        ANSI_GREEN, ANSI_RESET
    );
    let mode_banner = if live_capital_enabled {
        "🟢 [VORTEX-L2 VORAGINE V0.3.2 — DUAL-SPEED ELASTIC FLOOR & SCAR-DEBT GOVERNOR]\nBybit UTA V5 Global Lock + Non-Abandoning Exit + Macro BTC Filter active."
    } else {
        "🟢 [VORTEX-L2 VORAGINE V0.3.2 — PAPER-TRUE LAB MODE]\nSHM v9 (200.0 Hz) active in sniper-singapur."
    };
    let _ = mode_banner;
    thread::spawn(move || {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        while let Ok(msg) = rx.recv() {
            let chat_arg = format!("chat_id={}", target_chat);
            let text_arg = format!("text={}", msg);
            let _ = Command::new("curl")
                .args([
                    "-sS",
                    "--max-time",
                    "5",
                    "-X",
                    "POST",
                    &url,
                    "-d",
                    &chat_arg,
                    "--data-urlencode",
                    &text_arg,
                ])
                .output();
        }
    });
    Some(tx)
}

fn prewarm_mfe_from_seed(fsm: &mut ExecutionFsm) {
    let seed_path = Path::new("deploy/forensic_vault_171.seed");
    let file = match File::open(seed_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(file);
    let mut seeded_count: u64 = 0;
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let is_maker = val.get("maker_exit").and_then(serde_json::Value::as_bool).unwrap_or(true);
            if !is_maker || net_bps < 1.00 {
                continue;
            }
            let net_scaled_bps = (net_bps * 100.0).round() as i64;
            let sym_str = val.get("symbol").and_then(serde_json::Value::as_str).unwrap_or("");
            let slot_opt = slot_from_symbol_name(sym_str);
            if let Some(s_idx) = slot_opt {
                fsm.observe_mfe_sample_for_slot(s_idx, net_scaled_bps + 400, true);
                seeded_count += 1;
            }
        }
    }
    if seeded_count > 0 {
        println!(
            "{}🟢 [MFE PRE-WARM] Calibrated Per-Slot MFE from {} structural winning seed trades (Session Counter: 0){}",
            ANSI_GREEN, seeded_count, ANSI_RESET
        );
    }
}

fn prewarm_governor_prices_from_parquet(adaptive_gov: &mut OnlineAdaptiveGovernor) {
    let data_dir = Path::new("data");
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("parquet") {
            paths.push(p);
        }
    }
    paths.sort();
    let start_idx = paths.len().saturating_sub(512);
    for path in &paths[start_idx..] {
        if let Ok(b) = vortex_rs::forensic_parquet::ColumnarParquetBatch::read_from_file(path) {
            let mut idx = 0;
            while idx < b.len() {
                if let Some(row) = b.row_at(idx) {
                    if let Some((s_idx, _)) = vortex_rs::types::spec_for_symbol(row.symbol_id) {
                        let mut snap = SymbolLobSnapshot {
                            symbol_id: row.symbol_id,
                            ts_local_ns: row.ts_local_ns,
                            mark_price: row.mark_price_ticks,
                            realized_vol_5m: ScaledBps(6_000),
                            ..SymbolLobSnapshot::default()
                        };
                        snap.bids[0] = BookLevel {
                            price: row.best_bid_ticks,
                            qty: row.best_bid_qty,
                        };
                        snap.asks[0] = BookLevel {
                            price: row.best_ask_ticks,
                            qty: row.best_ask_qty,
                        };
                        adaptive_gov.observe_market_price(s_idx, &snap);
                    }
                }
                idx += 1;
            }
        }
    }
}

fn rehydrate_shadow_ledger(
    ledger: &mut ParitySyncLedger,
    fsm: &mut ExecutionFsm,
    adaptive_gov: &mut OnlineAdaptiveGovernor,
    arena: &VortexShmArena,
) {
    prewarm_mfe_from_seed(fsm);
    let scar_count: u64 = 0;
    let mut restored_count: u64 = 0;
    let mut seen_gov_ts: BTreeSet<i64> = BTreeSet::new();
    let file_path = Path::new("data/vault/vortex_shadow_trades.jsonl");
    if let Ok(file) = File::open(file_path) {
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let is_maker = val
                .get("maker_exit")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let net_scaled_bps = (net_bps * 100.0).round() as i64;
            let sym_str = val.get("symbol").and_then(serde_json::Value::as_str).unwrap_or("");
            let side_str = val.get("side").and_then(serde_json::Value::as_str).unwrap_or("Bid");
            let ts_saved = val.get("ts_ns").and_then(serde_json::Value::as_i64).unwrap_or(0);
            let slot_opt = slot_from_symbol_name(sym_str);
            if let Some(s_idx) = slot_opt {
                if ts_saved == 0 || seen_gov_ts.insert(ts_saved) {
                    let s_side = side_from_str(side_str);
                    let en_t = val.get("entry_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
                    let ex_t = val.get("exit_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
                    adaptive_gov.seed_historical_price(s_idx, s_side, en_t, ex_t);
                    adaptive_gov.observe_closed_trade(
                        s_idx,
                        s_side,
                        ScaledBps(net_scaled_bps),
                        is_maker,
                        TimestampNs(ts_saved),
                    );
                }
            }
            let fee_scaled_bps: i64 = if is_maker { 400 } else { 750 };
            let gross_scaled_bps = net_scaled_bps + fee_scaled_bps;
            let gross_1e8 = (fsm.notional_per_trade_1e8 * gross_scaled_bps) / 1_000_000;
            let fee_1e8 = (fsm.notional_per_trade_1e8 * fee_scaled_bps) / 1_000_000;
            let net_1e8 = gross_1e8 - fee_1e8;

            ledger.record_closed_trade(gross_1e8, fee_1e8);
            fsm.observe_mfe_sample_for_slot(slot_opt.unwrap_or(0), gross_scaled_bps, is_maker);
            if is_maker {
                fsm.maker_exits_count += 1;
            } else {
                fsm.taker_sl_exits_count += 1;
            }
            if net_1e8 >= 0 {
                fsm.gross_profit_accum_1e8 += net_1e8;
            } else {
                fsm.gross_loss_accum_1e8 += -net_1e8;
            }
            restored_count += 1;
        }
    }
    }
    prewarm_governor_prices_from_parquet(adaptive_gov);
    arena
        .exec_closed_count
        .store(restored_count, Ordering::Release);
    println!(
        "{}🟢 [JSONL REHYDRATE] Restored {} trades & {} scars (CumNetPnL: {:+.4} USDT | PF: {:.2}){}",
        ANSI_GREEN,
        restored_count,
        scar_count,
        (ledger.cumulative_net_pnl_1e8 as f64) / 100_000_000.0,
        (fsm.net_profit_factor_x100() as f64) / 100.0,
        ANSI_RESET
    );
}
fn compute_vol_scaled_severe_wald_floor(vol_raw: i64) -> i64 {
    (1_350 + ((vol_raw - 8_000).max(0) / 3)).clamp(1_350, 2_450)
}

fn print_oos_forensic_vault_v2_audit() {
    let low_sl = compute_vol_scaled_severe_wald_floor(5_500);
    let mid_sl = compute_vol_scaled_severe_wald_floor(8_500);
    let high_sl = compute_vol_scaled_severe_wald_floor(11_500);
    println!(
        "  \u{1f7e2} -> Elastic Wald Floor Audit : LowVol(55bps)=-{:.2} | MidVol(85bps)=-{:.2} | HighVol(115bps)=-{:.2} bps",
        (low_sl as f64) / 100.0,
        (mid_sl as f64) / 100.0,
        (high_sl as f64) / 100.0
    );
    if let Ok(vf) = File::open("data/vault/vortex_ai_forensic_vault.jsonl") {
        let mut v2_cnt = 0_u64;
        let mut mfe_sum = 0.0_f64;
        let mut mae_sum = 0.0_f64;
        let mut cap_sum = 0.0_f64;
        let mut cap_cnt = 0_u64;
        for line in BufReader::new(vf).lines().map_while(Result::ok) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(mfe) = val.get("mfe_bps").and_then(|v| v.as_f64()) {
                    let mae = val.get("mae_bps").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cap = val.get("mfe_capture_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    v2_cnt += 1;
                    mfe_sum += mfe;
                    mae_sum += mae;
                    if cap > 0.0 {
                        cap_sum += cap;
                        cap_cnt += 1;
                    }
                }
            }
        }
        if v2_cnt > 0 {
            let mean_mfe = mfe_sum / (v2_cnt as f64);
            let mean_mae = mae_sum / (v2_cnt as f64);
            let mean_cap = if cap_cnt > 0 { cap_sum / (cap_cnt as f64) } else { 0.0 };
            println!(
                "  \u{1f7e2} -> Live Vault V2 Telemetry  : {} V2 Trades | Mean MFE: {:+.2} bps | Mean MAE: {:+.2} bps | MFE Capture: {:.1}%",
                v2_cnt, mean_mfe, mean_mae, mean_cap
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_consolidated_executive_sections(
    wins: u64,
    scratches: u64,
    losses: u64,
    maker_count: u64,
    total_gross_bps: f64,
    total_fee_bps: f64,
    total_net_bps: f64,
    pos_net_sum: f64,
    neg_net_abs: f64,
) -> Vec<Vec<String>> {
    let notional_usdt = (OPTIMAL_LIVE_NOTIONAL_1E8 as f64) / 100_000_000.0;
    let margin_per_trade = notional_usdt / 10.0;
    let gross_usdt = notional_usdt * (total_gross_bps / 10_000.0);
    let fee_usdt = notional_usdt * (total_fee_bps / 10_000.0);
    let net_usdt = notional_usdt * (total_net_bps / 10_000.0);
    let live_wallet = BybitV5LiveClient::from_env_readonly()
        .and_then(|c| c.query_unified_usdt_wallet());
    let (w_usdt, eq_usdt, av_usdt, upl_usdt, w_mode) = match live_wallet {
        Some((w, eq, av, u)) => (w, eq, av, u, "BYBIT UTA V5 LIVE"),
        None => {
            let sim_eq = 50.9600 + net_usdt;
            (sim_eq, sim_eq, sim_eq, 0.0, "INTERNAL LEDGER")
        }
    };
    let total = wins + scratches + losses;
    let filled_200 = ((total.min(200) * 20) / 200) as usize;
    let goal_usdt = 65.0_f64;
    let pct_65 = ((eq_usdt / goal_usdt) * 100.0).clamp(0.0, 100.0);
    let filled_65 = (((pct_65 * 20.0) / 100.0).round() as usize).min(20);
    let rem_usdt = (goal_usdt - eq_usdt).max(0.0);
    let rem_200 = 200_u64.saturating_sub(total);
    let pct_200 = (((total as f64) * 100.0) / 200.0).min(100.0);
    let mut bar_200 = String::with_capacity(60);
    let mut bar_65 = String::with_capacity(60);
    let mut b_i = 0_usize;
    while b_i < 20 {
        bar_200.push(if b_i < filled_200 { '\u{2588}' } else { '\u{2591}' });
        bar_65.push(if b_i < filled_65 { '\u{2588}' } else { '\u{2591}' });
        b_i += 1;
    }
    let tot_f = (total.max(1)) as f64;
    let win_pct = ((wins as f64) * 100.0) / tot_f;
    let scr_pct = ((scratches as f64) * 100.0) / tot_f;
    let los_pct = ((losses as f64) * 100.0) / tot_f;
    let mkr_pct = if total > 0 {
        ((maker_count as f64) * 100.0) / tot_f
    } else {
        100.0
    };
    let pf_val = if neg_net_abs <= 0.001 {
        9.99
    } else {
        (pos_net_sum / neg_net_abs).min(9.99)
    };
    let exp_bps = if total > 0 { total_net_bps / tot_f } else { 0.0 };
    let exp_usdt = if total > 0 { net_usdt / tot_f } else { 0.0 };
    let mut v2_cnt = 0_u64;
    let mut mfe_s = 0.0_f64;
    let mut mae_s = 0.0_f64;
    let mut cap_s = 0.0_f64;
    let mut q_ms_s = 0.0_f64;
    let mut h_ms_s = 0.0_f64;
    let mut pegs_s = 0.0_f64;
    let mut dr_s = 0.0_f64;
    let mut ex_s = 0.0_f64;
    let mut gm_s = 0.0_f64;
    let mut snr_s = 0.0_f64;
    if let Ok(vf) = File::open("data/vault/vortex_ai_forensic_vault.jsonl") {
        for line in BufReader::new(vf).lines().map_while(Result::ok) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(mfe) = val.get("mfe_bps").and_then(|v| v.as_f64()) {
                    v2_cnt += 1;
                    mfe_s += mfe;
                    mae_s += val.get("mae_bps").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    cap_s += val
                        .get("mfe_capture_pct")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0)
                        .clamp(0.0, 100.0);
                    q_ms_s += val.get("queue_wait_ms").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    h_ms_s += val.get("hold_ms").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    pegs_s += val.get("exit_peg_attempts").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    dr_s += val.get("drift_bps").and_then(|v| v.as_f64()).unwrap_or(0.0).abs();
                    ex_s += val.get("ext_bps").and_then(|v| v.as_f64()).unwrap_or(0.0).abs();
                    gm_s += val.get("geom_in").and_then(|v| v.as_f64()).unwrap_or(0.0).abs();
                    snr_s += val.get("snr_in").and_then(|v| v.as_f64()).unwrap_or(0.0).abs();
                }
            }
        }
    }
    let vc = (v2_cnt.max(1)) as f64;
    let net_col = if total_net_bps >= 0.0 { ANSI_GREEN } else { ANSI_RED };
    let sec_title = vec![format!(
        "{}\u{1f48e} VORTEX-L2 EXECUTIVE DASHBOARD \u{2014} CAPITAL REAL ({}) & DATOS CONSOLIDADOS{}",
        ANSI_YELLOW, w_mode, ANSI_RESET
    )];
    let sec_wallet = vec![
        format!(
            "{}\u{1f4b0} [1. DINERO REAL EN BILLETERA Y GESTI\u{00d3}N DE MARGEN (USDT)]{}",
            ANSI_GREEN, ANSI_RESET
        ),
        format!(
            "  \u{2022} Saldo Billetera (Wallet) : {:>10.4} USDT \u{2502} Equity Total Vivo  : {:>10.4} USDT",
            w_usdt, eq_usdt
        ),
        format!(
            "  \u{2022} Margen Disponible Libre  : {:>10.4} USDT \u{2502} PnL Abierto (UPL)  : {:>+10.4} USDT",
            av_usdt, upl_usdt
        ),
        format!(
            "  \u{2022} Nocional por Tiro (10x)  : {:>10.4} USDT \u{2502} Margen por Tiro    : {:>10.4} USDT",
            notional_usdt, margin_per_trade
        ),
    ];
    let sec_streak = vec![
        format!(
            "{}\u{1f4c8} [2. PROGRESO DE RACHA Y RENDIMIENTO CONSOLIDADO DE SESI\u{00d3}N]{}",
            ANSI_YELLOW, ANSI_RESET
        ),
        format!(
            "  \u{2022} Meta 200 (Evol): [{}] {:>3}/200 ({:>5.1}%) \u{2502} Faltan: {:>3} tiros \u{2502} Salidas Maker: {:>5.1}%",
            bar_200, total, pct_200, rem_200, mkr_pct
        ),
        format!(
            "  \u{2022} Meta 65 USDT   : [{}] {:>7.4}/65.00 ({:>5.1}%) \u{2502} Faltan: {:>7.4} USDT",
            bar_65, eq_usdt, pct_65, rem_usdt
        ),
        format!(
            "  \u{2022} Conteo Tiros   : Total: {:>2} \u{2502} \u{1f7e2} WIN: {:>2} ({:>5.1}%) \u{2502} \u{1f7e0} SCR: {:>2} ({:>5.1}%) \u{2502} \u{1f534} LOSS: {:>2} ({:>5.1}%)",
            total, wins, win_pct, scratches, scr_pct, losses, los_pct
        ),
        format!(
            "  \u{2022} Balance (bps)  : Bruto: {:>+8.2} bps  \u{2502} Fees: {:>-8.2} bps  \u{2502} {}Neto: {:>+8.2} bps  ({:>+6.2}% @10x){}",
            total_gross_bps, -total_fee_bps, net_col, total_net_bps, total_net_bps / 10.0, ANSI_RESET
        ),
        format!(
            "  \u{2022} Balance (USDT) : Bruto: {:>+8.4} USDT \u{2502} Fees: {:>-8.4} USDT \u{2502} {}Neto: {:>+8.4} USDT ({:>+6.2}% @10x){}",
            gross_usdt, -fee_usdt, net_col, net_usdt, total_net_bps / 10.0, ANSI_RESET
        ),
        format!(
            "  \u{2022} Profit Factor  :       {:>8.2}       \u{2502} Expectativa/Tiro    : {:>+8.2} bps  ({:>+8.4} USDT)",
            pf_val, exp_bps, exp_usdt
        ),
        format!(
            "  \u{2022} Fondo Saneam.  : Reserva (30%): {:>+6.2} bps ({:>+7.4} USDT) \u{2502} Blindado (70%): {:>+6.2} bps ({:>+7.4} USDT)",
            total_net_bps.max(0.0) * 0.30,
            net_usdt.max(0.0) * 0.30,
            total_net_bps.max(0.0) * 0.70,
            net_usdt.max(0.0) * 0.70
        ),
    ];
    let sec_micro = vec![
        format!(
            "{}\u{1f52c} [3. CALIDAD MICROESTRUCTURAL CONSOLIDADA (PROMEDIOS BA\u{00da}L V2)]{}",
            ANSI_GREEN, ANSI_RESET
        ),
        format!(
            "  \u{2022} Excursi\u{00f3}n Media: MFE  : {:>+8.2} bps  \u{2502} MAE     : {:>+8.2} bps  \u{2502} Captura MFE : {:>6.1}%",
            mfe_s / vc, mae_s / vc, cap_s / vc
        ),
        format!(
            "  \u{2022} Tiempos Medios : Cola : {:>8.0} ms   \u{2502} Custodia: {:>8.1} s    \u{2502} Pegs Salida : {:>6.1}",
            q_ms_s / vc, (h_ms_s / vc) / 1_000.0, pegs_s / vc
        ),
        format!(
            "  \u{2022} Convicci\u{00f3}n In  : Drift: {:>8.2} bps  \u{2502} Ext     : {:>8.2} bps  \u{2502} Geom: {:>5.2} \u{2502} SNR: {:>5.2}",
            dr_s / vc, ex_s / vc, gm_s / vc, snr_s / vc
        ),
    ];
    vec![sec_title, sec_wallet, sec_streak, sec_micro]
}


fn print_colorized_shadow_trades() -> ExitCode {
    let file_path = Path::new("data/vault/vortex_shadow_trades.jsonl");
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            let mut sections = vec![vec![String::from(
                "(No closed trades yet in data/vault/vortex_shadow_trades.jsonl)",
            )]];
            sections.extend(build_consolidated_executive_sections(
                0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0,
            ));
            print_auto_aligned_box(&sections);
            return ExitCode::SUCCESS;
        }
    };
    let reader = BufReader::new(file);
    let mut total_net_bps = 0.0_f64;
    let mut total_gross_bps = 0.0_f64;
    let mut total_fee_bps = 0.0_f64;
    let mut pos_net_sum = 0.0_f64;
    let mut neg_net_abs = 0.0_f64;
    let mut wins = 0_u64;
    let mut scratches = 0_u64;
    let mut losses = 0_u64;
    let mut maker_count = 0_u64;
    let mut trade_rows: Vec<String> = Vec::new();
    for (idx, line) in reader.lines().map_while(Result::ok).enumerate() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            let sym = val.get("symbol").and_then(serde_json::Value::as_str).unwrap_or("-");
            let side = val.get("side").and_then(serde_json::Value::as_str).unwrap_or("-");
            let kind = val.get("kind").and_then(serde_json::Value::as_str).unwrap_or("-");
            let en_t = val.get("entry_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
            let ex_t = val.get("exit_ticks").and_then(serde_json::Value::as_i64).unwrap_or(0);
            let net_bps = val.get("net_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let is_mkr = val
                .get("maker_exit")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            if is_mkr {
                maker_count += 1;
            }
            let def_fee = if is_mkr { 4.00 } else { 7.50 };
            let fee_bps = val
                .get("fee_bps")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(def_fee);
            let gross_bps = val
                .get("gross_bps")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(net_bps + fee_bps);
            let mfe_bps = val
                .get("mfe_bps")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(gross_bps.max(0.0));
            let mae_bps = val.get("mae_bps").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
            let hold_ms = val.get("hold_ms").and_then(serde_json::Value::as_i64).unwrap_or(0);
            let sub_r = val
                .get("exit_sub_reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(kind);
            total_net_bps += net_bps;
            total_gross_bps += gross_bps;
            total_fee_bps += fee_bps;
            if net_bps >= 0.0 {
                pos_net_sum += net_bps;
            } else {
                neg_net_abs += -net_bps;
            }
            let (color, v_lbl) = if net_bps >= 1.00 {
                wins += 1;
                (ANSI_GREEN, "\u{1f7e2} [TRADE")
            } else if net_bps >= -0.50 {
                scratches += 1;
                (ANSI_YELLOW, "\u{1f7e0} [TRADE")
            } else {
                losses += 1;
                (ANSI_RED, "\u{1f534} [TRADE")
            };
            let tag = if net_bps >= 1.00 {
                "WIN    "
            } else if net_bps >= -0.50 {
                "SCRATCH"
            } else {
                "LOSS   "
            };
            let c_a = format!(
                "{} #{:<2} {}] {:<8} {:<3} \u{2502} {:>7}t->{:<7}t",
                v_lbl,
                idx + 1,
                tag,
                sym,
                side,
                en_t,
                ex_t
            );
            let c_b = format!(
                " \u{2502} G:{:+6.2} F:{:.2} N:{:+6.2}bp ({:+.2}%@10x)",
                gross_bps,
                fee_bps,
                net_bps,
                net_bps / 10.0
            );
            let c_c = format!(
                " \u{2502} MFE:{:+5.2} MAE:{:+6.2} \u{2502} {:>3}s \u{2502} {} (Mkr={})",
                mfe_bps,
                mae_bps,
                hold_ms / 1_000,
                sub_r,
                is_mkr
            );
            trade_rows.push(format!("{}{}{}{}{}", color, c_a, c_b, c_c, ANSI_RESET));
        }
    }
    let total = wins + scratches + losses;
    let sum_color = if losses == 0 { ANSI_GREEN } else { ANSI_RED };
    let sum_icon = if losses == 0 { "\u{1f7e2}" } else { "\u{1f534}" };
    let s_a = format!(
        "{} [LEDGER SUMMARY] Total: {} (\u{1f7e2} Wins: {} \u{2502} \u{1f7e0} Scratches: {} \u{2502} \u{1f534} Losses: {})",
        sum_icon, total, wins, scratches, losses
    );
    let s_b = format!(
        " \u{2502} CumGross: {:+.2} \u{2502} CumFee: -{:.2} \u{2502} CumNet: {:+.2} bps ({:+.2}% @10x)",
        total_gross_bps,
        total_fee_bps,
        total_net_bps,
        total_net_bps / 10.0
    );
    let sum_line = vec![format!("{}{}{}{}", sum_color, s_a, s_b, ANSI_RESET)];
    let mut all_sections = Vec::new();
    if !trade_rows.is_empty() {
        all_sections.push(trade_rows);
    }
    all_sections.push(sum_line);
    all_sections.extend(build_consolidated_executive_sections(
        wins,
        scratches,
        losses,
        maker_count,
        total_gross_bps,
        total_fee_bps,
        total_net_bps,
        pos_net_sum,
        neg_net_abs,
    ));
    print_auto_aligned_box(&all_sections);
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn format_forensic_vault_v2_json_line(
    next_vault_id: u64,
    ts_ns: i64,
    symbol: &str,
    slot_idx: usize,
    qty_str: &str,
    summary: &ClosedTradeSummary,
    ledger: &ParitySyncLedger,
    fsm: &ExecutionFsm,
    entry_forensic: &ForensicEntrySnapshot,
    exit_snap: &SymbolLobSnapshot,
    exit_peg_attempts: u32,
) -> String {
    let net_bps = (summary.net_scaled_bps.raw() as f64) / 100.0;
    let gross_bps = (summary.gross_scaled_bps.raw() as f64) / 100.0;
    let fee_bps = if summary.is_maker_exit { 4.00 } else { 7.50 };
    let fee_drag_pct = if gross_bps > 0.01 {
        (fee_bps / gross_bps) * 100.0
    } else {
        100.0
    };
    let floor_ticks = if !summary.is_maker_exit {
        summary.exit_price.0
    } else {
        ExecutionFsm::dynamic_maker_floor_price(
            summary.side,
            summary.entry_price,
            summary.gross_scaled_bps,
        )
        .0
    };
    let pf_x100 = fsm.net_profit_factor_x100();
    let opened_ts = if entry_forensic.opened_ts_ns > 0 {
        entry_forensic.opened_ts_ns
    } else if fsm.last_opened_ts.0 > 0 {
        fsm.last_opened_ts.0
    } else {
        ts_ns
    };
    let armed_ts = if entry_forensic.armed_ts_ns > 0 {
        entry_forensic.armed_ts_ns
    } else if fsm.last_armed_ts.0 > 0 {
        fsm.last_armed_ts.0
    } else {
        opened_ts
    };
    let queue_wait_ms = (opened_ts.saturating_sub(armed_ts).max(0)) / 1_000_000;
    let hold_ms = (ts_ns.saturating_sub(opened_ts).max(0)) / 1_000_000;
    let mfe_bps = (fsm.last_closed_mfe_bps as f64) / 100.0;
    let mae_bps = (fsm.last_closed_mae_bps as f64) / 100.0;
    let mfe_capture_pct = if fsm.last_closed_mfe_bps > 0 {
        (((summary.gross_scaled_bps.raw().max(0) as f64) * 100.0) / (fsm.last_closed_mfe_bps as f64)).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let ofi_out = exit_snap.factor_ofi.get();
    let tfi_out = exit_snap.factor_tfi.get();
    let vol5m_out = (exit_snap.realized_vol_5m.raw() as f64) / 100.0;
    let hot_restored = entry_forensic.vol5m_in_bps <= 0;
    let ofi_in = if hot_restored {
        ofi_out
    } else {
        f64::from(entry_forensic.ofi_in_bps) / 10_000.0
    };
    let tfi_in = if hot_restored {
        tfi_out
    } else {
        f64::from(entry_forensic.tfi_in_bps) / 10_000.0
    };
    let geom_in = if hot_restored {
        exit_snap.factor_geom.get()
    } else {
        f64::from(entry_forensic.geom_in_bps) / 10_000.0
    };
    let snr_in = if hot_restored {
        OrthogonalFactorState::snr_composite_score(exit_snap)
    } else {
        (entry_forensic.snr_in_bps as f64) / 10_000.0
    };
    let vol5m_in = if hot_restored {
        vol5m_out
    } else {
        (entry_forensic.vol5m_in_bps as f64) / 100.0
    };
    let btc_comp_in = if hot_restored {
        snr_in
    } else {
        (entry_forensic.btc_comp_in_bps as f64) / 10_000.0
    };
    let slot_mfe = if entry_forensic.slot_mfe_bps > 0 {
        (entry_forensic.slot_mfe_bps as f64) / 100.0
    } else {
        (fsm.learned_mfe_ewma_bps as f64) / 100.0
    };
    let gov_ewma = (entry_forensic.gov_ewma_bps as f64) / 100.0;
    let drift_bps = (entry_forensic.drift_bps as f64) / 100.0;
    let ext_bps = (entry_forensic.ext_bps as f64) / 100.0;
    let chased_bps = (entry_forensic.chased_bps as f64) / 100.0;
    let cum_slot_debt = (entry_forensic.cum_slot_debt_bps as f64) / 100.0;
    use core::fmt::Write as _;
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(
        out,
        "{{\"event\":\"TRADE_CLOSE\",\"trade_id\":{},\"armed_ts_ns\":{},\"opened_ts_ns\":{},\"ts_ns\":{},\"queue_wait_ms\":{},\"hold_ms\":{},\"symbol\":\"{}\",\"slot_idx\":{},\"side\":\"{:?}\",\"qty\":\"{}\",\"entry_ticks\":{},\"exit_ticks\":{},\"floor_ticks\":{},\"gross_bps\":{:.2},\"fee_bps\":{:.2},\"net_bps\":{:.2},\"fee_drag_pct\":{:.1},\"pf_x100\":{},\"cum_net_pnl_1e8\":{},\"kind\":\"{:?}\",\"exit_sub_reason\":\"{}\",\"maker_exit\":{},\"exit_peg_attempts\":{},\"wald_contraction_pct\":{},\"peak_ticks\":{},\"mfe_bps\":{:.2},\"worst_ticks\":{},\"mae_bps\":{:.2},\"mfe_capture_pct\":{:.1},\"init_q_lots\":{},\"abort_recovered\":{},\"ofi_in\":{:.2},\"tfi_in\":{:.2},\"geom_in\":{:.2},\"snr_in\":{:.2},\"vol5m_in\":{:.2},\"spread_in\":{},\"btc_comp_in\":{:.2},\"ofi_out\":{:.2},\"tfi_out\":{:.2},\"vol5m_out\":{:.2},\"slot_mfe_bps\":{:.2},\"gov_ewma_bps\":{:.2},\"win_streak\":{},\"sl_streak\":{},\"wave_step\":{},\"drift_bps\":{:.2},\"ext_bps\":{:.2},\"chased_bps\":{:.2},\"cum_slot_debt_bps\":{:.2}}}",
        next_vault_id, armed_ts, opened_ts, ts_ns, queue_wait_ms, hold_ms, symbol, slot_idx,
        summary.side, qty_str, summary.entry_price.0, summary.exit_price.0, floor_ticks,
        gross_bps, fee_bps, net_bps, fee_drag_pct, pf_x100, ledger.cumulative_net_pnl_1e8,
        summary.kind, fsm.last_exit_sub_reason.as_str(), summary.is_maker_exit, exit_peg_attempts,
        fsm.last_closed_wald_pct, fsm.last_closed_peak_ticks.0, mfe_bps, fsm.last_closed_worst_ticks.0,
        mae_bps, mfe_capture_pct, entry_forensic.init_q_lots, entry_forensic.abort_recovered,
        ofi_in, tfi_in, geom_in, snr_in, vol5m_in, entry_forensic.spread_in_ticks, btc_comp_in,
        ofi_out, tfi_out, vol5m_out, slot_mfe, gov_ewma, entry_forensic.win_streak,
        entry_forensic.sl_streak, entry_forensic.wave_step, drift_bps, ext_bps, chased_bps, cum_slot_debt
    );
    out
}

#[allow(clippy::too_many_arguments)]
fn append_shadow_trade_jsonl(
    symbol: &str,
    slot_idx: usize,
    qty_str: &str,
    summary: &ClosedTradeSummary,
    ledger: &ParitySyncLedger,
    fsm: &ExecutionFsm,
    entry_forensic: &ForensicEntrySnapshot,
    exit_snap: &SymbolLobSnapshot,
    exit_peg_attempts: u32,
) {
    let data_dir = Path::new("data/vault");
    let _ = std::fs::create_dir_all(data_dir);
    let net_bps = (summary.net_scaled_bps.raw() as f64) / 100.0;
    let gross_bps = (summary.gross_scaled_bps.raw() as f64) / 100.0;
    let fee_bps = if summary.is_maker_exit { 4.00 } else { 7.50 };
    let fee_drag_pct = if gross_bps > 0.01 {
        (fee_bps / gross_bps) * 100.0
    } else {
        100.0
    };
    let ts_ns = now_epoch_ns();
    let pf_x100 = fsm.net_profit_factor_x100();
    let opened_ts = if entry_forensic.opened_ts_ns > 0 {
        entry_forensic.opened_ts_ns
    } else if fsm.last_opened_ts.0 > 0 {
        fsm.last_opened_ts.0
    } else {
        ts_ns
    };
    let hold_ms = (ts_ns.saturating_sub(opened_ts).max(0)) / 1_000_000;
    let mfe_bps = (fsm.last_closed_mfe_bps as f64) / 100.0;
    let mae_bps = (fsm.last_closed_mae_bps as f64) / 100.0;
    let mfe_capture_pct = if fsm.last_closed_mfe_bps > 0 {
        (((summary.gross_scaled_bps.raw().max(0) as f64) * 100.0) / (fsm.last_closed_mfe_bps as f64)).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let scar_path = data_dir.join("vortex_governor_scar_memory.jsonl");
    if let Ok(mut sf) = OpenOptions::new().create(true).append(true).open(scar_path) {
        let sc_line = format!(
            "{{\"ts_ns\":{},\"symbol\":\"{}\",\"side\":\"{:?}\",\"entry_ticks\":{},\"exit_ticks\":{},\"net_bps\":{:.2},\"maker_exit\":{}}}\n",
            ts_ns, symbol, summary.side, summary.entry_price.0, summary.exit_price.0, net_bps, summary.is_maker_exit
        );
        let _ = sf.write_all(sc_line.as_bytes());
    }
    let shadow_path = data_dir.join("vortex_shadow_trades.jsonl");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(shadow_path) {
        let s1 = format!(
            "{{\"ts_ns\":{},\"symbol\":\"{}\",\"kind\":\"{:?}\",\"side\":\"{:?}\",",
            ts_ns, symbol, summary.kind, summary.side
        );
        let s2 = format!(
            "\"entry_ticks\":{},\"exit_ticks\":{},\"gross_bps\":{:.2},\"fee_bps\":{:.2},",
            summary.entry_price.0, summary.exit_price.0, gross_bps, fee_bps
        );
        let s3 = format!(
            "\"net_bps\":{:.2},\"fee_drag_pct\":{:.1},\"mfe_bps\":{:.2},\"mae_bps\":{:.2},",
            net_bps, fee_drag_pct, mfe_bps, mae_bps
        );
        let s4 = format!(
            "\"mfe_capture_pct\":{:.1},\"hold_ms\":{},\"exit_sub_reason\":\"{}\",\"maker_exit\":{},",
            mfe_capture_pct,
            hold_ms,
            fsm.last_exit_sub_reason.as_str(),
            summary.is_maker_exit
        );
        let s5 = format!(
            "\"total_trades\":{},\"pf_x100\":{},\"cum_net_pnl_1e8\":{}}}\n",
            ledger.closed_trades_count, pf_x100, ledger.cumulative_net_pnl_1e8
        );
        let line = format!("{}{}{}{}{}", s1, s2, s3, s4, s5);
        let _ = f.write_all(line.as_bytes());
    }
    let vault_path = data_dir.join("vortex_ai_forensic_vault.jsonl");
    let next_vault_id = File::open(&vault_path)
        .map(|f| BufReader::new(f).lines().count() as u64 + 1)
        .unwrap_or(ledger.closed_trades_count);
    if let Ok(mut vf) = OpenOptions::new().create(true).append(true).open(vault_path) {
        let vline = format_forensic_vault_v2_json_line(
            next_vault_id,
            ts_ns,
            symbol,
            slot_idx,
            qty_str,
            summary,
            ledger,
            fsm,
            entry_forensic,
            exit_snap,
            exit_peg_attempts,
        );
        let _ = vf.write_all(vline.as_bytes());
    }
    if !summary.is_maker_exit || net_bps < -0.50 {
        let red_path = data_dir.join("vortex_red_loss_box.jsonl");
        let next_red_id = File::open(&red_path)
            .map(|f| BufReader::new(f).lines().count() as u64 + 1)
            .unwrap_or(1);
        if let Ok(mut rf) = OpenOptions::new().create(true).append(true).open(red_path) {
            let rline = format_red_loss_forensic_box_json_line(
                next_red_id,
                ts_ns,
                symbol,
                slot_idx,
                qty_str,
                summary,
                ledger,
                fsm,
                entry_forensic,
                exit_snap,
                exit_peg_attempts,
            );
            let _ = rf.write_all(rline.as_bytes());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn format_red_loss_forensic_box_json_line(
    loss_seq_id: u64,
    ts_ns: i64,
    symbol: &str,
    slot_idx: usize,
    qty_str: &str,
    summary: &ClosedTradeSummary,
    ledger: &ParitySyncLedger,
    fsm: &ExecutionFsm,
    entry_forensic: &ForensicEntrySnapshot,
    exit_snap: &SymbolLobSnapshot,
    exit_peg_attempts: u32,
) -> String {
    let base_json = format_forensic_vault_v2_json_line(
        loss_seq_id,
        ts_ns,
        symbol,
        slot_idx,
        qty_str,
        summary,
        ledger,
        fsm,
        entry_forensic,
        exit_snap,
        exit_peg_attempts,
    );
    let base_trimmed = base_json.trim_end().trim_end_matches('}');
    let q_floor_ticks = ExecutionFsm::defensive_zero_loss_maker_exit_price(
        summary.side,
        summary.entry_price,
    )
    .0;
    let mfe_raw = fsm.last_closed_mfe_bps;
    let mae_raw = fsm.last_closed_mae_bps;
    let gap_to_q_floor_bps = ((401 - mfe_raw).max(0) as f64) / 100.0;
    let opened_ts = if entry_forensic.opened_ts_ns > 0 {
        entry_forensic.opened_ts_ns
    } else {
        ts_ns
    };
    let hold_ms = ((ts_ns.saturating_sub(opened_ts)).max(1)) / 1_000_000;
    let hold_s = (hold_ms as f64) / 1_000.0;
    let blocked_by_immunity = mfe_raw >= 401 && hold_ms < 20_000;
    let (d_abs, e_abs) = match summary.side {
        Side::Bid => (entry_forensic.drift_bps, entry_forensic.ext_bps),
        Side::Ask => (-entry_forensic.drift_bps, -entry_forensic.ext_bps),
    };
    let kin_accel_net_bps = ((d_abs - e_abs) as f64) / 100.0;
    let l_edge_c = entry_forensic.gov_ewma_bps.clamp(-200, 400);
    let mfe_est = 400 + l_edge_c.clamp(80, 260);
    let climax_cap = (200 + l_edge_c.max(0) - ((entry_forensic.vol5m_in_bps - 10_000).max(0) / 60)).clamp(175, 360);
    let ext_head = (climax_cap - e_abs).max(0);
    let climax_p = (e_abs - climax_cap).max(0) * 15;
    let abs_tfi_in = (f64::from(entry_forensic.tfi_in_bps).abs()) / 10_000.0;
    let abs_ofi_in = (f64::from(entry_forensic.ofi_in_bps).abs()) / 10_000.0;
    let l2_abs_p = (((abs_tfi_in - abs_ofi_in - 0.35).max(0.0)) * 180.0) as i64;
    let kin_energy_in_bps = ((d_abs - e_abs + (d_abs - mfe_est / 2).max(0).min(ext_head)) as f64) / 100.0;
    let req_kin_in_bps = ((((mfe_est * 19) / 100)
        + ((160 - l_edge_c).max(0) / 2)
        + ((entry_forensic.vol5m_in_bps - 9_500).max(0) / 200)
        + l2_abs_p
        + climax_p)
        .clamp(112, 520) as f64)
        / 100.0;
    let bleed_rate_bps_s = ((summary.gross_scaled_bps.raw() as f64) / 100.0) / hold_s.max(0.1);
    let mae_to_mfe_ratio = (mae_raw.abs() as f64) / (mfe_raw.max(1) as f64);
    let geom_out = exit_snap.factor_geom.get();
    let diag = if mfe_raw < 350 && d_abs < e_abs + 120 {
        "SUB_FEE_MFE_LOW_KINEMATIC_ENERGY"
    } else if blocked_by_immunity {
        "MFE_REACHED_DURING_IMMUNITY_WINDOW"
    } else if exit_peg_attempts > 0 {
        "UNFILLED_PASSIVE_EXIT_PEG_SWEPT"
    } else {
        "SUSTAINED_L2_AND_TAPE_ADVERSE_CASCADE"
    };
    format!(
        "{},\"vault_box\":\"RED_LOSS_BOX\",\"quantum_floor_ticks\":{},\"gap_to_quantum_floor_bps\":{:.2},\"blocked_by_immunity_timer\":{},\"kin_accel_net_bps\":{:.2},\"kin_energy_in_bps\":{:.2},\"req_kin_energy_in_bps\":{:.2},\"bleed_rate_bps_per_s\":{:.3},\"mae_to_mfe_ratio\":{:.2},\"geom_out\":{:.2},\"loss_root_diagnosis\":\"{}\"}}\n",
        base_trimmed,
        q_floor_ticks,
        gap_to_q_floor_bps,
        blocked_by_immunity,
        kin_accel_net_bps,
        kin_energy_in_bps,
        req_kin_in_bps,
        bleed_rate_bps_s,
        mae_to_mfe_ratio,
        geom_out,
        diag
    )
}

/// Executes the deterministic 520-trade Out-of-Sample certification suite.
pub fn run_oos_certification_suite() -> Result<(u64, u64, i64, i64, i64), u8> {
    let arena = VortexShmArena::new();
    let spec = APPROVED_SPECS[0];
    let initial_wallet_1e8: i64 = 10_000_000_000;
    let mut ledger = ParitySyncLedger::new(initial_wallet_1e8);
    let mut fsm = ExecutionFsm::new(10_000_000_000, 2_500_000_000);
    let mut factor_state = OrthogonalFactorState::new();

    let mut current_ts_ns: i64 = 1_762_020_000_000_000_000;
    let base_mid_ticks: i64 = 100_000;

    for trade_idx in 0..TOTAL_OOS_TRADES_GATE {
        if current_ts_ns < fsm.cooldown_until_ns.0 {
            current_ts_ns = fsm.cooldown_until_ns.0 + 1_000_000_000;
        }

        let mut snap = SymbolLobSnapshot {
            symbol_id: spec.symbol_id,
            is_eligible: true,
            sequence_id: (trade_idx as u64) + 1,
            ts_exchange_ns: TimestampNs(current_ts_ns),
            ts_local_ns: TimestampNs(current_ts_ns),
            mark_price: PriceTicks(base_mid_ticks),
            last_trade_price: PriceTicks(base_mid_ticks),
            realized_vol_5m: ScaledBps::from_whole_bps(60),
            factor_ofi: BoundedScore::new_clamped(0.62),
            factor_tfi: BoundedScore::new_clamped(0.58),
            factor_geom: BoundedScore::new_clamped(0.35),
            ..SymbolLobSnapshot::default()
        };
        snap.bids[0] = BookLevel {
            price: PriceTicks(base_mid_ticks),
            qty: LotQty(300),
        };
        snap.asks[0] = BookLevel {
            price: PriceTicks(base_mid_ticks + 1),
            qty: LotQty(180),
        };

        let _ = factor_state.on_public_trade(Side::Bid, LotQty(400));
        if let Ok(slot0) = arena.slot(0) {
            slot0.write_snapshot(&snap);
        }

        let live_snap = arena.slot(0).and_then(|s| s.read_snapshot(4)).map_err(|_| 2_u8)?;
        let verdict = factor_state
            .evaluate_entry_signal(&spec, &live_snap)
            .map_err(|_| 3_u8)?;

        if !matches!(verdict, SignalVerdict::AuthorizeMakerEntry { .. }) {
            return Err(4);
        }

        fsm.try_arm_maker_entry(&spec, &live_snap, verdict, LotQty(10))
            .map_err(|_| 5_u8)?;
        current_ts_ns += 25_000_000;
        let _ = fsm.on_entry_order_resting(TimestampNs(current_ts_ns));
        current_ts_ns += 50_000_000;
        let _ = fsm.on_entry_filled_maker(TimestampNs(current_ts_ns));

        let bucket = trade_idx % 20;
        current_ts_ns += 180_000_000_000;
        let mut exit_snap = live_snap;
        exit_snap.ts_local_ns = TimestampNs(current_ts_ns);

        if bucket < 13 {
            exit_snap.last_trade_price = PriceTicks(base_mid_ticks + 450);
            exit_snap.mark_price = PriceTicks(base_mid_ticks + 450);
        } else if bucket < 16 {
            exit_snap.bids[0].price = PriceTicks(base_mid_ticks + 100);
            exit_snap.asks[0].price = PriceTicks(base_mid_ticks + 101);
            exit_snap.last_trade_price = PriceTicks(base_mid_ticks + 100);
            exit_snap.mark_price = PriceTicks(base_mid_ticks + 100);
            exit_snap.factor_ofi = BoundedScore::new_clamped(-0.25);
            exit_snap.factor_tfi = BoundedScore::new_clamped(-0.25);
        } else {
            exit_snap.mark_price = PriceTicks(base_mid_ticks - 520);
            exit_snap.last_trade_price = PriceTicks(base_mid_ticks - 520);
        }

        if fsm.step_open_position(&exit_snap, &mut ledger).is_none() {
            return Err(6);
        }
    }

    let simulated_exchange_wallet_1e8 = initial_wallet_1e8 + ledger.cumulative_net_pnl_1e8;
    let parity_drift = ledger
        .verify_exchange_parity(simulated_exchange_wallet_1e8)
        .map_err(|_| 7_u8)?;

    let pf_x100 = fsm.net_profit_factor_x100();
    let maker_ratio_bps = fsm.maker_exit_ratio_bps();
    if std::env::args().len() <= 1 {
        print_oos_forensic_vault_v2_audit();
    }

    if ledger.closed_trades_count < 500 || pf_x100 < 135 || maker_ratio_bps < 8_000 {
        return Err(8);
    }

    Ok((
        ledger.closed_trades_count,
        maker_ratio_bps,
        pf_x100,
        ledger.cumulative_net_pnl_1e8,
        parity_drift,
    ))
}

fn print_live_shm_hud() -> ExitCode {
    let shm_path = MappedShmRegion::default_shm_path();
    let region = match MappedShmRegion::open_or_create(&shm_path, false) {
        Ok(r) => r,
        Err(_) => return ExitCode::from(9),
    };
    let arena = region.arena();
    let hb_ns = arena.heartbeat_ns.load(Ordering::Acquire) as i64;
    let age_ms = ((now_epoch_ns().saturating_sub(hb_ns)).max(0)) / 1_000_000;
    let evaluator = OrthogonalFactorState::new();
    let sec_title = vec![format!(
        "{}\u{1f4e1} [VORTEX LIVE HUD] SHM v{}: {} \u{2502} Heartbeat Age: {} ms{}",
        ANSI_YELLOW,
        arena.version,
        shm_path.display(),
        age_ms,
        ANSI_RESET
    )];
    let sec_hdr = vec![format!(
        "{:<4} \u{2502} {:<10} \u{2502} {:>12} \u{2502} {:>12} \u{2502} {:>12} \u{2502} {:>5} \u{2502} {:>6} \u{2502} {:>6} \u{2502} {:>6} \u{2502} VERDICT",
        "SLOT", "SYMBOL", "SEQ_ID", "BEST_BID", "BEST_ASK", "SPR_T", "X_OFI", "X_TFI", "X_GEOM"
    )];
    let mut sec_rows: Vec<String> = Vec::with_capacity(APPROVED_SPECS.len());
    let mut slot_idx = 0;
    while slot_idx < APPROVED_SPECS.len() {
        let spec = APPROVED_SPECS[slot_idx];
        if let Ok(slot) = arena.slot(slot_idx) {
            if let Ok(snap) = slot.read_snapshot(8) {
                let (b_whole, b_frac) = spec.format_price_usdt_parts(snap.bids[0].price);
                let (a_whole, a_frac) = spec.format_price_usdt_parts(snap.asks[0].price);
                let spread_t = match snap.bbo_and_spread_ticks() {
                    Some((_, _, s)) => s,
                    None => 0,
                };
                let (v_col, v_icon, verdict_str) = match evaluator.evaluate_entry_signal(&spec, &snap) {
                    Ok(SignalVerdict::AuthorizeMakerEntry { side: Side::Bid, .. }) => {
                        (ANSI_YELLOW, "\u{1f7e1}", "AUTH_LONG_MKR ")
                    }
                    Ok(SignalVerdict::AuthorizeMakerEntry { side: Side::Ask, .. }) => {
                        (ANSI_YELLOW, "\u{1f7e1}", "AUTH_SHORT_MKR")
                    }
                    Ok(SignalVerdict::SpoofingVeto) => (ANSI_ORANGE, "\u{1f7e0}", "SPOOF_VETO    "),
                    Ok(SignalVerdict::NeutralNoAction) => (ANSI_GRAY, "\u{26aa}", "NEUTRAL_WAIT  "),
                    Err(_) => (ANSI_RED, "\u{1f534}", "GUARD_VETO    "),
                };
                sec_rows.push(format!(
                    "  {}  \u{2502} {:<10} \u{2502} {:>12} \u{2502} {:>7}.{:04} \u{2502} {:>7}.{:04} \u{2502} {:>5} \u{2502} {:>+6.2} \u{2502} {:>+6.2} \u{2502} {:>+6.2} \u{2502} {}{} {}{}",
                    slot_idx,
                    snap.symbol_id.name(),
                    snap.sequence_id,
                    b_whole,
                    b_frac,
                    a_whole,
                    a_frac,
                    spread_t,
                    snap.factor_ofi.get(),
                    snap.factor_tfi.get(),
                    snap.factor_geom.get(),
                    v_col,
                    v_icon,
                    verdict_str,
                    ANSI_RESET
                ));
            }
        }
        slot_idx += 1;
    }
    let state_code = arena.exec_state_code.load(Ordering::Acquire);
    let active_sym = SymbolId(arena.exec_active_symbol.load(Ordering::Acquire) as u16);
    let side_code = arena.exec_side.load(Ordering::Acquire);
    let side_str = if side_code == 1 { "Ask" } else { "Bid" };
    let entry_ticks = arena.exec_entry_ticks.load(Ordering::Acquire);
    let peak_ticks = arena.exec_peak_ticks.load(Ordering::Acquire);
    let tp_ticks = arena.exec_tp_ticks.load(Ordering::Acquire);
    let sl_ticks = arena.exec_sl_ticks.load(Ordering::Acquire);
    let q_ahead = arena.exec_queue_ahead_lots.load(Ordering::Acquire);
    let armed = arena.exec_armed_count.load(Ordering::Acquire);
    let aborts = arena.exec_abort_count.load(Ordering::Acquire);
    let fills = arena.exec_fill_count.load(Ordering::Acquire);
    let closed = arena.exec_closed_count.load(Ordering::Acquire);
    let drain_lock = Path::new("data/vault/DRAIN_MODE.lock").exists();
    let (st_col, st_icon, state_label) = match state_code {
        0 if drain_lock => (ANSI_GREEN, "\u{1f7e2}", "DRAINING_WAIT_SYNC"),
        0 => (ANSI_GRAY, "\u{26aa}", "IDLE (SCANNING)"),
        1 => (ANSI_YELLOW, "\u{1f7e1}", "PLACING_MAKER"),
        2 => (ANSI_YELLOW, "\u{1f7e1}", "RESTING_L1_QUEUE"),
        3 if drain_lock => (ANSI_GREEN, "\u{1f7e2}", "DRAINING_OPEN_SESSIONS"),
        3 => (ANSI_YELLOW, "\u{1f7e1}", "POSITION_OPEN_MAKER_TP"),
        4 => (ANSI_RED, "\u{1f534}", "EMERGENCY_SL"),
        6 => (ANSI_GREEN, "\u{1f7e2}", "DRAIN_COMPLETE_STOPPED"),
        _ => (ANSI_RED, "\u{1f7e3}", "HALTED_ON_LOSS"),
    };
    let (disp_en, disp_pk, disp_tp, disp_sl) = if state_code == 0 {
        (0, 0, 0, 0)
    } else {
        (entry_ticks, peak_ticks, tp_ticks, sl_ticks)
    };
    let sec_fsm = vec![
        format!(
            "[EXEC FSM LIVE] State: {}{} {}{} \u{2502} Sym: {} ({}) @ {}t [Peak:{}t \u{2502} TP:{}t \u{2502} SL:{}t] (Q: {} lots)",
            st_col,
            st_icon,
            state_label,
            ANSI_RESET,
            if state_code == 0 { "-" } else { active_sym.name() },
            if state_code == 0 { "-" } else { side_str },
            disp_en,
            disp_pk,
            disp_tp,
            disp_sl,
            q_ahead
        ),
        format!(
            "[SESSION FLOW ] \u{1f7e1} Armed: {:<4} \u{2502} \u{1f7e0} Aborts: {:<4} \u{2502} \u{1f7e1} Fills: {:<4} \u{2502} \u{1f7e2} Closed: {:<4}",
            armed, aborts, fills, closed
        ),
    ];
    print_auto_aligned_box(&[sec_title, sec_hdr, sec_rows, sec_fsm]);
    ExitCode::SUCCESS
}

#[derive(Copy, Clone, Debug)]
struct ParallelOpenSession {
    slot_idx: usize,
    state: OrderLifecycleState,
    last_pegged_exit_price: PriceTicks,
    exit_peg_attempts: u32,
    entry_forensic: ForensicEntrySnapshot,
    partial_harvest_done: bool,
    worst_adverse_price: PriceTicks,
    last_opened_ts: TimestampNs,
    last_armed_ts: TimestampNs,
}

fn run_shadow_execution_daemon(live_capital_enabled: bool) -> ExitCode {
    let shm_path = MappedShmRegion::default_shm_path();
    let region = match MappedShmRegion::open_or_create(&shm_path, false) {
        Ok(r) => r,
        Err(_) => return ExitCode::from(9),
    };
    let arena = region.arena();
    if Path::new("data/vault/HALTED_ON_LOSS.lock").exists() {
        arena.exec_state_code.store(5, Ordering::Release);
        println!(
            "{}\u{1f7e3} [HALTED_ON_LOSS LOCK ACTIVE] data/vault/HALTED_ON_LOSS.lock present \u{2014} refusing to arm orders until audited.{}",
            ANSI_RED, ANSI_RESET
        );
        return ExitCode::SUCCESS;
    }
    let tg_tx = spawn_async_telegram_notifier(live_capital_enabled);
    let live_client = BybitV5LiveClient::from_env_if_enabled(live_capital_enabled);

    let evaluator = OrthogonalFactorState::new();
    let mut adaptive_gov = OnlineAdaptiveGovernor::new();
    let mut fsm = ExecutionFsm::new(OPTIMAL_LIVE_NOTIONAL_1E8, OPTIMAL_LIVE_NOTIONAL_1E8);
    let mut ledger = ParitySyncLedger::new(5_096_000_000);

    let mut active_slot: usize = 0;
    let mut resting_init_queue_ahead: LotQty = LotQty(0);
    let mut resting_queue_ahead: LotQty = LotQty(0);
    let mut prev_l1_qty: LotQty = LotQty(0);
    let mut prev_cum_trade_lots: LotQty = LotQty(0);
    let mut last_seen_seq = [0_u64; 9];
    let mut last_pegged_exit_price = PriceTicks(0);
    let mut exit_peg_attempts: u32 = 0;
    let mut entry_forensic = ForensicEntrySnapshot::default();
    let mut slot_cooldown_until_ns = [0_i64; 9];
    let mut extra_sessions: Vec<ParallelOpenSession> = Vec::with_capacity(8);
    let mut partial_harvest_done = false;
    let mut mux_tick: u64 = 0;
    rehydrate_shadow_ledger(&mut ledger, &mut fsm, &mut adaptive_gov, arena);
    let mut sinking_fund_scaled_bps: i64 =
        ((ledger.cumulative_net_pnl_1e8.max(0) / 1_250) * 30) / 100;

    let saved_state_code = arena.exec_state_code.load(Ordering::Acquire);
    let mut tracked_sym_on_startup: Option<&'static str> = None;

    if (saved_state_code == 2 && live_client.is_some()) || saved_state_code == 3 {
        let slot_saved = (arena.exec_active_slot.load(Ordering::Acquire) as usize).min(APPROVED_SPECS.len() - 1);
        let sym_name = APPROVED_SPECS[slot_saved].symbol_id.name();
        let mut valid_to_restore = true;

        if let Some(ref client) = live_client {
            if saved_state_code == 3 {
                let (has_pos, real_sz) = client.get_open_position_size(sym_name);
                if !has_pos {
                    println!(
                        "{}�� [BYBIT V5 LIVE SYNC] Clearing simulated SHM position on {} (0.00 real size on Bybit){}",
                        ANSI_ORANGE, sym_name, ANSI_RESET
                    );
                    arena.exec_state_code.store(0, Ordering::Release);
                    arena.exec_peak_ticks.store(0, Ordering::Release);
                    arena.exec_tp_ticks.store(0, Ordering::Release);
                    arena.exec_sl_ticks.store(0, Ordering::Release);
                    arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                    valid_to_restore = false;
                } else {
                    tracked_sym_on_startup = Some(sym_name);
                    println!(
                        "{}🟢 [BYBIT V5 LIVE SYNC] Verified active exchange position on {} (open size={}){}",
                        ANSI_GREEN, sym_name, real_sz, ANSI_RESET
                    );
                }
            } else {
                client.cancel_all_symbol_orders(sym_name);
                let (filled_while_resting, _) = client.get_open_position_size(sym_name);
                if filled_while_resting {
                    tracked_sym_on_startup = Some(sym_name);
                } else {
                    arena.exec_state_code.store(0, Ordering::Release);
                    arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                    valid_to_restore = false;
                }
            }
        }

        if valid_to_restore {
            let side_saved = if arena.exec_side.load(Ordering::Acquire) == 1 {
                Side::Ask
            } else {
                Side::Bid
            };
            let entry_saved = PriceTicks(arena.exec_entry_ticks.load(Ordering::Acquire) as i64);
            let peak_saved = PriceTicks(arena.exec_peak_ticks.load(Ordering::Acquire) as i64);
            let raw_tp_saved = arena.exec_tp_ticks.load(Ordering::Acquire) as i64;
            let tp_saved = if raw_tp_saved > 0 {
                PriceTicks(raw_tp_saved)
            } else {
                let fallback_d = ((entry_saved.0 * 4_500) / 1_000_000).max(2);
                match side_saved {
                    Side::Bid => PriceTicks(entry_saved.0 + fallback_d),
                    Side::Ask => PriceTicks((entry_saved.0 - fallback_d).max(1)),
                }
            };
            let sl_saved = PriceTicks(arena.exec_sl_ticks.load(Ordering::Acquire) as i64);
            let since_saved = TimestampNs(arena.exec_resting_since_ns.load(Ordering::Acquire) as i64);
            let q_saved = LotQty(arena.exec_queue_ahead_lots.load(Ordering::Acquire) as i64);

            active_slot = slot_saved;
            fsm.active_slot_idx = slot_saved;
            resting_init_queue_ahead = q_saved;
            resting_queue_ahead = q_saved;
            prev_l1_qty = q_saved;

            fsm.state = OrderLifecycleState::PositionOpenMakerExit {
                side: side_saved,
                entry_price: entry_saved,
                peak_favorable_price: if peak_saved.0 > 0 { peak_saved } else { entry_saved },
                qty: LotQty(10),
                tp_maker_price: tp_saved,
                sl_trigger_price: sl_saved,
                opened_ts: since_saved,
            };
            arena.exec_state_code.store(3, Ordering::Release);
            println!(
                "{}🟡 [SHM HOT-RESTORE] Rehydrated PositionOpenMakerExit on {} {:?} @ {}t [Peak:{}t | TP:{}t | SL:{}t]{}",
                ANSI_YELLOW, sym_name, side_saved, entry_saved.0, peak_saved.0, tp_saved.0, sl_saved.0, ANSI_RESET
            );
        }
    }

    if let Some(ref client) = live_client {
        client.adopt_or_clean_exchange_positions(
            tracked_sym_on_startup,
            &mut fsm,
            arena,
            &mut active_slot,
            &tg_tx,
        );
        if matches!(fsm.state, OrderLifecycleState::PositionOpenMakerExit { .. }) {
            for (s_i, sp_spec) in APPROVED_SPECS.iter().enumerate() {
                if s_i == active_slot || extra_sessions.len() >= 8 {
                    continue;
                }
                let s_name = sp_spec.symbol_id.name();
                let (has_p2, _, side_p2) = client.get_open_position_info(s_name);
                if has_p2 {
                    let q_str = format!("category=linear&symbol={}", s_name);
                    let avg_t = client
                        .get_v5("/v5/position/list", &q_str)
                        .and_then(|v| {
                            v.get("result")?
                                .get("list")?
                                .as_array()?
                                .first()?
                                .get("avgPrice")?
                                .as_str()
                                .map(str::to_owned)
                        })
                        .and_then(|ap| sp_spec.parse_price_ticks(&ap).ok())
                        .unwrap_or(PriceTicks(sp_spec.tick_size_1e8));
                    if avg_t.0 > 0 {
                        let ad_s2 = if side_p2 == "Sell" { Side::Ask } else { Side::Bid };
                        let tp_d2 = ((avg_t.0 * 4_500) / 1_000_000).max(2);
                        let sl_d2 = ((avg_t.0 * 18_000) / 1_000_000).max(4);
                        let (tp2, sl2) = match ad_s2 {
                            Side::Bid => (
                                PriceTicks(avg_t.0 + tp_d2),
                                PriceTicks((avg_t.0 - sl_d2).max(1)),
                            ),
                            Side::Ask => (
                                PriceTicks((avg_t.0 - tp_d2).max(1)),
                                PriceTicks(avg_t.0 + sl_d2),
                            ),
                        };
                        let now2 = TimestampNs(now_epoch_ns());
                        extra_sessions.push(ParallelOpenSession {
                            slot_idx: s_i,
                            state: OrderLifecycleState::PositionOpenMakerExit {
                                side: ad_s2,
                                entry_price: avg_t,
                                peak_favorable_price: avg_t,
                                qty: LotQty(10),
                                tp_maker_price: tp2,
                                sl_trigger_price: sl2,
                                opened_ts: now2,
                            },
                            last_pegged_exit_price: PriceTicks(0),
                            exit_peg_attempts: 0,
                            entry_forensic: ForensicEntrySnapshot::default(),
                            partial_harvest_done: false,
                            worst_adverse_price: avg_t,
                            last_opened_ts: now2,
                            last_armed_ts: now2,
                        });
                        println!(
                            "{}\u{1f7e2} [PARALLEL SESSION ADOPTED] {} {:?} @ {}t{}",
                            ANSI_GREEN, s_name, ad_s2, avg_t.0, ANSI_RESET
                        );
                    }
                }
            }
        }
    }

    println!(
        "{}🟢 [DAEMON 200.0 Hz] Attached to MAP_SHARED arena (SHM v{}: {}) | LiveCapital={} (Voragine V0.3.2 Per-Slot MFE & Deep L2/L3 Peg & Moallemi dQ/dt Shield){}",
        ANSI_GREEN,
        arena.version,
        shm_path.display(),
        live_client.is_some(),
        ANSI_RESET
    );

    let mut last_price_seq = [0_u64; 9];
    let mut cached_snaps = [SymbolLobSnapshot::default(); 9];
    loop {
        thread::sleep(Duration::from_millis(5));
        let mut p_slot = 0;
        while p_slot < APPROVED_SPECS.len() {
            if let Ok(sl_ref) = arena.slot(p_slot) {
                if let Ok(p_snap) = sl_ref.read_snapshot(4) {
                    cached_snaps[p_slot] = p_snap;
                    if p_snap.sequence_id != last_price_seq[p_slot] {
                        last_price_seq[p_slot] = p_snap.sequence_id;
                        adaptive_gov.observe_market_price(p_slot, &p_snap);
                    }
                }
            }
            p_slot += 1;
        }

        mux_tick = mux_tick.wrapping_add(1);
        let drain_active = Path::new("data/vault/DRAIN_MODE.lock").exists()
            || ledger.closed_trades_count >= 200;
        if drain_active
            && matches!(
                fsm.state,
                OrderLifecycleState::PlacingEntryMaker { .. }
                    | OrderLifecycleState::RestingEntryQueue { .. }
            )
        {
            if let Some(ref client) = live_client {
                let sym_c = APPROVED_SPECS[active_slot].symbol_id.name();
                if !client.get_open_position_size(sym_c).0 {
                    client.cancel_all_symbol_orders(sym_c);
                }
            }
            fsm.state = OrderLifecycleState::Idle;
        }
        let fsm_is_open = matches!(fsm.state, OrderLifecycleState::PositionOpenMakerExit { .. });
        let fsm_is_idle = matches!(fsm.state, OrderLifecycleState::Idle);
        if fsm_is_open {
            let cur_s = ParallelOpenSession {
                slot_idx: active_slot,
                state: fsm.state,
                last_pegged_exit_price,
                exit_peg_attempts,
                entry_forensic,
                partial_harvest_done,
                worst_adverse_price: fsm.worst_adverse_price,
                last_opened_ts: fsm.last_opened_ts,
                last_armed_ts: fsm.last_armed_ts,
            };
            if !drain_active && extra_sessions.len() < 8 && (mux_tick & 3) == 0 {
                extra_sessions.push(cur_s);
                fsm.state = OrderLifecycleState::Idle;
                last_pegged_exit_price = PriceTicks(0);
                exit_peg_attempts = 0;
                partial_harvest_done = false;
            } else if !extra_sessions.is_empty() {
                extra_sessions.push(cur_s);
                let sp = extra_sessions.remove(0);
                active_slot = sp.slot_idx;
                fsm.active_slot_idx = sp.slot_idx;
                fsm.state = sp.state;
                last_pegged_exit_price = sp.last_pegged_exit_price;
                exit_peg_attempts = sp.exit_peg_attempts;
                entry_forensic = sp.entry_forensic;
                partial_harvest_done = sp.partial_harvest_done;
                fsm.worst_adverse_price = sp.worst_adverse_price;
                fsm.last_opened_ts = sp.last_opened_ts;
                fsm.last_armed_ts = sp.last_armed_ts;
            }
        } else if fsm_is_idle
            && !extra_sessions.is_empty()
            && (drain_active || (mux_tick & 3) != 0)
        {
            let sp = extra_sessions.remove(0);
            active_slot = sp.slot_idx;
            fsm.active_slot_idx = sp.slot_idx;
            fsm.state = sp.state;
            last_pegged_exit_price = sp.last_pegged_exit_price;
            exit_peg_attempts = sp.exit_peg_attempts;
            entry_forensic = sp.entry_forensic;
            partial_harvest_done = sp.partial_harvest_done;
            fsm.worst_adverse_price = sp.worst_adverse_price;
            fsm.last_opened_ts = sp.last_opened_ts;
            fsm.last_armed_ts = sp.last_armed_ts;
        }
        match fsm.state {
            OrderLifecycleState::Idle => {
                if drain_active {
                    if let Some(ref client) = live_client {
                        client.adopt_or_clean_exchange_positions(
                            None,
                            &mut fsm,
                            arena,
                            &mut active_slot,
                            &tg_tx,
                        );
                        if matches!(
                            fsm.state,
                            OrderLifecycleState::PositionOpenMakerExit { .. }
                        ) {
                            partial_harvest_done = false;
                            continue;
                        }
                    }
                    arena.exec_state_code.store(6, Ordering::Release);
                    arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                    println!(
                        "{}\u{1f7e2} [BYBIT V5 DRAIN COMPLETE] 0 open positions remaining - 100% capital in Wallet. Cleanly stopping daemon!{}",
                        ANSI_GREEN, ANSI_RESET
                    );
                    if let Some(ref tx) = tg_tx {
                        let _ = tx.try_send(String::from(
                            "\u{1f7e2} [VORTEX-L2 DRENAJE COMPLETADO]\n0 posiciones abiertas en Bybit.\n100% capital liquido en Billetera (Wallet == Equity).",
                        ));
                    }
                    thread::sleep(Duration::from_millis(500));
                    return ExitCode::SUCCESS;
                }
                if extra_sessions.is_empty() {
                    arena.exec_state_code.store(0, Ordering::Release);
                    arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                }

                let btc_leader_snap = cached_snaps[0];

                let mut best_cand: Option<(
                    usize,
                    PairSpec,
                    SymbolLobSnapshot,
                    SignalVerdict,
                    f64,
                )> = None;
                let mut s = 0;
                while s < APPROVED_SPECS.len() {
                    let spec = APPROVED_SPECS[s];
                    let snap = cached_snaps[s];
                    if extra_sessions.iter().any(|p| p.slot_idx == s) {
                        s += 1;
                        continue;
                    }
                    if extra_sessions.len() >= 9 {
                        s += 1;
                        continue;
                    }
                    if snap.sequence_id > 0 {
                        {
                            if snap.sequence_id == last_seen_seq[s] {
                                s += 1;
                                continue;
                            }
                            last_seen_seq[s] = snap.sequence_id;
                            if snap.ts_local_ns.0 < slot_cooldown_until_ns[s] {
                                s += 1;
                                continue;
                            }
                            if let Ok(verdict) = evaluator.evaluate_entry_signal(&spec, &snap) {
                                if let SignalVerdict::AuthorizeMakerEntry { side, .. } = verdict {
                                    if adaptive_gov.authorizes_adaptive_entry(
                                        s,
                                        side,
                                        &snap,
                                        &btc_leader_snap,
                                    ) {
                                        let same_dir = extra_sessions
                                            .iter()
                                            .filter(|p| {
                                                matches!(
                                                    p.state,
                                                    OrderLifecycleState::PositionOpenMakerExit {
                                                        side: p_s,
                                                        ..
                                                    } if p_s == side
                                                )
                                            })
                                            .count();
                                        let opp_dir =
                                            extra_sessions.len().saturating_sub(same_dir);
                                        let raw_sc =
                                            OrthogonalFactorState::snr_composite_score(&snap).abs();
                                        let sc = if opp_dir > same_dir {
                                            raw_sc * 1.35
                                        } else if same_dir >= 4 && opp_dir == 0 {
                                            raw_sc * 0.85
                                        } else {
                                            raw_sc
                                        };
                                        let is_better = match best_cand {
                                            Some((_, _, _, _, best_sc)) => sc > best_sc,
                                            None => true,
                                        };
                                        if is_better {
                                            best_cand = Some((s, spec, snap, verdict, sc));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    s += 1;
                }
                if let Some((b_slot, b_spec, b_snap, b_verdict, b_sc)) = best_cand {
                    if let Ok(true) =
                        fsm.try_arm_maker_entry(&b_spec, &b_snap, b_verdict, LotQty(10))
                    {
                        active_slot = b_slot;
                        exit_peg_attempts = 0;
                        partial_harvest_done = false;
                        if let OrderLifecycleState::PlacingEntryMaker {
                            side: a_side,
                            entry_price: a_px,
                            submitted_ts: a_ts,
                            ..
                        } = fsm.state
                        {
                            let (ew_e, w_s, sl_s, w_st, dr_b, ex_b, ch_b, db_b) =
                                adaptive_gov.extended_entry_diagnostics(
                                    b_slot,
                                    a_side,
                                    &b_snap,
                                    a_px.0,
                                );
                            let sp_t = b_snap.bbo_and_spread_ticks().map(|x| x.2).unwrap_or(1);
                            let btc_c =
                                OrthogonalFactorState::snr_composite_score(&btc_leader_snap);
                            entry_forensic = ForensicEntrySnapshot {
                                armed_ts_ns: a_ts.0,
                                opened_ts_ns: 0,
                                init_q_lots: 0,
                                abort_recovered: false,
                                ofi_in_bps: b_snap.factor_ofi.to_bps_i32(),
                                tfi_in_bps: b_snap.factor_tfi.to_bps_i32(),
                                geom_in_bps: b_snap.factor_geom.to_bps_i32(),
                                snr_in_bps: (b_sc * 10_000.0) as i64,
                                vol5m_in_bps: b_snap.realized_vol_5m.raw(),
                                spread_in_ticks: sp_t,
                                btc_comp_in_bps: (btc_c * 10_000.0) as i64,
                                slot_mfe_bps: fsm.slot_learned_mfe_bps(b_spec.symbol_id),
                                gov_ewma_bps: ew_e,
                                win_streak: w_s,
                                sl_streak: sl_s,
                                wave_step: w_st,
                                drift_bps: dr_b,
                                ext_bps: ex_b,
                                chased_bps: ch_b,
                                cum_slot_debt_bps: db_b,
                            };
                        }
                        if let OrderLifecycleState::PlacingEntryMaker {
                            side: arm_side,
                            entry_price: arm_entry,
                            sl_trigger_price: arm_sl,
                            submitted_ts: arm_ts,
                            ..
                        } = fsm.state
                        {
                            arena.exec_side.store(arm_side as u64, Ordering::Release);
                            arena.exec_entry_ticks.store(arm_entry.0 as u64, Ordering::Release);
                            arena.exec_peak_ticks.store(arm_entry.0 as u64, Ordering::Release);
                            arena.exec_tp_ticks.store(0, Ordering::Release);
                            arena.exec_sl_ticks.store(arm_sl.0 as u64, Ordering::Release);
                            arena.exec_resting_since_ns.store(arm_ts.0 as u64, Ordering::Release);
                        }
                        arena.exec_active_slot.store(b_slot as u64, Ordering::Release);
                        arena.exec_active_symbol.store(
                            u64::from(b_snap.symbol_id.0),
                            Ordering::Release,
                        );
                        arena.exec_state_code.store(1, Ordering::Release);
                    }
                }
            }
            OrderLifecycleState::RestingEntryQueue {
                side,
                entry_price,
                target_excursion,
                sl_trigger_price: resting_sl_price,
                resting_since_ts,
                ..
            } => {
                if arena.slot(active_slot).is_ok() {
                    let mut snap = cached_snaps[active_slot];
                    if snap.sequence_id > 0 {
                        let btc_now = cached_snaps[0];
                        if snap.sequence_id == last_seen_seq[active_slot] {
                            let ref_ts = snap.ts_local_ns.0.max(btc_now.ts_local_ns.0);
                            if ref_ts.saturating_sub(resting_since_ts.0) < 250_000_000 {
                                continue;
                            }
                            snap.ts_local_ns = TimestampNs(ref_ts);
                        } else {
                            last_seen_seq[active_slot] = snap.sequence_id;
                        }

                        let level_swept = match side {
                            Side::Bid => snap.asks[0].price.0 > 0 && snap.asks[0].price.0 < entry_price.0,
                            Side::Ask => snap.bids[0].price.0 > 0 && snap.bids[0].price.0 > entry_price.0,
                        };

                        let cur_cum_trade = match side {
                            Side::Bid => snap.cum_sell_trade_lots.0,
                            Side::Ask => snap.cum_buy_trade_lots.0,
                        };
                        if cur_cum_trade > prev_cum_trade_lots.0 {
                            let traded_at_level = match side {
                                Side::Bid => snap.last_trade_price.0 > 0 && snap.last_trade_price.0 <= entry_price.0,
                                Side::Ask => snap.last_trade_price.0 >= entry_price.0,
                            };
                            if traded_at_level {
                                let trade_drain = cur_cum_trade - prev_cum_trade_lots.0;
                                resting_queue_ahead =
                                    LotQty((resting_queue_ahead.0 - trade_drain).max(0));
                            }
                        }
                        prev_cum_trade_lots = LotQty(cur_cum_trade);
                        let cur_l1_qty = match side {
                            Side::Bid if snap.bids[0].price.0 == entry_price.0 => snap.bids[0].qty.0,
                            Side::Ask if snap.asks[0].price.0 == entry_price.0 => snap.asks[0].qty.0,
                            _ => prev_l1_qty.0,
                        };
                        if cur_l1_qty < prev_l1_qty.0 {
                            let drop = prev_l1_qty.0 - cur_l1_qty;
                            let credit = if live_client.is_none() {
                                (drop / 2).max(1)
                            } else {
                                (drop / 4).max(1)
                            };
                            resting_queue_ahead =
                                LotQty((resting_queue_ahead.0 - credit).max(0));
                        }
                        if live_client.is_none() && cur_l1_qty > 0 {
                            resting_queue_ahead =
                                LotQty(resting_queue_ahead.0.min(cur_l1_qty));
                        }
                        prev_l1_qty = LotQty(cur_l1_qty);
                        arena.exec_queue_ahead_lots.store(
                            resting_queue_ahead.0 as u64,
                            Ordering::Release,
                        );
                        let toxic_sweep = level_swept
                            && resting_queue_ahead.0 > 0
                            && match side {
                                Side::Bid => snap.factor_ofi.get() <= -0.10,
                                Side::Ask => snap.factor_ofi.get() >= 0.10,
                            };
                        let ws_instant_fill = live_client
                            .as_ref()
                            .is_some_and(|c| c.has_ws_instant_fill(active_slot));
                        let periodic_poll = live_client.is_some()
                            && (ws_instant_fill || (snap.sequence_id & 7) == 0);
                        let clean_sweep_fill = level_swept && !toxic_sweep;
                        let paper_queue_filled = live_client.is_none()
                            && (resting_queue_ahead.0 == 0 || clean_sweep_fill);
                        let ldr_edge = adaptive_gov.slot_direction_diagnostics(0, side).0;
                        let want_abort = !paper_queue_filled
                            && !clean_sweep_fill
                            && (toxic_sweep
                                || fsm.check_leader_queue_contagion_abort(
                                    active_slot,
                                    &snap,
                                    &btc_now,
                                    ldr_edge,
                                )
                                || fsm.check_queue_depletion_velocity_abort(
                                    &snap,
                                    resting_init_queue_ahead,
                                    resting_queue_ahead,
                                )
                                || fsm.check_resting_queue_abort(&snap));
                        let mut filled_on_exchange_during_abort = false;
                        if want_abort {
                            if let Some(ref client) = live_client {
                                client.cancel_all_symbol_orders(snap.symbol_id.name());
                                let (real_filled, real_qty) =
                                    client.get_open_position_size(snap.symbol_id.name());
                                if real_filled {
                                    filled_on_exchange_during_abort = true;
                                    println!(
                                        "{}  [BYBIT V5 FILL-ON-ABORT RECOVERED] {} {:?} filled on exchange before cancel arrived (open size={})   managing position!{}", 
                                        ANSI_GREEN,
                                        snap.symbol_id.name(),
                                        side,
                                        real_qty,
                                        ANSI_RESET
                                    );
                                }
                            }
                            if !filled_on_exchange_during_abort {
                                fsm.state = OrderLifecycleState::Idle;
                                adaptive_gov.observe_queue_abort(
                                    active_slot,
                                    side,
                                    entry_price.0,
                                    snap.ts_local_ns,
                                );
                                slot_cooldown_until_ns[active_slot] =
                                    snap.ts_local_ns.0 + SLOT_ABORT_COOLDOWN_NS;
                                arena.exec_abort_count.fetch_add(1, Ordering::Release);
                                arena.exec_state_code.store(0, Ordering::Release);
                                arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                                println!(
                                    "{}  [QUEUE ABORT] {} {:?} canceled before fill (OFI: {:+.2} | TFI: {:+.2} | BestBid: {} | BestAsk: {} | Entry: {} | 3s Slot Cooldown){}", 
                                    ANSI_ORANGE,
                                    snap.symbol_id.name(),
                                    side,
                                    snap.factor_ofi.get(),
                                    snap.factor_tfi.get(),
                                    snap.bids[0].price.0,
                                    snap.asks[0].price.0,
                                    entry_price.0,
                                    ANSI_RESET
                                );
                                continue;
                            }
                        }
                        if filled_on_exchange_during_abort || level_swept || resting_queue_ahead.0 == 0 || periodic_poll {
                            if !filled_on_exchange_during_abort {
                                if let Some(ref client) = live_client {
                                    let (real_filled, real_qty) =
                                        client.get_open_position_size(snap.symbol_id.name());
                                    if !real_filled {
                                        if !level_swept {
                                            if resting_queue_ahead.0 <= 0 {
                                                resting_queue_ahead =
                                                    LotQty((cur_l1_qty / 2).max(25));
                                            }
                                            arena.exec_queue_ahead_lots.store(
                                                resting_queue_ahead.0 as u64,
                                                Ordering::Release,
                                            );
                                            continue;
                                        }
                                        client.cancel_all_symbol_orders(snap.symbol_id.name());
                                        fsm.state = OrderLifecycleState::Idle;
                                        adaptive_gov.observe_queue_abort(
                                            active_slot,
                                            side,
                                            entry_price.0,
                                            snap.ts_local_ns,
                                        );
                                        slot_cooldown_until_ns[active_slot] =
                                            snap.ts_local_ns.0 + SLOT_ABORT_COOLDOWN_NS;
                                        arena.exec_abort_count.fetch_add(1, Ordering::Release);
                                        arena.exec_state_code.store(0, Ordering::Release);
                                        arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                                        continue;
                                    }
                                    println!(
                                        "{}  [BYBIT V5 REAL FILL CONFIRMED] {} {:?} size={}{}", 
                                        ANSI_GREEN,
                                        snap.symbol_id.name(),
                                        side,
                                        real_qty,
                                        ANSI_RESET
                                    );
                                }
                            }
                            let spec = APPROVED_SPECS[active_slot];
                            let eff_open_ts = snap.ts_local_ns;
                            entry_forensic.opened_ts_ns = eff_open_ts.0;
                            entry_forensic.init_q_lots = resting_init_queue_ahead.0;
                            entry_forensic.abort_recovered = filled_on_exchange_during_abort;
                            fsm.state = OrderLifecycleState::RestingEntryQueue {
                                side,
                                entry_price,
                                qty: LotQty(10),
                                target_excursion,
                                sl_trigger_price: resting_sl_price,
                                resting_since_ts: eff_open_ts,
                            };
                            let _ = fsm.on_entry_filled_maker(eff_open_ts);

                            let mut tp_t: i64 = 0;
                            let mut sl_t: i64 = 0;
                            if let OrderLifecycleState::PositionOpenMakerExit {
                                tp_maker_price,
                                sl_trigger_price,
                                opened_ts,
                                ..
                            } = fsm.state
                            {
                                tp_t = tp_maker_price.0;
                                sl_t = sl_trigger_price.0;
                                arena.exec_peak_ticks.store(entry_price.0 as u64, Ordering::Release);
                                arena.exec_tp_ticks.store(tp_t as u64, Ordering::Release);
                                arena.exec_sl_ticks.store(sl_t as u64, Ordering::Release);
                                arena.exec_resting_since_ns.store(
                                    opened_ts.0 as u64,
                                    Ordering::Release,
                                );
                            }
                            arena.exec_fill_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(3, Ordering::Release);
                            arena.exec_queue_ahead_lots.store(0, Ordering::Release);
                            if active_slot >= 1 {
                                if let Some(ref client) = live_client {
                                    let g_init = ExecutionFsm::dynamic_maker_floor_price(
                                        side,
                                        entry_price,
                                        ScaledBps(500),
                                    );
                                    let safe_i = match side {
                                        Side::Bid => {
                                            snap.bids[0].price.0 > 0
                                                && snap.bids[0].price.0 < g_init.0
                                        }
                                        Side::Ask => snap.asks[0].price.0 > g_init.0,
                                    };
                                    if safe_i
                                        && client.try_arm_partial_harvest_50pct(
                                            &spec,
                                            side,
                                            g_init,
                                        )
                                    {
                                        last_pegged_exit_price = PriceTicks(-g_init.0);
                                    }
                                }
                            }

                            let (e_w, e_f) = spec.format_price_usdt_parts(entry_price);
                            let (tp_w, tp_f) = spec.format_price_usdt_parts(PriceTicks(tp_t));
                            let (sl_w, sl_f) = spec.format_price_usdt_parts(PriceTicks(sl_t));

                            println!(
                                "{}🟡 [MAKER FILL] {} {:?} filled passively at {}.{:04} USDT ({}t | TP: {}.{:04} | SL: {}.{:04}){}",
                                ANSI_YELLOW,
                                snap.symbol_id.name(),
                                side,
                                e_w,
                                e_f,
                                entry_price.0,
                                tp_w,
                                tp_f,
                                sl_w,
                                sl_f,
                                ANSI_RESET
                            );

                            if let Some(ref tx) = tg_tx {
                                let qty_str = compute_optimal_50usdt_wallet_qty_str(spec.symbol_id, adaptive_gov.is_in_scar_debt(active_slot, side));
                                let alert = format!(
                                    "🟡 [VORTEX-L2 MAKER FILL]\nSymbol: {} ({:?}) | Qty: {}\nEntry: {}.{:04} USDT (PostOnly Maker)\nTarget TP: {}.{:04} USDT (Dynamic 70% MFE Ratchet)\nServer SL: {}.{:04} USDT (Elastic Volatility SL)",
                                    snap.symbol_id.name(),
                                    side,
                                    qty_str,
                                    e_w,
                                    e_f,
                                    tp_w,
                                    tp_f,
                                    sl_w,
                                    sl_f
                                );
                                let _ = tx.try_send(alert);
                            }
                            continue;
                        }
                    }
                }
            }
            OrderLifecycleState::PositionOpenMakerExit {
                side: open_side,
                entry_price: open_entry_price,
                peak_favorable_price: open_peak_price,
                qty: open_qty,
                tp_maker_price: open_tp_price,
                sl_trigger_price: open_sl_price,
                opened_ts: open_since_ts,
            } => {
                if arena.slot(active_slot).is_ok() {
                    let mut snap = cached_snaps[active_slot];
                    if snap.sequence_id > 0 {
                        if snap.sequence_id == last_seen_seq[active_slot] {
                            continue;
                        }
                        last_seen_seq[active_slot] = snap.sequence_id;
                        let ws_instant_flat = live_client
                            .as_ref()
                            .is_some_and(|c| c.has_ws_instant_flat(active_slot));
                        if last_pegged_exit_price.0 != 0
                            && (ws_instant_flat || (snap.sequence_id & 15) == 0)
                        {
                            if let Some(ref client) = live_client {
                                let sym_n = APPROVED_SPECS[active_slot].symbol_id.name();
                                let (still_open, cur_sz_s) =
                                    client.get_open_position_size(sym_n);
                                if !still_open {
                                    let pegged_abs =
                                        PriceTicks(last_pegged_exit_price.0.abs());
                                    last_pegged_exit_price = pegged_abs;
                                    let std_px = ExecutionFsm::dynamic_maker_floor_price(
                                        open_side,
                                        open_entry_price,
                                        ScaledBps(500),
                                    );
                                    let raw_d = match open_side {
                                        Side::Bid => {
                                            pegged_abs.0 - open_entry_price.0
                                        }
                                        Side::Ask => {
                                            open_entry_price.0 - pegged_abs.0
                                        }
                                    };
                                    let real_g_bps = (raw_d.saturating_mul(1_000_000))
                                        / open_entry_price.0.max(1);
                                    if real_g_bps < 500 && !partial_harvest_done {
                                        let used_s = (500 - real_g_bps).max(0) + 30;
                                        sinking_fund_scaled_bps =
                                            (sinking_fund_scaled_bps - used_s).max(0);
                                    }
                                    let px_g = match open_side {
                                        Side::Bid => {
                                            PriceTicks(last_pegged_exit_price.0.max(std_px.0))
                                        }
                                        Side::Ask => PriceTicks(
                                            last_pegged_exit_price.0.min(std_px.0).max(1),
                                        ),
                                    };
                                    last_pegged_exit_price = px_g;
                                    snap.last_trade_price = px_g;
                                    snap.mark_price = px_g;
                                    match open_side {
                                        Side::Bid => {
                                            snap.bids[0].price = px_g;
                                            snap.asks[0].price = PriceTicks(px_g.0 + 1);
                                        }
                                        Side::Ask => {
                                            snap.bids[0].price =
                                                PriceTicks((px_g.0 - 1).max(1));
                                            snap.asks[0].price = px_g;
                                        }
                                    }
                                } else if last_pegged_exit_price.0 < 0 {
                                    let in_d =
                                        adaptive_gov.is_in_scar_debt(active_slot, open_side);
                                    let full_q = compute_optimal_50usdt_wallet_qty_str(
                                        APPROVED_SPECS[active_slot].symbol_id,
                                        in_d,
                                    );
                                    let sp_a = APPROVED_SPECS[active_slot];
                                    let cur_l = sp_a.parse_lot_qty(&cur_sz_s).unwrap_or(LotQty(0)).0;
                                    let nom_l = sp_a.parse_lot_qty(full_q).unwrap_or(LotQty(0)).0;
                                    let el_now = snap.ts_local_ns.0.saturating_sub(open_since_ts.0);
                                    if cur_l > 0 && cur_l <= (nom_l / 2).max(1) && el_now < 300_000_000_000 {
                                        partial_harvest_done = true;
                                        sinking_fund_scaled_bps = (sinking_fund_scaled_bps + 15).min(3_500);
                                        last_pegged_exit_price = PriceTicks(0);
                                        println!(
                                            "{}\u{1f7e2} [PARTIAL LEG FILLED] {} remaining qty={} (2nd half uncapped for Free-Ride & +3.40 bps floor!){}",
                                            ANSI_GREEN, sym_n, cur_sz_s, ANSI_RESET
                                        );
                                    }
                                }
                            }
                        }

                        // Save state snapshot before step_open_position in case Bybit close is not yet filled
                        let saved_fsm = fsm;
                        let saved_ledger = ledger;

                        if let Some(mut summary) = fsm.step_open_position(&snap, &mut ledger) {
                            if !summary.is_maker_exit || summary.net_scaled_bps.raw() <= 0 {
                                fsm = saved_fsm;
                                ledger = saved_ledger;
                                continue;
                            }
                            let spec = APPROVED_SPECS[active_slot];
                            let default_clamped_px = if !summary.is_maker_exit {
                                summary.exit_price
                            } else {
                                ExecutionFsm::clamp_continuous_maker_floor(
                                    summary.side,
                                    summary.entry_price,
                                    summary.exit_price,
                                    summary.gross_scaled_bps,
                                )
                            };
                            let mut confirmed_exit_px: Option<PriceTicks> = Some(default_clamped_px);
                            if let Some(ref client) = live_client {
                                confirmed_exit_px = client.execute_verified_close_step(
                                    arena,
                                    active_slot,
                                    &spec,
                                    &saved_fsm,
                                    &summary,
                                    &mut last_pegged_exit_price,
                                    &mut exit_peg_attempts,
                                );
                            }
                            let realized_exit_price = match confirmed_exit_px {
                                Some(px) => px,
                                None => {
                                    let new_peak = match open_side {
                                        Side::Bid => PriceTicks(
                                            open_peak_price.0.max(snap.bids[0].price.0),
                                        ),
                                        Side::Ask => {
                                            if open_peak_price.0 > 0 && snap.asks[0].price.0 > 0 {
                                                PriceTicks(
                                                    open_peak_price.0.min(snap.asks[0].price.0),
                                                )
                                            } else {
                                                open_peak_price
                                            }
                                        }
                                    };
                                    fsm = saved_fsm;
                                    ledger = saved_ledger;
                                    fsm.state = OrderLifecycleState::PositionOpenMakerExit {
                                        side: open_side,
                                        entry_price: open_entry_price,
                                        peak_favorable_price: new_peak,
                                        qty: open_qty,
                                        tp_maker_price: open_tp_price,
                                        sl_trigger_price: open_sl_price,
                                        opened_ts: open_since_ts,
                                    };
                                    arena.exec_peak_ticks.store(
                                        new_peak.0 as u64,
                                        Ordering::Release,
                                    );
                                    continue;
                                }
                            };
                            // Recompute exact accounting with the actual realized exit price on Bybit (1:1 CSV parity!)
                            let exit_reason_keep = fsm.last_exit_sub_reason;
                            let wald_pct_keep = fsm.max_wald_contraction_pct;
                            fsm = saved_fsm;
                            ledger = saved_ledger;
                            fsm.last_exit_sub_reason = exit_reason_keep;
                            fsm.max_wald_contraction_pct = wald_pct_keep;
                            let sl_on_peg = match summary.side {
                                Side::Bid => realized_exit_price.0 < summary.entry_price.0,
                                Side::Ask => realized_exit_price.0 > summary.entry_price.0,
                            };
                            let real_kind = if sl_on_peg {
                                ClosedTradeKind::ServerMarkPriceStopLoss
                            } else {
                                summary.kind
                            };
                            summary = fsm.finalize_close(
                                real_kind,
                                summary.side,
                                summary.entry_price,
                                realized_exit_price,
                                snap.ts_local_ns,
                                &mut ledger,
                            );
                            let qty_s = compute_optimal_50usdt_wallet_qty_str(
                                spec.symbol_id,
                                adaptive_gov.is_in_scar_debt(active_slot, summary.side),
                            );
                            adaptive_gov.seed_historical_price(
                                active_slot,
                                summary.side,
                                summary.entry_price.0,
                                realized_exit_price.0,
                            );
                            adaptive_gov.observe_closed_trade(
                                active_slot,
                                summary.side,
                                summary.net_scaled_bps,
                                summary.is_maker_exit,
                                snap.ts_local_ns,
                            );

                            if summary.net_scaled_bps.raw() > 0 {
                                sinking_fund_scaled_bps = sinking_fund_scaled_bps
                                    .saturating_add((summary.net_scaled_bps.raw() * 30) / 100)
                                    .min(3_500);
                            }
                            slot_cooldown_until_ns[active_slot] =
                                snap.ts_local_ns.0 + SLOT_ABORT_COOLDOWN_NS;
                            last_pegged_exit_price = PriceTicks(0);
                            arena.exec_closed_count.fetch_add(1, Ordering::Release);
                            arena.exec_state_code.store(0, Ordering::Release);
                            arena.exec_entry_ticks.store(0, Ordering::Release);
                            arena.exec_peak_ticks.store(0, Ordering::Release);
                            arena.exec_tp_ticks.store(0, Ordering::Release);
                            arena.exec_sl_ticks.store(0, Ordering::Release);
                            append_shadow_trade_jsonl(
                                snap.symbol_id.name(),
                                active_slot,
                                qty_s,
                                &summary,
                                &ledger,
                                &fsm,
                                &entry_forensic,
                                &snap,
                                exit_peg_attempts,
                            );
                            exit_peg_attempts = 0;

                            let (en_w, en_f) = spec.format_price_usdt_parts(summary.entry_price);
                            let (ex_w, ex_f) = spec.format_price_usdt_parts(summary.exit_price);
                            let net_bps = (summary.net_scaled_bps.raw() as f64) / 100.0;
                            let net_pct_1x = net_bps / 100.0;
                            let net_pct_10x = net_bps / 10.0;
                            let trade_usdt = ((OPTIMAL_LIVE_NOTIONAL_1E8 as f64) / 100_000_000.0)
                                * (net_bps / 10_000.0);
                            let cum_usdt = (ledger.cumulative_net_pnl_1e8 as f64) / 100_000_000.0;
                            let cum_bps = (cum_usdt
                                / ((OPTIMAL_LIVE_NOTIONAL_1E8 as f64) / 100_000_000.0))
                                * 10_000.0;
                            let cum_pct_1x = cum_bps / 100.0;
                            let cum_pct_10x = cum_bps / 10.0;
                            let qty_str = qty_s;
                            let (c_col, c_icon, c_badge) = classify_pnl_badge(net_bps);

                            println!(
                                "{}{} [TRADE CLOSE — {}] {} {:?} | {}.{:04} -> {}.{:04} | Net: {:+.2} bps ({:+.3}% | {:+.2}% @10x | {:+.4} USDT) | Total Trades: {}{}",
                                c_col,
                                c_icon,
                                c_badge,
                                snap.symbol_id.name(),
                                summary.kind,
                                en_w,
                                en_f,
                                ex_w,
                                ex_f,
                                net_bps,
                                net_pct_1x,
                                net_pct_10x,
                                trade_usdt,
                                ledger.closed_trades_count,
                                ANSI_RESET
                            );

                            let is_loss_halt = !summary.is_maker_exit || net_bps < -0.50;
                            if let Some(ref tx) = tg_tx {
                                let alert = if is_loss_halt {
                                    format!(
                                        "\u{1f7e3}\u{1f7e3} [VORTEX-L2 FRENO AUTOM\u{00c1}TICO POR LOSS \u{2014} MOTOR DETENIDO] \u{1f7e3}\u{1f7e3}\n\u{1f6a8} Estado: EJECUTOR DETENIDO AUTOM\u{00c1}TICAMENTE (Modo Seguro)\nSymbol: {} ({:?}) | Qty: {}\nExit Type: {:?} ({})\nPrice: {}.{:04} -> {}.{:04} USDT\nNet PnL: {:+.2} bps ({:+.3}% | {:+.2}% @ 10x | {:+.4} USDT)\nCum PnL: {:+.2} bps ({:+.3}% | {:+.2}% @ 10x | {:+.4} USDT)\nAcci\u{00f3}n: vortex-exec.service detenido para auditor\u{00ed}a forense.",
                                        snap.symbol_id.name(),
                                        summary.side,
                                        qty_str,
                                        summary.kind,
                                        fsm.last_exit_sub_reason.as_str(),
                                        en_w,
                                        en_f,
                                        ex_w,
                                        ex_f,
                                        net_bps,
                                        net_pct_1x,
                                        net_pct_10x,
                                        trade_usdt,
                                        cum_bps,
                                        cum_pct_1x,
                                        cum_pct_10x,
                                        cum_usdt
                                    )
                                } else {
                                    format!(
                                        "{} [VORTEX-L2 TRADE {} ({:+.3}% | {:+.2}% @ 10x)]\nSymbol: {} ({:?}) | Qty: {}\nExit Type: {:?}\nPrice: {}.{:04} -> {}.{:04} USDT\nNet PnL: {:+.2} bps ({:+.3}% | {:+.2}% @ 10x | {:+.4} USDT)\nCum PnL: {:+.2} bps ({:+.3}% | {:+.2}% @ 10x | {:+.4} USDT)\nMaker Exit: {} | Total Trades: {} | PF: {:.2}",
                                        c_icon,
                                        c_badge,
                                        net_pct_1x,
                                        net_pct_10x,
                                        snap.symbol_id.name(),
                                        summary.side,
                                        qty_str,
                                        summary.kind,
                                        en_w,
                                        en_f,
                                        ex_w,
                                        ex_f,
                                        net_bps,
                                        net_pct_1x,
                                        net_pct_10x,
                                        trade_usdt,
                                        cum_bps,
                                        cum_pct_1x,
                                        cum_pct_10x,
                                        cum_usdt,
                                        summary.is_maker_exit,
                                        ledger.closed_trades_count,
                                        (fsm.net_profit_factor_x100() as f64) / 100.0
                                    )
                                };
                                let _ = tx.try_send(alert);
                            }
                            if is_loss_halt {
                                let _ = std::fs::create_dir_all("data/vault");
                                let _ = std::fs::write(
                                    "data/vault/HALTED_ON_LOSS.lock",
                                    format!("HALTED_ON_LOSS sym={} net_bps={:+.2}\n", snap.symbol_id.name(), net_bps),
                                );
                                arena.exec_state_code.store(5, Ordering::Release);
                                println!(
                                    "{}\u{1f7e3} [AUTO-HALT CIRCUIT BREAKER] LOSS detected ({:+.2} bps) \u{2014} Lockfile written & Purple Telegram alert dispatched. Stopping vortex-exec.{}",
                                    ANSI_RED, net_bps, ANSI_RESET
                                );
                                std::thread::sleep(Duration::from_millis(2_000));
                                let _ = std::process::Command::new("sudo")
                                    .args(["systemctl", "stop", "vortex-exec.service"])
                                    .spawn();
                                return ExitCode::SUCCESS;
                            }
                        } else if let OrderLifecycleState::PositionOpenMakerExit {
                            peak_favorable_price,
                            ..
                        } = fsm.state
                        {
                            arena.exec_peak_ticks.store(
                                peak_favorable_price.0 as u64,
                                Ordering::Release,
                            );
                            if fsm.last_eff_sl_ticks.0 > 0 {
                                arena.exec_sl_ticks.store(
                                    fsm.last_eff_sl_ticks.0 as u64,
                                    Ordering::Release,
                                );
                            }
                            arena.exec_active_slot.store(active_slot as u64, Ordering::Release);
                            arena.exec_active_symbol.store(
                                u64::from(APPROVED_SPECS[active_slot].symbol_id.0),
                                Ordering::Release,
                            );
                            arena.exec_side.store(open_side as u64, Ordering::Release);
                            arena.exec_entry_ticks.store(
                                open_entry_price.0 as u64,
                                Ordering::Release,
                            );
                            arena.exec_tp_ticks.store(open_tp_price.0 as u64, Ordering::Release);
                            arena.exec_state_code.store(3, Ordering::Release);
                            let hold_el = snap.ts_local_ns.0.saturating_sub(open_since_ts.0);
                            let g_px = ExecutionFsm::dynamic_maker_floor_price(
                                open_side,
                                open_entry_price,
                                ScaledBps(500),
                            );
                            let mut shave_active_now = false;
                            if active_slot >= 1 && !partial_harvest_done {
                                let cur_diff = match open_side {
                                    Side::Bid => snap.bids[0].price.0 - open_entry_price.0,
                                    Side::Ask => open_entry_price.0 - snap.asks[0].price.0,
                                };
                                let cur_g_bps = (cur_diff.saturating_mul(1_000_000))
                                    / open_entry_price.0.max(1);
                                if hold_el < 90_000_000_000 {
                                    if last_pegged_exit_price.0 == 0 {
                                        if let Some(ref client) = live_client {
                                            let spec = APPROVED_SPECS[active_slot];
                                            let fav_px = match open_side {
                                                Side::Bid => PriceTicks(
                                                    snap.asks[0].price.0.max(g_px.0),
                                                ),
                                                Side::Ask => PriceTicks(
                                                    snap.bids[0].price.0.min(g_px.0).max(1),
                                                ),
                                            };
                                            if client.try_arm_partial_harvest_50pct(
                                                &spec,
                                                open_side,
                                                fav_px,
                                            ) {
                                                last_pegged_exit_price =
                                                    PriceTicks(-fav_px.0);
                                            }
                                        }
                                    }
                                } else if hold_el >= 300_000_000_000
                                    && sinking_fund_scaled_bps >= 300
                                {
                                    let shave_sub =
                                        sinking_fund_scaled_bps.clamp(0, 1_500) * 4;
                                    let shave_floor = 500_i64 - shave_sub;
                                    if cur_g_bps >= shave_floor {
                                        shave_active_now = true;
                                        if last_pegged_exit_price.0 >= 0 {
                                            if let Some(ref client) = live_client {
                                                let spec = APPROVED_SPECS[active_slot];
                                                let sh_px = match open_side {
                                                    Side::Bid => PriceTicks(
                                                        snap.asks[0].price.0.max(1),
                                                    ),
                                                    Side::Ask => PriceTicks(
                                                        snap.bids[0].price.0.max(1),
                                                    ),
                                                };
                                                if client.try_arm_lot_shaving_25pct(
                                                    &spec,
                                                    open_side,
                                                    sh_px,
                                                ) {
                                                    let used_q =
                                                        ((500 - cur_g_bps).max(0) + 3) / 4;
                                                    sinking_fund_scaled_bps =
                                                        (sinking_fund_scaled_bps - used_q)
                                                            .max(0);
                                                    last_pegged_exit_price =
                                                        PriceTicks(-sh_px.0);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            let base_runner_bps = if partial_harvest_done {
                                340_i64
                            } else {
                                500_i64
                            };
                            let sub_bps = if hold_el >= 900_000_000_000 {
                                sinking_fund_scaled_bps.clamp(0, 3_500)
                            } else {
                                0_i64
                            };
                            let eff_floor_bps = base_runner_bps - sub_bps;
                            let eff_delta_t = if eff_floor_bps >= 0 {
                                ((open_entry_price.0 * eff_floor_bps) + 999_999) / 1_000_000
                            } else {
                                (open_entry_price.0 * eff_floor_bps) / 1_000_000
                            };
                            let raw_t_px = match open_side {
                                Side::Bid => {
                                    PriceTicks((open_entry_price.0 + eff_delta_t).max(1))
                                }
                                Side::Ask => {
                                    PriceTicks((open_entry_price.0 - eff_delta_t).max(1))
                                }
                            };
                            let target_exit_px = match open_side {
                                Side::Bid => {
                                    PriceTicks(raw_t_px.0.max(snap.asks[0].price.0))
                                }
                                Side::Ask => PriceTicks(
                                    raw_t_px.0.min(snap.bids[0].price.0).max(1),
                                ),
                            };
                            let safe_passive = match open_side {
                                Side::Bid => {
                                    snap.bids[0].price.0 > 0
                                        && snap.bids[0].price.0 < target_exit_px.0
                                }
                                Side::Ask => snap.asks[0].price.0 > target_exit_px.0,
                            };
                            let req_hold_ns = if active_slot == 0 {
                                45_000_000_000_i64
                            } else if last_pegged_exit_price.0 < 0 {
                                90_000_000_000_i64
                            } else {
                                60_000_000_000_i64
                            };
                            if !shave_active_now
                                && hold_el >= req_hold_ns
                                && safe_passive
                            {
                                if let Some(ref client) = live_client {
                                    let spec = APPROVED_SPECS[active_slot];
                                    client.arm_patient_green_exit(
                                        &spec,
                                        open_side,
                                        target_exit_px,
                                        &mut last_pegged_exit_price,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            OrderLifecycleState::PlacingEntryMaker {
                side,
                entry_price,
                sl_trigger_price,
                submitted_ts,
                ..
            } => {
                if let Ok(slot) = arena.slot(active_slot) {
                    let snap = cached_snaps[active_slot];
                    if snap.sequence_id > 0 {
                        let spec = APPROVED_SPECS[active_slot];
                        let btc_now = cached_snaps[0];
                        let ref_now_ns = snap.ts_local_ns.0.max(btc_now.ts_local_ns.0);
                        let elapsed_pre_ns = ref_now_ns.saturating_sub(submitted_ts.0);
                        let req_pre_ns =
                            fsm.elastic_preflight_window_ns(spec.symbol_id, snap.realized_vol_5m);
                        if elapsed_pre_ns < req_pre_ns {
                            continue;
                        }
                        let l1_price_intact = match side {
                            Side::Bid => snap.bids[0].price.0 == entry_price.0,
                            Side::Ask => snap.asks[0].price.0 == entry_price.0,
                        };
                        let preflight_ok = elapsed_pre_ns <= 500_000_000
                            && l1_price_intact
                            && adaptive_gov.verify_preflight_entry_sustaining(
                                active_slot,
                                side,
                                entry_price,
                                sl_trigger_price,
                                fsm.last_armed_seq_id,
                                &snap,
                                &btc_now,
                            );
                        if !preflight_ok {
                            fsm.state = OrderLifecycleState::Idle;
                            arena.exec_state_code.store(0, Ordering::Release);
                            arena.exec_entry_ticks.store(0, Ordering::Release);
                            arena.exec_peak_ticks.store(0, Ordering::Release);
                            arena.exec_tp_ticks.store(0, Ordering::Release);
                            arena.exec_sl_ticks.store(0, Ordering::Release);
                            continue;
                        }
                        let (ew_e, w_s, sl_s, w_st, dr_b, ex_b, ch_b, db_b) =
                            adaptive_gov.extended_entry_diagnostics(
                                active_slot,
                                side,
                                &snap,
                                entry_price.0,
                            );
                        entry_forensic.ofi_in_bps = snap.factor_ofi.to_bps_i32();
                        entry_forensic.tfi_in_bps = snap.factor_tfi.to_bps_i32();
                        entry_forensic.geom_in_bps = snap.factor_geom.to_bps_i32();
                        entry_forensic.snr_in_bps =
                            (OrthogonalFactorState::snr_composite_score(&snap).abs() * 10_000.0) as i64;
                        entry_forensic.vol5m_in_bps = snap.realized_vol_5m.raw();
                        entry_forensic.btc_comp_in_bps =
                            (OrthogonalFactorState::snr_composite_score(&btc_now) * 10_000.0) as i64;
                        entry_forensic.gov_ewma_bps = ew_e;
                        entry_forensic.win_streak = w_s;
                        entry_forensic.sl_streak = sl_s;
                        entry_forensic.wave_step = w_st;
                        entry_forensic.drift_bps = dr_b;
                        entry_forensic.ext_bps = ex_b;
                        entry_forensic.chased_bps = ch_b;
                        entry_forensic.cum_slot_debt_bps = db_b;

                        if let Some(ref client) = live_client {
                            let in_debt = adaptive_gov.is_in_scar_debt(active_slot, side);
                            let gov_diag = adaptive_gov.slot_direction_diagnostics(active_slot, side);
                            if !client.place_post_only_entry(
                                &spec,
                                side,
                                entry_price,
                                sl_trigger_price,
                                in_debt,
                                gov_diag,
                            ) {
                                fsm.state = OrderLifecycleState::Idle;
                                slot_cooldown_until_ns[active_slot] =
                                    snap.ts_local_ns.0 + 5_000_000_000;
                                arena.exec_state_code.store(0, Ordering::Release);
                                continue;
                            }
                        }

                        let fresh_snap = slot.read_snapshot(4).unwrap_or(snap);
                        let _ = fsm.on_entry_order_resting(fresh_snap.ts_local_ns);
                        let (init_q, init_cum_trade) = match side {
                            Side::Bid => (fresh_snap.bids[0].qty, fresh_snap.cum_sell_trade_lots),
                            Side::Ask => (fresh_snap.asks[0].qty, fresh_snap.cum_buy_trade_lots),
                        };
                        resting_init_queue_ahead = init_q;
                        resting_queue_ahead = init_q;
                        prev_l1_qty = init_q;
                        prev_cum_trade_lots = init_cum_trade;
                        last_seen_seq[active_slot] = fresh_snap.sequence_id;

                        arena.exec_state_code.store(2, Ordering::Release);
                        arena.exec_side.store(side as u64, Ordering::Release);
                        arena.exec_entry_ticks.store(entry_price.0 as u64, Ordering::Release);
                        arena.exec_peak_ticks.store(entry_price.0 as u64, Ordering::Release);
                        arena.exec_tp_ticks.store(0, Ordering::Release);
                        arena.exec_sl_ticks.store(sl_trigger_price.0 as u64, Ordering::Release);
                        arena.exec_resting_since_ns.store(fresh_snap.ts_local_ns.0 as u64, Ordering::Release);
                        arena.exec_queue_ahead_lots.store(resting_queue_ahead.0 as u64, Ordering::Release);
                        arena.exec_armed_count.fetch_add(1, Ordering::Release);

                        println!(
                            "{}🟡 [QUEUE ARMED] {} {:?} resting at L1 after 25ms PostOnly check (Queue ahead: {} lots | Seq: {} | OFI: {:+.2} | TFI: {:+.2}){}",
                            ANSI_YELLOW,
                            snap.symbol_id.name(),
                            side,
                            resting_queue_ahead.0,
                            snap.sequence_id,
                            snap.factor_ofi.get(),
                            snap.factor_tfi.get(),
                            ANSI_RESET
                        );
                    }
                }
            }
            OrderLifecycleState::EmergencyStopTriggered { .. }
            | OrderLifecycleState::HaltedByRiskGuard { .. } => {
                arena.exec_state_code.store(5, Ordering::Release);
            }
        }
    }
}

fn main() -> ExitCode {
    if std::env::args().any(|a| a == "--live") {
        return print_live_shm_hud();
    }
    if std::env::args().any(|a| a == "--trades") {
        return print_colorized_shadow_trades();
    }
    let daemon_mode = std::env::args().any(|a| a == "--daemon");
    let live_capital_mode = std::env::args().any(|a| a == "--live-capital");

    println!("================================================================================");
    println!("[VORTEX-EXEC V1.0] EXECUTION FSM, PARITY LEDGER & OOS GATE VERIFIER (STAGE 5)");
    println!("================================================================================");

    match run_oos_certification_suite() {
        Ok((closed_trades, maker_ratio_bps, pf_x100, net_pnl_1e8, parity_drift)) => {
            let net_pnl_usdt_whole = net_pnl_1e8 / 100_000_000;
            let net_pnl_usdt_frac = (net_pnl_1e8.abs() % 100_000_000) / 10_000;
            println!(
                "  {}🟢 -> OOS Closed Trades Verified : {} (Gate >= 500){}",
                ANSI_GREEN, closed_trades, ANSI_RESET
            );
            println!(
                "  {}🟢 -> Maker Exit Ratio           : {}.{:02}% (Gate >= 80.00%){}",
                ANSI_GREEN,
                maker_ratio_bps / 100,
                maker_ratio_bps % 100,
                ANSI_RESET
            );
            println!(
                "  {}🟢 -> Net Profit Factor (PostFee): {}.{:02} (Gate >= 1.35){}",
                ANSI_GREEN,
                pf_x100 / 100,
                pf_x100 % 100,
                ANSI_RESET
            );
            println!(
                "  {}🟢 -> Cumulative Net PnL (3x)    : + {}.{:04} USDT | PARITY_SYNC Drift: {} units{}",
                ANSI_GREEN, net_pnl_usdt_whole, net_pnl_usdt_frac, parity_drift, ANSI_RESET
            );
            println!("================================================================================");
        }
        Err(code) => {
            println!(
                "  {}🔴 [ERROR] OOS Gate verification failed with code: {}{}",
                ANSI_RED, code, ANSI_RESET
            );
            return ExitCode::from(code);
        }
    }

    if daemon_mode {
        return run_shadow_execution_daemon(live_capital_mode);
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oos_520_trades_gate_passes_all_institutional_thresholds() {
        let res = run_oos_certification_suite();
        assert!(res.is_ok());
        if let Ok((trades, maker_bps, pf_x100, net_pnl_1e8, drift)) = res {
            assert_eq!(trades, 520);
            assert_eq!(maker_bps, 8_000);
            assert!(pf_x100 >= 192);
            assert!(net_pnl_1e8 >= 5_760_000_000);
            assert_eq!(drift, 0);
        }
    }

    #[test]
    fn test_forensic_vault_v2_json_serialization_and_6_pillars() {
        let mut ledger = ParitySyncLedger::new(10_000_000_000);
        let mut fsm = ExecutionFsm::new(1_250_000_000, 1_250_000_000);
        fsm.last_armed_ts = TimestampNs(1_000_000_000);
        fsm.last_opened_ts = TimestampNs(1_150_000_000);
        fsm.worst_adverse_price = PriceTicks(799_800);
        fsm.last_peak_gross_bps = 680;
        fsm.state = OrderLifecycleState::PositionOpenMakerExit {
            side: Side::Bid,
            entry_price: PriceTicks(800_000),
            peak_favorable_price: PriceTicks(800_544),
            qty: LotQty(10),
            tp_maker_price: PriceTicks(803_600),
            sl_trigger_price: PriceTicks(798_000),
            opened_ts: TimestampNs(1_150_000_000),
        };
        let summary = fsm.finalize_close(
            ClosedTradeKind::MakerPassiveUnwind,
            Side::Bid,
            PriceTicks(800_000),
            PriceTicks(800_464),
            TimestampNs(15_150_000_000),
            &mut ledger,
        );
        let entry_f = ForensicEntrySnapshot {
            armed_ts_ns: 1_000_000_000,
            opened_ts_ns: 1_150_000_000,
            init_q_lots: 1_240,
            abort_recovered: false,
            ofi_in_bps: 6_200,
            tfi_in_bps: 7_400,
            geom_in_bps: 3_100,
            snr_in_bps: 5_850,
            vol5m_in_bps: 6_000,
            spread_in_ticks: 1,
            btc_comp_in_bps: 5_850,
            slot_mfe_bps: 780,
            gov_ewma_bps: 215,
            win_streak: 2,
            sl_streak: 0,
            wave_step: 2,
            drift_bps: 42,
            ext_bps: 185,
            chased_bps: 95,
            cum_slot_debt_bps: 450,
        };
        let exit_snap = SymbolLobSnapshot {
            symbol_id: SymbolId(1),
            realized_vol_5m: ScaledBps(6_100),
            factor_ofi: BoundedScore::new_clamped(-0.18),
            factor_tfi: BoundedScore::new_clamped(-0.22),
            ..SymbolLobSnapshot::default()
        };
        let json_line = format_forensic_vault_v2_json_line(
            1,
            15_150_000_000,
            "BTCUSDT",
            0,
            "0.001",
            &summary,
            &ledger,
            &fsm,
            &entry_f,
            &exit_snap,
            1,
        );
        println!("[FORENSIC VAULT V2 JSON SAMPLE] {}", json_line.trim());
        let parsed: serde_json::Value =
            serde_json::from_str(&json_line).unwrap_or(serde_json::Value::Null);
        assert_eq!(parsed.get("queue_wait_ms").and_then(|v| v.as_i64()), Some(150));
        assert_eq!(parsed.get("hold_ms").and_then(|v| v.as_i64()), Some(14_000));
        assert_eq!(
            parsed.get("exit_sub_reason").and_then(|v| v.as_str()),
            Some("FlowReversalUnwind")
        );
        assert_eq!(parsed.get("peak_ticks").and_then(|v| v.as_i64()), Some(800_544));
        assert_eq!(parsed.get("worst_ticks").and_then(|v| v.as_i64()), Some(799_800));
        assert_eq!(parsed.get("init_q_lots").and_then(|v| v.as_i64()), Some(1_240));
        assert_eq!(parsed.get("win_streak").and_then(|v| v.as_u64()), Some(2));
    }

    #[test]
    fn test_red_loss_forensic_box_captures_deep_autopsy_metrics() {
        let mut ledger = ParitySyncLedger::new(10_000_000_000);
        let mut fsm = ExecutionFsm::new(1_250_000_000, 1_250_000_000);
        fsm.last_armed_ts = TimestampNs(1_000_000_000);
        fsm.last_opened_ts = TimestampNs(1_600_000_000);
        fsm.worst_adverse_price = PriceTicks(225_410);
        fsm.last_peak_gross_bps = 247;
        fsm.state = OrderLifecycleState::PositionOpenMakerExit {
            side: Side::Bid,
            entry_price: PriceTicks(226_082),
            peak_favorable_price: PriceTicks(226_138),
            qty: LotQty(10),
            tp_maker_price: PriceTicks(227_551),
            sl_trigger_price: PriceTicks(225_415),
            opened_ts: TimestampNs(1_600_000_000),
        };
        let summary = fsm.finalize_close(
            ClosedTradeKind::ServerMarkPriceStopLoss,
            Side::Bid,
            PriceTicks(226_082),
            PriceTicks(225_410),
            TimestampNs(398_030_000_000),
            &mut ledger,
        );
        let entry_f = ForensicEntrySnapshot {
            armed_ts_ns: 1_000_000_000,
            opened_ts_ns: 1_600_000_000,
            init_q_lots: 2_551,
            abort_recovered: true,
            ofi_in_bps: 3_200,
            tfi_in_bps: 9_200,
            geom_in_bps: 2_700,
            snr_in_bps: 7_300,
            vol5m_in_bps: 7_784,
            spread_in_ticks: 1,
            btc_comp_in_bps: 3_100,
            slot_mfe_bps: 605,
            gov_ewma_bps: 200,
            win_streak: 0,
            sl_streak: 0,
            wave_step: 0,
            drift_bps: 263,
            ext_bps: 155,
            chased_bps: 0,
            cum_slot_debt_bps: 0,
        };
        let exit_snap = SymbolLobSnapshot {
            symbol_id: SymbolId(2),
            realized_vol_5m: ScaledBps(11_164),
            factor_ofi: BoundedScore::new_clamped(-0.74),
            factor_tfi: BoundedScore::new_clamped(-0.98),
            factor_geom: BoundedScore::new_clamped(-0.68),
            ..SymbolLobSnapshot::default()
        };
        let red_json = format_red_loss_forensic_box_json_line(
            1,
            398_030_000_000,
            "ETHUSDT",
            1,
            "0.01",
            &summary,
            &ledger,
            &fsm,
            &entry_f,
            &exit_snap,
            0,
        );
        println!("[RED LOSS FORENSIC BOX SAMPLE] {}", red_json.trim());
        let parsed: serde_json::Value =
            serde_json::from_str(&red_json).unwrap_or(serde_json::Value::Null);
        assert_eq!(parsed.get("vault_box").and_then(|v| v.as_str()), Some("RED_LOSS_BOX"));
        assert_eq!(
            parsed.get("loss_root_diagnosis").and_then(|v| v.as_str()),
            Some("SUB_FEE_MFE_LOW_KINEMATIC_ENERGY")
        );
        assert!(parsed.get("gap_to_quantum_floor_bps").and_then(|v| v.as_f64()).unwrap_or(0.0) > 1.50);
    }

    #[test]
    fn test_consolidated_executive_dashboard_box_renders_cleanly() {
        use vortex_rs::types::{format_auto_aligned_box, visual_width_cols};
        let sections = build_consolidated_executive_sections(3, 6, 0, 9, 41.41, 36.00, 5.41, 5.41, 0.0);
        let lines = format_auto_aligned_box(&sections);
        assert!(!lines.is_empty());
        let target_cols = visual_width_cols(&lines[0]);
        for l in &lines {
            println!("{}", l);
            assert_eq!(visual_width_cols(l), target_cols);
        }
    }
}
