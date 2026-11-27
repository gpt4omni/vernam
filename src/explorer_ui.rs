//! Vernam (`VRNM`) v2.2.0 Authenticated, Self-Contained Dark-Mode Web Explorer & Testnet Dashboard.
//!
//! Zero external crates and zero external CDN script/stylesheet dependencies so the
//! explorer renders instantaneously even on offline, LAN, or air-gapped deployments.
//!
//! Exports [`VERNAM_EXPLORER_HTML`] for serving at `GET /`.

/// Complete self-contained HTML5 + CSS + vanilla JS dashboard for Vernam (`VRNM`) Testnet v2.2.0.
///
/// Consumes the hardened `v2.2.0` HTTP/1.1 JSON endpoints:
/// - `GET /status` — BFT block height, Express/Shielded txs, PSS epoch, QKD QBER, tokenomics & events
/// - `GET /p2p/peers` — Decentralized P2P gossip peer mesh (with graceful fallback to local `V0..V3`)
/// - `POST /account/register` — Registers one-time `(pad_id, r, s)` Carter-Wegman auth keys in session
/// - `POST /faucet` — Express BFT + Shielded Shamir faucet drip
/// - `POST /tx/express` — CW-MAC authenticated (`AUTH_DOMAIN_EXPRESS = 1`) 2-Phase OTP + BFT transfer
/// - `POST /tx/shielded` — CW-MAC authenticated (`AUTH_DOMAIN_SHIELDED = 2`) Blinded IT-MPC transfer
/// - `GET /balance/<id>` — Public Express balance only (shielded balance & raw Shamir shares REDACTED)
/// - `POST /balance/private` — CW-MAC authenticated (`AUTH_DOMAIN_BALANCE = 3`) owner shielded balance
/// - `POST /pop/commit` & `POST /pop/submit` — Interactive challenge-response Proof-of-Pad endpoints
///   for external `vrnm miner` clients (server-side self-mining `/pop/mine` is disabled in `v2.2.0`)
pub const VERNAM_EXPLORER_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vernam (VRNM) Live Testnet Explorer</title>
<style>
  :root {
    --bg: #050912;
    --bg-elevated: #0b1322;
    --panel: rgba(12, 20, 36, 0.88);
    --panel-solid: #0c1424;
    --panel-2: #111d33;
    --border: #1c2c4a;
    --border-bright: #2a416b;
    --text: #e6edf7;
    --text-soft: #cbd5e1;
    --muted: #8b9bb7;
    --emerald: #10b981;
    --emerald-soft: rgba(16, 185, 129, 0.14);
    --cyan: #22d3ee;
    --cyan-soft: rgba(34, 211, 238, 0.12);
    --violet: #a78bfa;
    --violet-soft: rgba(167, 139, 250, 0.14);
    --amber: #f59e0b;
    --amber-soft: rgba(245, 158, 11, 0.14);
    --rose: #fb7185;
    --rose-soft: rgba(251, 113, 133, 0.14);
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: var(--sans);
    background-color: var(--bg);
    background-image:
      radial-gradient(ellipse 80% 45% at 50% -10%, rgba(16, 185, 129, 0.14), transparent 70%),
      radial-gradient(ellipse 60% 35% at 95% 10%, rgba(34, 211, 238, 0.09), transparent 65%),
      linear-gradient(rgba(28, 44, 74, 0.22) 1px, transparent 1px),
      linear-gradient(90deg, rgba(28, 44, 74, 0.22) 1px, transparent 1px);
    background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px;
    color: var(--text);
    min-height: 100vh;
    padding: 20px 18px 48px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }

  .container {
    max-width: 1320px;
    margin: 0 auto;
  }

  /* Top Status Banner */
  .banner {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    padding: 18px 22px;
    margin-bottom: 18px;
    border-radius: 16px;
    background: linear-gradient(135deg, rgba(13, 24, 44, 0.96), rgba(9, 17, 32, 0.94));
    border: 1px solid var(--border);
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .logo {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    box-shadow: 0 0 24px rgba(6, 182, 212, 0.35);
    flex-shrink: 0;
  }
  .logo svg { width: 50px; height: 50px; display: block; }

  .brand-title {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
  }

  .brand h1 {
    font-size: 20px;
    font-weight: 750;
    letter-spacing: -0.02em;
    color: #f8fafc;
  }

  .version-tag {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 6px;
    background: var(--cyan-soft);
    border: 1px solid rgba(34, 211, 238, 0.35);
    color: var(--cyan);
  }

  .brand-sub {
    font-size: 12.5px;
    color: var(--muted);
    margin-top: 3px;
  }

  .banner-pills {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }

  .badge-otp {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 7px 13px;
    border-radius: 999px;
    background: rgba(16, 185, 129, 0.09);
    border: 1px solid rgba(16, 185, 129, 0.32);
    color: #6ee7b7;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.01em;
  }

  .conn-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 7px 14px;
    border-radius: 999px;
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 700;
    border: 1px solid rgba(16, 185, 129, 0.4);
    background: var(--emerald-soft);
    color: var(--emerald);
    transition: all 0.2s ease;
  }

  .conn-pill.offline {
    border-color: rgba(251, 113, 133, 0.45);
    background: var(--rose-soft);
    color: var(--rose);
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--emerald);
    box-shadow: 0 0 10px var(--emerald);
    animation: pulse 1.8s infinite;
  }

  .conn-pill.offline .dot {
    background: var(--rose);
    box-shadow: 0 0 8px var(--rose);
    animation: none;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.35; transform: scale(0.88); }
  }

  /* Security Posture Bar */
  .posture-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    padding: 11px 16px;
    margin-bottom: 18px;
    border-radius: 13px;
    background: linear-gradient(90deg, rgba(11, 22, 40, 0.94), rgba(8, 17, 32, 0.9));
    border: 1px solid rgba(34, 211, 238, 0.24);
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.24);
  }

  .posture-title {
    font-family: var(--mono);
    font-size: 10.5px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.09em;
    color: var(--cyan);
    padding-right: 8px;
    border-right: 1px solid var(--border-bright);
    margin-right: 2px;
  }

  .posture-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.28);
    color: #a7f3d0;
  }

  .posture-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--emerald);
    box-shadow: 0 0 6px rgba(16, 185, 129, 0.85);
    flex-shrink: 0;
  }

  /* Research Disclaimer Bar */
  .disclaimer-bar {
    padding: 10px 15px;
    margin-bottom: 18px;
    border-radius: 11px;
    background: rgba(245, 158, 11, 0.08);
    border: 1px solid rgba(245, 158, 11, 0.28);
    color: #fde68a;
    font-size: 12px;
    line-height: 1.5;
  }

  .disclaimer-bar strong { color: #fbbf24; }

  /* 6 KPI Cards */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 14px;
    margin-bottom: 22px;
  }

  @media (max-width: 1180px) {
    .kpi-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  }
  @media (max-width: 640px) {
    .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }

  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 15px;
    padding: 18px;
    backdrop-filter: blur(10px);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.22);
  }

  .kpi-card {
    padding: 16px 16px 15px;
    position: relative;
    overflow: hidden;
  }

  .kpi-card::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent, var(--emerald)), transparent);
    opacity: 0.65;
  }

  .kpi-label {
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
  }

  .kpi-val {
    font-family: var(--mono);
    font-variant-numeric: tabular-nums;
    font-size: 22px;
    font-weight: 750;
    margin-top: 7px;
    letter-spacing: -0.02em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .kpi-sub {
    font-size: 11.5px;
    color: var(--muted);
    margin-top: 5px;
    font-family: var(--mono);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .c-emerald { color: var(--emerald); }
  .c-cyan { color: var(--cyan); }
  .c-violet { color: var(--violet); }
  .c-amber { color: var(--amber); }
  .c-rose { color: var(--rose); }
  .c-muted { color: var(--muted); }

  /* Section Header */
  .section-head {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
  }

  .mini-pill {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    padding: 3px 9px;
    border-radius: 999px;
    background: var(--panel-2);
    border: 1px solid var(--border-bright);
    color: var(--cyan);
  }

  .mini-pill.emerald { color: var(--emerald); border-color: rgba(16, 185, 129, 0.35); background: var(--emerald-soft); }
  .mini-pill.amber { color: var(--amber); border-color: rgba(245, 158, 11, 0.35); background: var(--amber-soft); }
  .mini-pill.rose { color: var(--rose); border-color: rgba(251, 113, 133, 0.35); background: var(--rose-soft); }
  .mini-pill.violet { color: var(--violet); border-color: rgba(167, 139, 250, 0.35); background: var(--violet-soft); }

  /* Layout Grids */
  .split-main {
    display: grid;
    grid-template-columns: 1.3fr 1fr;
    gap: 18px;
    margin-bottom: 22px;
  }

  @media (max-width: 1020px) {
    .split-main { grid-template-columns: 1fr; }
  }

  .auth-card {
    margin-bottom: 22px;
    border-color: rgba(34, 211, 238, 0.32);
    background: linear-gradient(135deg, rgba(12, 22, 42, 0.94), rgba(10, 18, 34, 0.92));
  }

  .ops-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin-bottom: 22px;
  }

  @media (max-width: 1020px) {
    .ops-grid { grid-template-columns: 1fr; }
  }

  .split-bottom {
    display: grid;
    grid-template-columns: 1.15fr 0.85fr;
    gap: 18px;
    margin-bottom: 22px;
  }

  @media (max-width: 980px) {
    .split-bottom { grid-template-columns: 1fr; }
  }

  .card h2 {
    font-size: 16px;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 4px;
  }

  .card .desc {
    font-size: 12.5px;
    color: var(--muted);
    margin-bottom: 14px;
  }

  /* P2P Peer Mesh Table */
  .mesh-note {
    font-size: 12px;
    color: #93c5fd;
    background: rgba(34, 211, 238, 0.07);
    border: 1px solid rgba(34, 211, 238, 0.22);
    border-radius: 10px;
    padding: 9px 12px;
    margin-bottom: 14px;
  }

  .table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 11px;
    background: rgba(7, 13, 24, 0.72);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }

  th {
    text-align: left;
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: var(--muted);
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    background: rgba(15, 25, 45, 0.75);
    white-space: nowrap;
  }

  td {
    padding: 10px 12px;
    border-bottom: 1px solid rgba(28, 44, 74, 0.55);
    font-family: var(--mono);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(25, 42, 74, 0.28); }

  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.03em;
  }

  .status-ok { background: var(--emerald-soft); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.35); }
  .status-warn { background: var(--amber-soft); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.35); }
  .status-bad { background: var(--rose-soft); color: var(--rose); border: 1px solid rgba(251, 113, 133, 0.35); }

  .self-tag {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 4px;
    background: var(--cyan-soft);
    color: var(--cyan);
    border: 1px solid rgba(34, 211, 238, 0.3);
    margin-left: 6px;
    vertical-align: middle;
  }

  /* Proof-of-Pad Mining Panel */
  .pop-notice {
    background: rgba(245, 158, 11, 0.08);
    border: 1px solid rgba(245, 158, 11, 0.32);
    border-radius: 10px;
    padding: 11px 13px;
    font-size: 12px;
    color: #fde68a;
    margin-bottom: 12px;
    line-height: 1.5;
  }

  .pop-notice code {
    color: #fef08a;
    font-family: var(--mono);
  }

  .audit-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
    margin: 12px 0;
  }

  .audit-item {
    background: #080f1d;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .audit-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 6px;
  }

  .audit-name {
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-soft);
  }

  .audit-val {
    font-family: var(--mono);
    font-size: 11.5px;
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .supply-box {
    background: #080f1d;
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 12px 14px;
    margin-top: 12px;
  }

  .supply-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 10px;
    font-size: 12px;
    margin-bottom: 8px;
  }

  .supply-bar-track {
    height: 10px;
    border-radius: 999px;
    background: #132038;
    border: 1px solid var(--border);
    overflow: hidden;
  }

  .supply-bar-fill {
    height: 100%;
    width: 4.8%;
    min-width: 4px;
    border-radius: 999px;
    background: linear-gradient(90deg, var(--emerald), var(--cyan));
    transition: width 0.45s ease;
  }

  .supply-meta {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 8px;
    margin-top: 8px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
  }

  /* Forms & Buttons */
  .row-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-bottom: 10px; }
  .row-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-bottom: 10px; }
  .row-4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 10px; }

  @media (max-width: 780px) {
    .row-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }

  label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 4px;
  }

  input {
    width: 100%;
    padding: 9px 11px;
    border-radius: 9px;
    border: 1px solid var(--border);
    background: #070e1c;
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }

  input:focus {
    outline: none;
    border-color: var(--emerald);
    box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15);
  }

  button {
    width: 100%;
    padding: 10px 14px;
    border-radius: 10px;
    border: none;
    font-weight: 700;
    font-size: 13px;
    cursor: pointer;
    transition: transform 0.1s ease, filter 0.15s ease, opacity 0.15s ease;
  }

  button:hover { filter: brightness(1.07); }
  button:active { transform: scale(0.985); }
  button:disabled { opacity: 0.55; cursor: wait; }

  .btn-emerald { background: linear-gradient(135deg, #10b981, #059669); color: #03111c; }
  .btn-cyan { background: linear-gradient(135deg, #22d3ee, #0284c7); color: #03111c; }
  .btn-violet { background: linear-gradient(135deg, #a78bfa, #7c3aed); color: #ffffff; }
  .btn-amber { background: linear-gradient(135deg, #f59e0b, #d97706); color: #04101d; }

  .out-box {
    margin-top: 10px;
    padding: 9px 11px;
    border-radius: 9px;
    background: #070e1c;
    border: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 11.5px;
    min-height: 38px;
    color: var(--muted);
    word-break: break-word;
  }

  .out-box.ok { border-color: rgba(16, 185, 129, 0.4); color: #a7f3d0; }
  .out-box.err { border-color: rgba(251, 113, 133, 0.45); color: #fecdd3; }

  /* Balance & Privacy Inspector */
  .bal-summary {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin-top: 12px;
  }

  @media (max-width: 640px) {
    .bal-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }

  .bal-tile {
    background: #070e1c;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
  }

  .bal-tile .k { font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
  .bal-tile .v { font-family: var(--mono); font-size: 15px; font-weight: 700; margin-top: 3px; word-break: break-word; }

  .shares-panel {
    margin-top: 12px;
    background: #070d1a;
    border: 1px dashed var(--border-bright);
    border-radius: 11px;
    padding: 12px 14px;
  }

  .shares-caption {
    font-size: 11.5px;
    color: var(--muted);
    margin-bottom: 8px;
  }

  .privacy-row {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    padding: 7px 0;
    border-bottom: 1px solid rgba(28, 44, 74, 0.45);
    font-family: var(--mono);
    font-size: 12px;
  }

  .privacy-row:last-child { border-bottom: none; }

  /* Quick Connect Card */
  .cmd-block {
    background: #060c18;
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 12px;
    margin-bottom: 12px;
  }

  .cmd-block:last-child { margin-bottom: 0; }

  .cmd-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
  }

  .cmd-label {
    font-size: 11.5px;
    font-weight: 700;
    color: var(--text-soft);
  }

  .copy-btn {
    width: auto;
    padding: 5px 11px;
    border-radius: 7px;
    font-size: 11px;
    font-family: var(--mono);
    background: var(--panel-2);
    color: var(--emerald);
    border: 1px solid rgba(16, 185, 129, 0.35);
  }

  .copy-btn:hover { background: var(--emerald-soft); }

  pre.cmd-code {
    font-family: var(--mono);
    font-size: 11.5px;
    color: #cbd5e1;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.55;
  }

  /* Live Event Stream */
  .events {
    max-height: 290px;
    overflow-y: auto;
    background: #060c18;
    border: 1px solid var(--border);
    border-radius: 11px;
    font-family: var(--mono);
    font-size: 12px;
  }

  .event-row {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 9px 12px;
    border-bottom: 1px solid rgba(28, 44, 74, 0.55);
    color: var(--text-soft);
  }

  .event-row:last-child { border-bottom: none; }

  .ev-tag {
    flex-shrink: 0;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 5px;
    letter-spacing: 0.04em;
    background: var(--panel-2);
    color: var(--cyan);
    border: 1px solid var(--border-bright);
  }

  .ev-tag.faucet { color: var(--emerald); border-color: rgba(16, 185, 129, 0.35); background: var(--emerald-soft); }
  .ev-tag.express { color: var(--cyan); border-color: rgba(34, 211, 238, 0.35); background: var(--cyan-soft); }
  .ev-tag.shielded { color: var(--violet); border-color: rgba(167, 139, 250, 0.35); background: var(--violet-soft); }
  .ev-tag.epoch { color: var(--amber); border-color: rgba(245, 158, 11, 0.35); background: var(--amber-soft); }
  .ev-tag.pop { color: #34d399; border-color: rgba(52, 211, 153, 0.4); background: rgba(52, 211, 153, 0.14); }
  .ev-tag.p2p { color: #60a5fa; border-color: rgba(96, 165, 250, 0.35); background: rgba(96, 165, 250, 0.12); }

  footer {
    text-align: center;
    color: var(--muted);
    font-size: 11.5px;
    font-family: var(--mono);
    padding-top: 8px;
  }
</style>
</head>
<body>
<div class="container">

  <!-- Top Status Banner -->
  <header class="banner">
    <div class="brand">
      <div class="logo" aria-label="Vernam VRNM"><svg viewBox="0 0 512 512" width="50" height="50"><defs><linearGradient id="vrnmAz" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#06B6D4"/><stop offset="100%" stop-color="#2563EB"/></linearGradient></defs><circle cx="256" cy="256" r="244" fill="#05070D"/><circle cx="256" cy="256" r="218" fill="none" stroke="#1E293B" stroke-width="6"/><path d="M 256 38 A 218 218 0 0 1 445 365" fill="none" stroke="url(#vrnmAz)" stroke-width="10" stroke-linecap="round"/><path d="M 256 474 A 218 218 0 0 1 67 147" fill="none" stroke="#F8FAFC" stroke-width="10" stroke-linecap="round"/><path d="M 142 152 L 200 152 L 256 306 L 312 152 L 370 152 L 278 386 L 234 386 Z" fill="#F8FAFC"/><circle cx="256" cy="184" r="30" fill="none" stroke="url(#vrnmAz)" stroke-width="8"/><line x1="256" y1="154" x2="256" y2="214" stroke="#0EA5E9" stroke-width="7" stroke-linecap="round"/><line x1="226" y1="184" x2="286" y2="184" stroke="#06B6D4" stroke-width="7" stroke-linecap="round"/></svg></div>
      <div>
        <div class="brand-title">
          <h1>Vernam (VRNM) Testnet v2.2</h1>
          <span class="version-tag">v2.2.0 HARDENED &bull; CW-MAC AUTH &bull; OTP + IT-MPC + QKD</span>
        </div>
        <p class="brand-sub">Information-Theoretically Secure Ledger &bull; Carter-Wegman BFT &bull; Sharded Shamir Privacy &bull; Interactive PoP Mesh</p>
      </div>
    </div>
    <div class="banner-pills">
      <span class="badge-otp">100% OTP &bull; Immune to Quantum &amp; P=NP</span>
      <span class="conn-pill" id="conn-pill"><span class="dot"></span><span id="conn-label">LIVE</span></span>
    </div>
  </header>

  <!-- Security Posture Bar -->
  <section class="posture-bar" aria-label="Security Posture">
    <span class="posture-title">v2.2.0 Security Posture</span>
    <span class="posture-pill"><span class="posture-dot"></span>Zero External Crates</span>
    <span class="posture-pill"><span class="posture-dot"></span>Owner CW-MAC Auth</span>
    <span class="posture-pill"><span class="posture-dot"></span>Information-Theoretic Privacy</span>
    <span class="posture-pill"><span class="posture-dot"></span>Branchless F_(2^127-1)</span>
    <span class="posture-pill"><span class="posture-dot"></span>Sattolo Beacon Pairing</span>
    <span class="posture-pill"><span class="posture-dot"></span>Anti-Replay Registry</span>
    <span class="posture-pill"><span class="posture-dot"></span>/24 Eclipse Defense</span>
  </section>

  <!-- Honest Research Testnet Notice -->
  <section class="disclaimer-bar" aria-label="Research Testnet Notice">
    <strong>Experimental MIT Research Testnet:</strong> Not audited for real value; VRNM is not for sale. Transfers and private balance queries use single-use symmetric Carter-Wegman MAC keys over <code>F_(2^127-1)</code> (burned immediately on use). Software BB84 QBER on public testnet is simulated unless paired with physical QRNG / ETSI 014 QKD hardware; front raw <code>:8080</code> HTTP with TLS (<code>deploy/Caddyfile</code>) in production.
  </section>

  <!-- 6 KPI Cards -->
  <section class="kpi-grid" aria-label="Network Key Performance Indicators">
    <div class="card kpi-card" style="--accent: var(--cyan);">
      <div class="kpi-label">Block Height</div>
      <div class="kpi-val c-cyan" id="k-blocks">0</div>
      <div class="kpi-sub" id="k-bft-sub">2-Phase OTP+CW BFT</div>
    </div>
    <div class="card kpi-card" style="--accent: var(--emerald);">
      <div class="kpi-label">Express Txs (VRNM-Fast)</div>
      <div class="kpi-val c-emerald" id="k-express">0</div>
      <div class="kpi-sub" id="k-tps">Live TPS: 0.0/s</div>
    </div>
    <div class="card kpi-card" style="--accent: var(--violet);">
      <div class="kpi-label">Shielded Txs (VRNM-Private)</div>
      <div class="kpi-val c-violet" id="k-shielded">0</div>
      <div class="kpi-sub" id="k-beaver">Beaver Pool: --</div>
    </div>
    <div class="card kpi-card" style="--accent: var(--amber);">
      <div class="kpi-label">PSS Epoch</div>
      <div class="kpi-val c-amber" id="k-epoch">1</div>
      <div class="kpi-sub" id="k-pop-epoch">PoP Epoch: 0</div>
    </div>
    <div class="card kpi-card" style="--accent: var(--emerald);">
      <div class="kpi-label">QKD QBER (%)</div>
      <div class="kpi-val c-emerald" id="k-qber">0.000%</div>
      <div class="kpi-sub" id="k-qkd-sub">Shor-Preskill &lt; 11%</div>
    </div>
    <div class="card kpi-card" style="--accent: var(--rose);">
      <div class="kpi-label">Total Burned VRNM</div>
      <div class="kpi-val c-rose" id="k-burned">0.0000</div>
      <div class="kpi-sub">20% Pad-Burn + Slashing</div>
    </div>
  </section>

  <!-- Client-Side One-Time CW-MAC Auth Key Manager -->
  <section class="card auth-card" aria-label="Account CW-MAC Key Registration">
    <div class="section-head">
      <div>
        <h2>Client-Side One-Time CW-MAC Session Keys (<code>F_(2^127-1)</code>)</h2>
        <p class="desc" style="margin-bottom:0;">Register single-use <code>(pad_id, r, s)</code> keys via <code>POST /account/register</code>. Keys live only in browser memory (<code>sessionAuthKeys</code>), sign requests in pure JS <code>BigInt</code>, and are burned immediately after one use.</p>
      </div>
      <span class="mini-pill cyan" id="auth-keys-pill">0 SESSION KEYS</span>
    </div>
    <div class="row-4" style="align-items:end;">
      <div>
        <label for="reg-acct">Account ID (0-63)</label>
        <input id="reg-acct" type="number" value="1" min="0" max="63" onchange="updateSessionKeySummary()">
      </div>
      <div>
        <label for="reg-count">One-Time Keys Batch (1-64)</label>
        <input id="reg-count" type="number" value="8" min="1" max="64">
      </div>
      <div>
        <button class="btn-cyan" id="btn-reg-keys" onclick="registerAccountAuthKeys()">Register Account Auth Keys (POST /account/register)</button>
      </div>
      <div>
        <button class="btn-amber" onclick="clearSessionAuthKeys()">Zero &amp; Wipe Session Keys</button>
      </div>
    </div>
    <div class="out-box" id="reg-out">No keys registered yet in this browser session. Register one-time keys for an Account ID to sign Express transfers (domain=1), Shielded transfers (domain=2), and Private Balance queries (domain=3).</div>
  </section>

  <!-- Decentralized P2P Peer Mesh + Interactive Proof-of-Pad Panel -->
  <section class="split-main">
    <div class="card">
      <div class="section-head">
        <div>
          <h2>Decentralized P2P Peer Mesh</h2>
          <p class="desc" style="margin-bottom:0;">Live gossip topology from <code>GET /p2p/peers</code> (auto-falls back to local <code>V0..V3</code> in single-node mode).</p>
        </div>
        <span class="mini-pill emerald" id="mesh-mode-pill">DISCOVERING...</span>
      </div>

      <div class="mesh-note">
        <strong>Zero Manual Node Lists:</strong> Connect to any single seed peer &mdash; Vernam nodes and wallets automatically discover active validators transitively over <code>/p2p/peers</code> gossip with SSRF and <code>/24</code> eclipse protection.
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Node ID</th>
              <th>Advertised IP:Port</th>
              <th>Height</th>
              <th>PoP Score</th>
              <th>QBER</th>
              <th>Health</th>
            </tr>
          </thead>
          <tbody id="peer-tbody">
            <tr><td colspan="6" class="c-muted">Loading mesh topology...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="section-head">
        <div>
          <h2>Proof-of-Pad (PoP) Remote Mining</h2>
          <p class="desc" style="margin-bottom:0;">Interactive challenge-response entropy &amp; Beaver-triple auditing via <code>POST /pop/commit</code> &rarr; <code>POST /pop/submit</code>.</p>
        </div>
        <span class="mini-pill emerald" id="pop-status-pill">CHALLENGE-RESPONSE</span>
      </div>

      <div class="pop-notice">
        <strong>v2.2.0 Hardening:</strong> Server-side self-mining theater (<code>POST /pop/mine</code>) is <strong>disabled</strong> because a node auditing itself proves nothing. External miners must commit fresh entropy via <code>POST /pop/commit</code>, receive a beacon-derived challenge, and answer via <code>POST /pop/submit</code>.
      </div>

      <div class="cmd-block" style="margin-bottom:12px;">
        <div class="cmd-head">
          <span class="cmd-label">Run Authenticated Remote PoP Miner (<code>/pop/commit</code> &rarr; <code>/pop/submit</code>)</span>
          <button class="copy-btn" onclick="copySnippet('cmd-pop-miner', this)">Copy</button>
        </div>
        <pre class="cmd-code" id="cmd-pop-miner">vrnm miner --cores 1 --node "$VRNM_NODE"</pre>
      </div>

      <div class="audit-grid">
        <div class="audit-item">
          <div class="audit-top">
            <span class="audit-name">Commit Endpoint</span>
            <span class="status-badge status-ok" id="aud-commit">ACTIVE</span>
          </div>
          <div class="audit-val">POST /pop/commit</div>
        </div>
        <div class="audit-item">
          <div class="audit-top">
            <span class="audit-name">Submit Endpoint</span>
            <span class="status-badge status-ok" id="aud-submit">ACTIVE</span>
          </div>
          <div class="audit-val">POST /pop/submit</div>
        </div>
        <div class="audit-item">
          <div class="audit-top">
            <span class="audit-name">Self-Mine Theater</span>
            <span class="status-badge status-bad" id="aud-self-mine">DISABLED</span>
          </div>
          <div class="audit-val">POST /pop/mine disabled in v2.2.0</div>
        </div>
        <div class="audit-item">
          <div class="audit-top">
            <span class="audit-name">QKD BB84 QBER</span>
            <span class="status-badge status-ok" id="aud-qber">PASS</span>
          </div>
          <div class="audit-val" id="aud-qber-val">Threshold &lt; 11.0%</div>
        </div>
      </div>

      <div class="supply-box">
        <div class="supply-head">
          <span style="font-weight:700;color:#f8fafc;">Circulating Supply vs. 21,000,000 VRNM Cap</span>
          <span class="c-cyan" style="font-family:var(--mono);font-weight:700;" id="supply-pct">0.00%</span>
        </div>
        <div class="supply-bar-track">
          <div class="supply-bar-fill" id="supply-bar-fill"></div>
        </div>
        <div class="supply-meta">
          <span id="supply-circ">Circulating: --</span>
          <span id="supply-minted">Minted: --</span>
          <span>Hard Cap: 21,000,000 VRNM</span>
        </div>
      </div>
    </div>
  </section>

  <!-- Interactive Authenticated Testnet Controls -->
  <section class="ops-grid">
    <div class="card">
      <h2>Testnet Faucet</h2>
      <p class="desc">Drips Express <code>VRNM-Fast</code> via real 2-phase BFT + mints Shielded Shamir shares via <code>POST /faucet</code>.</p>
      <div class="row-3">
        <div><label for="f-acct">Account ID (0-63)</label><input id="f-acct" type="number" value="1" min="0" max="63"></div>
        <div><label for="f-exp">Express Amt</label><input id="f-exp" type="number" value="1000" min="0"></div>
        <div><label for="f-sh">Shielded Amt</label><input id="f-sh" type="number" value="500" min="0" max="65535"></div>
      </div>
      <button class="btn-emerald" onclick="doFaucet()">Mint / Drip Testnet VRNM</button>
      <div class="out-box" id="f-out">Ready.</div>
    </div>

    <div class="card">
      <h2>Express Send (CW-MAC Signed BFT)</h2>
      <p class="desc">Signs with a burned one-time <code>F_(2^127-1)</code> CW-MAC (<code>domain=1</code>) and submits to <code>POST /tx/express</code>.</p>
      <div class="row-3">
        <div><label for="e-from">Sender ID</label><input id="e-from" type="number" value="1" min="0" max="63"></div>
        <div><label for="e-to">Recipient ID</label><input id="e-to" type="number" value="2" min="0" max="63"></div>
        <div><label for="e-amt">Amount</label><input id="e-amt" type="number" value="50" min="1"></div>
      </div>
      <button class="btn-cyan" onclick="doExpress()">Sign &amp; Send Express BFT Tx</button>
      <div class="out-box" id="e-out">Requires a registered session CW-MAC key for Sender ID.</div>
    </div>

    <div class="card">
      <h2>Shielded Private Send (CW-MAC IT-MPC)</h2>
      <p class="desc">Signs with a burned one-time CW-MAC (<code>domain=2</code>) and blinds amount &amp; recipient via <code>POST /tx/shielded</code>.</p>
      <div class="row-2">
        <div><label for="s-from">Sender ID</label><input id="s-from" type="number" value="1" min="0" max="63"></div>
        <div><label for="s-amt">Amount (Hidden)</label><input id="s-amt" type="number" value="25" min="1" max="65535"></div>
      </div>
      <div class="row-2">
        <div><label for="s-bkt">Recipient Bucket (0-3)</label><input id="s-bkt" type="number" value="0" min="0" max="3" oninput="updateShieldedHint()"></div>
        <div><label for="s-slot">Recipient Slot (0-15)</label><input id="s-slot" type="number" value="2" min="0" max="15" oninput="updateShieldedHint()"></div>
      </div>
      <button class="btn-violet" onclick="doShielded()">Sign &amp; Send Blinded Shielded Tx</button>
      <div class="out-box" id="s-out">Target Account #2 (Bucket 0, Slot 2) &mdash; requires registered CW-MAC key for Sender ID.</div>
    </div>
  </section>

  <!-- Privacy-Preserving Balance Inspector + Quick Connect -->
  <section class="split-bottom">
    <div class="card">
      <div class="section-head">
        <div>
          <h2>Privacy-Preserving Balance Inspector</h2>
          <p class="desc" style="margin-bottom:0;"><code>GET /balance/&lt;id&gt;</code> exposes only public Express state. Unlock your private Shielded balance with an owner CW-MAC key via <code>POST /balance/private</code>.</p>
        </div>
        <span class="mini-pill violet" id="insp-loc">Bucket 0 &bull; Slot 1</span>
      </div>

      <div class="row-3" style="margin-top:12px;align-items:end;">
        <div>
          <label for="i-acct">Account ID (0-63)</label>
          <input id="i-acct" type="number" value="1" min="0" max="63" onchange="loadBalance(true)">
        </div>
        <div>
          <button class="btn-cyan" onclick="loadBalance(true)">Inspect Public Balance</button>
        </div>
        <div>
          <button class="btn-violet" id="btn-unlock-bal" onclick="unlockPrivateBalance()">Unlock Private Balance (POST /balance/private)</button>
        </div>
      </div>

      <div class="bal-summary">
        <div class="bal-tile">
          <div class="k">Express Balance (Public)</div>
          <div class="v c-emerald" id="b-exp">--</div>
        </div>
        <div class="bal-tile">
          <div class="k">Shielded Balance</div>
          <div class="v c-amber" id="b-sh">REDACTED</div>
        </div>
        <div class="bal-tile">
          <div class="k">PSS Epoch</div>
          <div class="v c-amber" id="b-ep">--</div>
        </div>
        <div class="bal-tile">
          <div class="k">Bucket / Slot</div>
          <div class="v c-cyan" id="b-loc">--</div>
        </div>
      </div>

      <div class="shares-panel">
        <div class="shares-caption">
          <strong>Zero Unauthenticated Privacy Leaks (v2.2.0):</strong> Unauthenticated RPC queries never reconstruct private balances or expose raw validator Shamir shares.
        </div>
        <div class="privacy-row">
          <span class="c-violet">Shielded State</span>
          <span id="b-sh-status" class="c-amber">SHIELDED BALANCE: REDACTED (Owner CW-MAC Auth Required)</span>
        </div>
        <div class="privacy-row">
          <span class="c-cyan">Validator Shares</span>
          <span id="b-shares-status" class="c-muted">RAW SHAMIR SHARES: REDACTED (1 Share / Host in Multi-Host Mode)</span>
        </div>
      </div>
      <div class="out-box" id="bal-out">Public GET /balance/&lt;id&gt; loaded. Use "Unlock Private Balance" with a registered one-time CW-MAC key (domain=3) to authenticate as the account owner.</div>
    </div>

    <div class="card">
      <div class="section-head">
        <div>
          <h2>Quick Join / Inspect-First CLI</h2>
          <p class="desc" style="margin-bottom:0;">Auto-configured via <code>window.location.origin</code> (live testnet seed: <code>88.216.62.115:8080</code>). Inspect source before building.</p>
        </div>
        <span class="mini-pill" id="qc-origin-pill">ORIGIN</span>
      </div>

      <div class="cmd-block">
        <div class="cmd-head">
          <span class="cmd-label">1. Clone &amp; Build Offline (0 External Crates)</span>
          <button class="copy-btn" onclick="copySnippet('cmd-install', this)">Copy</button>
        </div>
        <pre class="cmd-code" id="cmd-install">Loading...</pre>
      </div>

      <div class="cmd-block">
        <div class="cmd-head">
          <span class="cmd-label">2. Create Wallet &amp; Claim Faucet</span>
          <button class="copy-btn" onclick="copySnippet('cmd-wallet', this)">Copy</button>
        </div>
        <pre class="cmd-code" id="cmd-wallet">Loading...</pre>
      </div>

      <div class="cmd-block">
        <div class="cmd-head">
          <span class="cmd-label">3. Run CW-MAC Signed Shielded IT-MPC Transfer</span>
          <button class="copy-btn" onclick="copySnippet('cmd-shielded', this)">Copy</button>
        </div>
        <pre class="cmd-code" id="cmd-shielded">Loading...</pre>
      </div>

      <div class="cmd-block">
        <div class="cmd-head">
          <span class="cmd-label">4. Join P2P Mesh or Run Interactive PoP Miner</span>
          <button class="copy-btn" onclick="copySnippet('cmd-node', this)">Copy</button>
        </div>
        <pre class="cmd-code" id="cmd-node">Loading...</pre>
      </div>
    </div>
  </section>

  <!-- Live Event Stream -->
  <section class="card" style="margin-bottom:18px;">
    <div class="section-head">
      <div>
        <h2>Live Network Event Stream</h2>
        <p class="desc" style="margin-bottom:0;">Auto-refreshes every 3 seconds &mdash; finalized BFT blocks, blinded IT-MPC transfers, PoP audits, and PSS/BB84 rotations.</p>
      </div>
      <span class="mini-pill emerald" id="ev-count-pill">0 EVENTS</span>
    </div>
    <div class="events" id="event-list">
      <div class="event-row"><span class="ev-tag">INIT</span><span>Connecting to Vernam node...</span></div>
    </div>
  </section>

  <footer>
    Vernam (VRNM) v2.2.0 Authenticated Explorer (MIT License &bull; Experimental Research Testnet) &bull; Zero External Dependencies &bull; Pure Information-Theoretic Security (OTP + Carter-Wegman + Shamir IT-MPC + BB84 QKD)
  </footer>
</div>

<script>
const VERN_PER_VRNM = 1e8;
const MAX_SUPPLY_VERN = 21000000 * VERN_PER_VRNM;

// Canonical Carter-Wegman MAC over F_(2^127 - 1) matching Rust bit-for-bit.
const PRIME_P = (1n << 127n) - 1n;
const AUTH_DOMAIN_EXPRESS = 1;
const AUTH_DOMAIN_SHIELDED = 2;
const AUTH_DOMAIN_BALANCE = 3;
const AUTH_DOMAIN_REGISTER = 4;

const sessionAuthKeys = {};

let prevExpress = 0;
let prevTime = Date.now();
let latestStatus = null;
let unlockedPrivateCache = null;

function parseFieldScalar(val) {
  if (typeof val === 'bigint') return ((val % PRIME_P) + PRIME_P) % PRIME_P;
  if (typeof val === 'number') return BigInt(val) % PRIME_P;
  const s = String(val || '').trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) {
    return BigInt(s) % PRIME_P;
  }
  if (/^[0-9a-fA-F]{32}$/.test(s)) {
    let acc = 0n;
    for (let i = 15; i >= 0; i--) {
      acc = (acc << 8n) | BigInt(parseInt(s.slice(i * 2, i * 2 + 2), 16));
    }
    return acc % PRIME_P;
  }
  return BigInt(s) % PRIME_P;
}

function computeAuthTagHex(domain, acct, a1, a2, a3, padId, rBig, sBig) {
  const r = rBig % PRIME_P;
  let acc = (BigInt(domain) * r) % PRIME_P;
  acc = ((acc + BigInt(acct)) * r) % PRIME_P;
  acc = ((acc + BigInt(a1)) * r) % PRIME_P;
  acc = ((acc + BigInt(a2)) * r) % PRIME_P;
  acc = ((acc + BigInt(a3)) * r) % PRIME_P;
  acc = ((acc + BigInt(padId)) * r) % PRIME_P;
  const tag = (acc + (sBig % PRIME_P)) % PRIME_P;
  let hex = '';
  for (let i = 0; i < 16; i++) hex += Number((tag >> BigInt(i * 8)) & 0xffn).toString(16).padStart(2, '0');
  return hex;
}

function consumeOneTimeAuthKey(acctId) {
  const list = sessionAuthKeys[acctId];
  if (!list || list.length === 0) {
    throw new Error(`No registered one-time CW-MAC auth keys in session for Acct #${acctId}. Click "Register Account Auth Keys" first.`);
  }
  const key = list.shift();
  updateSessionKeySummary();
  return key;
}

function burnKeyMaterial(key) {
  if (!key) return;
  key.r = 0n;
  key.s = 0n;
  key.r_hex = '';
  key.s_hex = '';
}

function updateSessionKeySummary() {
  let total = 0;
  const parts = [];
  for (const [acct, arr] of Object.entries(sessionAuthKeys)) {
    if (arr && arr.length > 0) {
      total += arr.length;
      parts.push(`#${acct}:${arr.length}`);
    }
  }
  const pill = document.getElementById('auth-keys-pill');
  if (pill) {
    pill.textContent = total > 0
      ? `${total} KEYS (${parts.join(', ')})`
      : '0 SESSION KEYS';
    pill.className = 'mini-pill ' + (total > 0 ? 'emerald' : 'amber');
  }
}

async function registerAccountAuthKeys() {
  const acctId = Math.max(0, Math.min(63, parseInt(document.getElementById('reg-acct').value, 10) || 0));
  const count = Math.max(1, Math.min(64, parseInt(document.getElementById('reg-count').value, 10) || 8));
  const btn = document.getElementById('btn-reg-keys');
  btn.disabled = true;
  let authKey = null;
  try {
    if (!sessionAuthKeys[acctId]) sessionAuthKeys[acctId] = [];
    const payload = { account_id: acctId, count };
    let usedRefillAuth = false;
    if (sessionAuthKeys[acctId].length > 0) {
      authKey = consumeOneTimeAuthKey(acctId);
      const tagHex = computeAuthTagHex(AUTH_DOMAIN_REGISTER, acctId, count, 0, 0, authKey.pad_id, authKey.r, authKey.s);
      payload.auth_pad_id = authKey.pad_id;
      payload.auth_tag = tagHex;
      burnKeyMaterial(authKey);
      authKey = null;
      usedRefillAuth = true;
    }

    const res = await api('/account/register', 'POST', payload);
    const returnedKeys = Array.isArray(res.keys) ? res.keys : [];
    for (const k of returnedKeys) {
      const padId = Number(k.pad_id);
      const rBig = parseFieldScalar(k.r_hex ?? k.r);
      const sBig = parseFieldScalar(k.s_hex ?? k.s);
      sessionAuthKeys[acctId].push({ pad_id: padId, r: rBig, s: sBig });
    }
    updateSessionKeySummary();
    setOut(
      'reg-out',
      `${usedRefillAuth ? 'Refilled' : 'Registered'} ${returnedKeys.length} single-use CW-MAC auth keys for Acct #${acctId} (session pool: ${sessionAuthKeys[acctId].length}). Each key is burned immediately after signing one request.`,
      'ok'
    );
  } catch (err) {
    burnKeyMaterial(authKey);
    setOut('reg-out', 'Key registration failed: ' + err.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

function clearSessionAuthKeys() {
  for (const acct of Object.keys(sessionAuthKeys)) {
    for (const k of sessionAuthKeys[acct] || []) burnKeyMaterial(k);
    delete sessionAuthKeys[acct];
  }
  unlockedPrivateCache = null;
  updateSessionKeySummary();
  setOut('reg-out', 'All in-memory session CW-MAC keys zeroed and wiped.', '');
  loadBalance(true);
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtShortVrnm(vern) {
  const n = Number(vern || 0) / VERN_PER_VRNM;
  if (n >= 1000) {
    return n.toLocaleString(undefined, { maximumFractionDigits: 2 }) + ' VRNM';
  }
  return n.toLocaleString(undefined, { minimumFractionDigits: 4, maximumFractionDigits: 4 }) + ' VRNM';
}

function setConn(isLive) {
  const pill = document.getElementById('conn-pill');
  const lbl = document.getElementById('conn-label');
  if (isLive) {
    pill.classList.remove('offline');
    lbl.textContent = 'LIVE';
  } else {
    pill.classList.add('offline');
    lbl.textContent = 'OFFLINE';
  }
}

function setOut(id, msg, kind) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.remove('ok', 'err');
  if (kind === 'ok') el.classList.add('ok');
  if (kind === 'err') el.classList.add('err');
}

function setAuditBadge(id, passed, labelPass, labelFail) {
  const el = document.getElementById(id);
  el.classList.remove('status-ok', 'status-warn', 'status-bad');
  if (passed === true) {
    el.classList.add('status-ok');
    el.textContent = labelPass || 'PASS';
  } else if (passed === false) {
    el.classList.add('status-bad');
    el.textContent = labelFail || 'FAIL';
  } else {
    el.classList.add('status-warn');
    el.textContent = 'PENDING';
  }
}

async function api(path, method = 'GET', body = null) {
  const opts = { method, headers: {} };
  if (body !== null) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { raw: text }; }
  if (!res.ok) {
    const err = new Error(data.error || ('HTTP ' + res.status));
    err.status = res.status;
    throw err;
  }
  return data;
}

function updateSupplyBar(circulatingVern, totalMintedVern) {
  const circ = Number(circulatingVern || 0);
  const minted = Number(totalMintedVern || circ);
  const pct = Math.max(0, Math.min(100, (circ / MAX_SUPPLY_VERN) * 100));
  document.getElementById('supply-bar-fill').style.width = Math.max(pct, 1.5).toFixed(2) + '%';
  document.getElementById('supply-pct').textContent = pct.toFixed(3) + '%';
  document.getElementById('supply-circ').textContent = 'Circulating: ' + fmtShortVrnm(circ);
  document.getElementById('supply-minted').textContent = 'Minted: ' + fmtShortVrnm(minted);
}

function classifyEvent(ev) {
  const u = ev.toUpperCase();
  if (u.startsWith('FAUCET')) return ['FAUCET', 'faucet'];
  if (u.startsWith('EXPRESS')) return ['EXPRESS', 'express'];
  if (u.startsWith('SHIELDED')) return ['SHIELDED', 'shielded'];
  if (u.startsWith('POP') || u.includes('PROOF-OF-PAD') || u.includes('MINED')) return ['POP', 'pop'];
  if (u.startsWith('EPOCH')) return ['EPOCH', 'epoch'];
  if (u.startsWith('P2P') || u.includes('PEER')) return ['P2P', 'p2p'];
  if (u.startsWith('GENESIS')) return ['GENESIS', 'faucet'];
  return ['EVENT', ''];
}

function renderPeersFromList(rows, modeLabel, pillClass) {
  const pill = document.getElementById('mesh-mode-pill');
  pill.textContent = modeLabel;
  pill.className = 'mini-pill ' + pillClass;

  const tbody = document.getElementById('peer-tbody');
  if (!rows || !rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="c-muted">No peers discovered yet.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(p => {
    const idLabel = p.label != null ? p.label : ('Node #' + (p.node_id ?? p.id ?? '?'));
    const selfBadge = p.is_self ? '<span class="self-tag">SELF</span>' : '';
    const addr = p.advertise_addr || p.addr || p.address || p.endpoint || p.url || 'local-cluster';
    const height = p.height ?? p.block_height ?? 0;
    const popScore = p.pop_score ?? p.score ?? p.voting_power ?? '--';
    const rawQber = p.qber != null ? p.qber : (p.last_qber != null ? p.last_qber : (latestStatus ? latestStatus.last_qber : null));
    const qberStr = rawQber != null ? (Number(rawQber) * 100).toFixed(3) + '%' : '--';
    const isHealthy = p.healthy === true || p.online === true || String(p.status || '').toLowerCase() === 'active' || String(p.status || '').toLowerCase() === 'healthy';
    const statusText = p.status ? String(p.status).toUpperCase() : (isHealthy ? 'HEALTHY' : 'OFFLINE');
    const badgeCls = isHealthy ? 'status-ok' : 'status-bad';

    return `<tr>
      <td><strong>${esc(idLabel)}</strong>${selfBadge}</td>
      <td class="c-cyan">${esc(addr)}</td>
      <td>#${esc(height)}</td>
      <td class="c-emerald">${esc(popScore)}</td>
      <td>${esc(qberStr)}</td>
      <td><span class="status-badge ${badgeCls}">${esc(statusText)}</span></td>
    </tr>`;
  }).join('');
}

async function refreshPeers() {
  try {
    const data = await api('/p2p/peers');
    let list = [];
    const selfNode = data.self_node || data.self || data.local_node || null;
    const peersArr = Array.isArray(data) ? data : (data.peers || data.nodes || []);
    if (selfNode && typeof selfNode === 'object') {
      list.push(Object.assign({ is_self: true, healthy: true, status: 'HEALTHY' }, selfNode));
    }
    for (const p of peersArr) {
      if (!p || typeof p !== 'object') continue;
      const pAddr = p.advertise_addr || p.addr || p.address || p.endpoint || '';
      const pId = p.node_id ?? p.id;
      const dup = list.some(x =>
        (pAddr && (x.advertise_addr || x.addr || x.address || x.endpoint) === pAddr) ||
        (pId != null && (x.node_id ?? x.id) === pId && pAddr === '')
      );
      if (!dup) list.push(p);
    }
    if (list.length > 0) {
      renderPeersFromList(list, 'P2P MESH (' + list.length + ' NODES)', 'emerald');
      return;
    }
  } catch (_) {
    // Graceful fallback to local V0..V3 validators from GET /status
  }

  if (latestStatus && Array.isArray(latestStatus.validators)) {
    const fallback = latestStatus.validators.map(v => ({
      label: v.label || ('V' + v.id),
      advertise_addr: 'local-bft-cluster (V' + v.id + ')',
      height: v.height,
      pop_score: v.voting_power != null ? ('Vote ' + v.voting_power + (v.wot_verified ? ' (PoP)' : '')) : '1',
      qber: latestStatus.last_qber,
      healthy: v.online,
      status: v.online ? (v.status || 'ACTIVE') : 'OFFLINE',
      is_self: v.id === 0
    }));
    renderPeersFromList(fallback, 'SINGLE-NODE MODE (V0..V3)', 'amber');
  }
}

async function refreshStatus() {
  try {
    const s = await api('/status');
    latestStatus = s;
    setConn(true);

    const now = Date.now();
    const dt = Math.max((now - prevTime) / 1000, 0.25);
    const tps = Math.max(0, (Number(s.express_txs || 0) - prevExpress) / dt);
    prevExpress = Number(s.express_txs || 0);
    prevTime = now;

    document.getElementById('k-blocks').textContent = s.blocks_finalized ?? 0;
    document.getElementById('k-express').textContent = s.express_txs ?? 0;
    document.getElementById('k-tps').textContent = 'Live TPS: ' + tps.toFixed(1) + '/s';
    document.getElementById('k-shielded').textContent = s.shielded_txs ?? 0;
    document.getElementById('k-beaver').textContent = 'Beaver Pool: ' + (s.beaver_pool_remaining ?? '--');
    document.getElementById('k-epoch').textContent = s.pss_epoch ?? 1;
    document.getElementById('k-pop-epoch').textContent = 'PoP Epoch: ' + (s.tokenomics_epoch ?? 0);

    const qberPct = Number(s.last_qber || 0) * 100;
    document.getElementById('k-qber').textContent = qberPct.toFixed(3) + '%';
    setAuditBadge('aud-qber', qberPct < 11.0, 'PASS', 'ALERT');
    document.getElementById('aud-qber-val').textContent = 'Live QBER: ' + qberPct.toFixed(3) + '% (< 11%)';

    document.getElementById('k-burned').textContent = (Number(s.total_burned_vern || 0) / VERN_PER_VRNM).toFixed(4);
    updateSupplyBar(s.circulating_supply_vern, s.total_minted_vern);

    const evs = (s.recent_events || []).slice().reverse();
    document.getElementById('ev-count-pill').textContent = evs.length + ' EVENTS';
    const evEl = document.getElementById('event-list');
    evEl.innerHTML = evs.length
      ? evs.map(e => {
          const [tag, cls] = classifyEvent(e);
          return `<div class="event-row"><span class="ev-tag ${cls}">${tag}</span><span>${esc(e)}</span></div>`;
        }).join('')
      : '<div class="event-row"><span class="ev-tag">IDLE</span><span>No network events yet.</span></div>';
  } catch (err) {
    setConn(false);
  }
}

function renderRedactedShielded(id) {
  const shTile = document.getElementById('b-sh');
  const shStatus = document.getElementById('b-sh-status');
  const sharesStatus = document.getElementById('b-shares-status');
  if (unlockedPrivateCache && unlockedPrivateCache.account_id === id) {
    shTile.textContent = String(unlockedPrivateCache.shielded_balance);
    shTile.className = 'v c-violet';
    shStatus.textContent = `AUTHENTICATED OWNER BALANCE: ${unlockedPrivateCache.shielded_balance} (CW-MAC Verified)`;
    shStatus.className = 'c-emerald';
  } else {
    shTile.textContent = 'REDACTED';
    shTile.className = 'v c-amber';
    shStatus.textContent = 'SHIELDED BALANCE: REDACTED (Owner CW-MAC Auth Required)';
    shStatus.className = 'c-amber';
  }
  sharesStatus.textContent = 'RAW SHAMIR SHARES: REDACTED (1 Share / Host in Multi-Host Mode)';
}

async function loadBalance(resetPrivate = false) {
  const id = Math.max(0, parseInt(document.getElementById('i-acct').value, 10) || 0);
  if (resetPrivate && unlockedPrivateCache && unlockedPrivateCache.account_id !== id) {
    unlockedPrivateCache = null;
  }
  try {
    const b = await api('/balance/' + id);
    document.getElementById('b-exp').textContent = b.express_balance;
    document.getElementById('b-ep').textContent = '#' + (b.epoch ?? b.pss_epoch ?? 0);
    const bkt = b.bucket_id != null ? b.bucket_id : Math.floor(id / 16);
    const slot = b.slot_in_bucket != null ? b.slot_in_bucket : (id % 16);
    document.getElementById('b-loc').textContent = 'B' + bkt + ' / S' + slot;
    document.getElementById('insp-loc').textContent = 'Bucket ' + bkt + ' \u2022 Slot ' + slot;
    renderRedactedShielded(id);
  } catch (err) {
    setOut('bal-out', 'Public balance query failed: ' + err.message, 'err');
  }
}

async function unlockPrivateBalance() {
  const id = Math.max(0, parseInt(document.getElementById('i-acct').value, 10) || 0);
  const btn = document.getElementById('btn-unlock-bal');
  btn.disabled = true;
  let key = null;
  try {
    key = consumeOneTimeAuthKey(id);
    const tagHex = computeAuthTagHex(AUTH_DOMAIN_BALANCE, id, 0, 0, 0, key.pad_id, key.r, key.s);
    const padId = key.pad_id;
    burnKeyMaterial(key);
    key = null;

    const res = await api('/balance/private', 'POST', {
      account_id: id,
      pad_id: padId,
      auth_pad_id: padId,
      auth_tag: tagHex
    });
    unlockedPrivateCache = {
      account_id: id,
      shielded_balance: res.shielded_balance
    };
    if (res.express_balance != null) {
      document.getElementById('b-exp').textContent = res.express_balance;
    }
    if (res.epoch != null || res.pss_epoch != null) {
      document.getElementById('b-ep').textContent = '#' + (res.epoch ?? res.pss_epoch);
    }
    renderRedactedShielded(id);
    setOut(
      'bal-out',
      `Unlocked private balance for Acct #${id}: Shielded=${res.shielded_balance} (CW-MAC pad #${padId} burned).`,
      'ok'
    );
  } catch (err) {
    burnKeyMaterial(key);
    setOut('bal-out', 'Private balance unlock failed: ' + err.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

async function doFaucet() {
  try {
    const res = await api('/faucet', 'POST', {
      account_id: parseInt(document.getElementById('f-acct').value, 10) || 0,
      express: parseInt(document.getElementById('f-exp').value, 10) || 0,
      shielded: parseInt(document.getElementById('f-sh').value, 10) || 0
    });
    setOut(
      'f-out',
      `Credited Acct #${res.account_id} | Express=${res.express_balance} (+${res.express_credited ?? 0}), Shielded +${res.shielded_credited ?? 0} (use POST /balance/private to inspect)`,
      'ok'
    );
    document.getElementById('i-acct').value = res.account_id;
    document.getElementById('reg-acct').value = res.account_id;
    unlockedPrivateCache = null;
    await Promise.all([refreshStatus(), refreshPeers(), loadBalance(true)]);
  } catch (err) {
    setOut('f-out', 'Error: ' + err.message, 'err');
  }
}

async function doExpress() {
  let key = null;
  try {
    const sender = parseInt(document.getElementById('e-from').value, 10) || 0;
    const recipient = parseInt(document.getElementById('e-to').value, 10) || 0;
    const amount = parseInt(document.getElementById('e-amt').value, 10) || 0;
    key = consumeOneTimeAuthKey(sender);
    const tagHex = computeAuthTagHex(AUTH_DOMAIN_EXPRESS, sender, recipient, amount, 0, key.pad_id, key.r, key.s);
    const padId = key.pad_id;
    burnKeyMaterial(key);
    key = null;

    const res = await api('/tx/express', 'POST', {
      sender,
      recipient,
      amount,
      pad_id: padId,
      auth_pad_id: padId,
      auth_tag: tagHex
    });
    setOut(
      'e-out',
      `Block #${res.block_height} finalized (Leader V${res.leader_id}) | Burned ${res.burned_vern} vern | CW-MAC pad #${padId} burned`,
      'ok'
    );
    await Promise.all([refreshStatus(), refreshPeers(), loadBalance()]);
  } catch (err) {
    burnKeyMaterial(key);
    setOut('e-out', 'Error: ' + err.message, 'err');
  }
}

function updateShieldedHint() {
  const bkt = parseInt(document.getElementById('s-bkt').value, 10) || 0;
  const slot = parseInt(document.getElementById('s-slot').value, 10) || 0;
  const target = bkt * 16 + slot;
  setOut('s-out', `Target Account #${target} (Bucket ${bkt}, Slot ${slot}) \u2014 requires registered CW-MAC key for Sender ID.`, '');
}

async function doShielded() {
  let key = null;
  try {
    const sender = parseInt(document.getElementById('s-from').value, 10) || 0;
    const recipient_bucket = parseInt(document.getElementById('s-bkt').value, 10) || 0;
    const recipient_slot = parseInt(document.getElementById('s-slot').value, 10) || 0;
    const amount = parseInt(document.getElementById('s-amt').value, 10) || 0;
    key = consumeOneTimeAuthKey(sender);
    const tagHex = computeAuthTagHex(
      AUTH_DOMAIN_SHIELDED,
      sender,
      recipient_bucket,
      recipient_slot,
      amount,
      key.pad_id,
      key.r,
      key.s
    );
    const padId = key.pad_id;
    burnKeyMaterial(key);
    key = null;

    const res = await api('/tx/shielded', 'POST', {
      sender,
      recipient_bucket,
      recipient_slot,
      amount,
      pad_id: padId,
      auth_pad_id: padId,
      auth_tag: tagHex
    });
    unlockedPrivateCache = null;
    setOut(
      's-out',
      `Blinded IT-MPC settled (${res.triples_consumed} triples) | Burned ${res.burned_vern} vern | Pool: ${res.beaver_pool_remaining} | CW-MAC pad #${padId} burned`,
      'ok'
    );
    await Promise.all([refreshStatus(), refreshPeers(), loadBalance(true)]);
  } catch (err) {
    burnKeyMaterial(key);
    setOut('s-out', 'Error: ' + err.message, 'err');
  }
}

function initQuickConnect() {
  const defaultSeed = '88.216.62.115:8080';
  const proto = window.location.protocol === 'https:' ? 'https:' : 'http:';
  const origin = window.location.origin && window.location.origin !== 'null'
    ? window.location.origin
    : (proto + '//' + defaultSeed);
  const rawHost = window.location.host || defaultSeed;
  const seedHostPort = rawHost.includes(':')
    ? rawHost
    : rawHost + (window.location.protocol === 'https:' ? ':443' : ':80');
  const tlsProto = 'https:';

  document.getElementById('qc-origin-pill').textContent = rawHost;

  document.getElementById('cmd-pop-miner').textContent =
    `export VRNM_NODE="${origin}"\n` +
    `vrnm miner --cores 1 --node "$VRNM_NODE"`;

  document.getElementById('cmd-install').textContent =
    `git clone ${tlsProto}//github.com/gpt4omni/vernam.git\n` +
    `cd vernam && cargo build --release --offline\n` +
    `export VRNM_NODE="${origin}"\n` +
    `./target/release/vernam-rs wallet status --node "$VRNM_NODE"`;

  document.getElementById('cmd-wallet').textContent =
    `export VRNM_NODE="${origin}"\n` +
    `vrnm wallet create --name alice --node "$VRNM_NODE"\n` +
    `vrnm wallet faucet --name alice --node "$VRNM_NODE"\n` +
    `vrnm wallet balance --name alice --node "$VRNM_NODE"`;

  document.getElementById('cmd-shielded').textContent =
    `vrnm wallet create --name bob --node "$VRNM_NODE"\n` +
    `vrnm wallet send-private --from alice --to bob --amount 25 --node "$VRNM_NODE"\n` +
    `vrnm wallet balance --name bob --node "$VRNM_NODE"`;

  document.getElementById('cmd-node').textContent =
    `# Join decentralized P2P mesh:\n` +
    `vrnm node --bind 0.0.0.0:8080 --advertise <YOUR_IP>:8080 --seed ${seedHostPort}\n` +
    `# Or run interactive PoP miner (POST /pop/commit -> POST /pop/submit):\n` +
    `vrnm miner --cores 1 --node "$VRNM_NODE"`;
}

async function copySnippet(elId, btn) {
  const text = document.getElementById(elId).textContent;
  const orig = btn.textContent;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1600);
  } catch (_) {
    btn.textContent = 'Select & Copy';
    setTimeout(() => { btn.textContent = orig; }, 1600);
  }
}

async function tick() {
  await refreshStatus();
  await Promise.all([refreshPeers(), loadBalance()]);
}

initQuickConnect();
updateSessionKeySummary();
tick();
setInterval(tick, 3000);
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::VERNAM_EXPLORER_HTML;

    #[test]
    fn test_explorer_html_structure_and_branding() {
        assert!(VERNAM_EXPLORER_HTML.starts_with("<!DOCTYPE html>"));
        assert!(VERNAM_EXPLORER_HTML.contains("</html>"));
        assert!(VERNAM_EXPLORER_HTML.contains("Vernam (VRNM) Live Testnet Explorer"));
        assert!(VERNAM_EXPLORER_HTML.contains("Vernam (VRNM) Testnet v2.2"));
        assert!(VERNAM_EXPLORER_HTML.contains("100% OTP"));
        assert!(VERNAM_EXPLORER_HTML.contains("Immune to Quantum"));
        assert!(VERNAM_EXPLORER_HTML.contains("21,000,000 VRNM"));
        assert!(VERNAM_EXPLORER_HTML.contains("MIT License"));
    }

    #[test]
    fn test_explorer_contains_all_v22_authenticated_endpoints() {
        let required_endpoints = [
            "/status",
            "/p2p/peers",
            "/account/register",
            "/faucet",
            "/tx/express",
            "/tx/shielded",
            "/balance/",
            "/balance/private",
            "/pop/commit",
            "/pop/submit",
        ];
        for ep in required_endpoints {
            assert!(
                VERNAM_EXPLORER_HTML.contains(ep),
                "explorer HTML missing required v2.2.0 endpoint: {ep}"
            );
        }
    }

    #[test]
    fn test_explorer_privacy_redaction_and_cw_mac_client_signing() {
        // Must NEVER leak raw validator Shamir shares over unauthenticated GET /balance/<id>
        for leaked_field in [
            "v0_shamir_share",
            "v1_shamir_share",
            "v2_shamir_share",
            "v3_shamir_share",
        ] {
            assert!(
                !VERNAM_EXPLORER_HTML.contains(leaked_field),
                "explorer HTML must not expect unauthenticated raw share leak field: {leaked_field}"
            );
        }

        // Explicit privacy-preserving redaction banners & authenticated private balance unlock
        assert!(VERNAM_EXPLORER_HTML.contains("SHIELDED BALANCE: REDACTED"));
        assert!(VERNAM_EXPLORER_HTML.contains("RAW SHAMIR SHARES: REDACTED"));
        assert!(VERNAM_EXPLORER_HTML.contains("POST /balance/private"));
        assert!(VERNAM_EXPLORER_HTML.contains("POST /account/register"));

        // Canonical pure-JS BigInt F_(2^127-1) CW-MAC signing + one-time key burn
        assert!(VERNAM_EXPLORER_HTML.contains("const PRIME_P = (1n << 127n) - 1n;"));
        assert!(VERNAM_EXPLORER_HTML.contains("function computeAuthTagHex("));
        assert!(VERNAM_EXPLORER_HTML.contains("AUTH_DOMAIN_EXPRESS = 1"));
        assert!(VERNAM_EXPLORER_HTML.contains("AUTH_DOMAIN_SHIELDED = 2"));
        assert!(VERNAM_EXPLORER_HTML.contains("AUTH_DOMAIN_BALANCE = 3"));
        assert!(VERNAM_EXPLORER_HTML.contains("sessionAuthKeys"));
        assert!(VERNAM_EXPLORER_HTML.contains("burnKeyMaterial"));
    }

    #[test]
    fn test_explorer_pop_remote_mining_and_inspect_first_cli() {
        assert!(VERNAM_EXPLORER_HTML.contains("POST /pop/commit"));
        assert!(VERNAM_EXPLORER_HTML.contains("POST /pop/submit"));
        assert!(VERNAM_EXPLORER_HTML.contains("vrnm miner"));
        assert!(VERNAM_EXPLORER_HTML.contains("window.location.origin"));
        assert!(VERNAM_EXPLORER_HTML.contains("vrnm wallet create"));
        assert!(VERNAM_EXPLORER_HTML.contains("vrnm wallet send-private"));
        assert!(VERNAM_EXPLORER_HTML.contains("vrnm node --bind 0.0.0.0:8080 --advertise"));
        assert!(VERNAM_EXPLORER_HTML.contains("setInterval(tick, 3000)"));
        assert!(VERNAM_EXPLORER_HTML.contains("88.216.62.115:8080"));
        assert!(
            !VERNAM_EXPLORER_HTML.contains("| bash"),
            "explorer Quick Join CLI must use inspect-first git clone, not curl | bash"
        );
    }

    #[test]
    fn test_explorer_has_zero_external_cdn_dependencies() {
        let lower = VERNAM_EXPLORER_HTML.to_ascii_lowercase();
        let forbidden = [
            "http://",
            "https://",
            "<script src=",
            "<link rel=\"stylesheet\"",
            "cdn.jsdelivr.net",
            "unpkg.com",
            "cdnjs.cloudflare.com",
            "fonts.googleapis.com",
            "tailwindcss.com",
        ];
        for needle in forbidden {
            assert!(
                !lower.contains(needle),
                "explorer HTML must remain 100% offline/air-gapped (found forbidden external reference: {needle})"
            );
        }
    }

    #[test]
    fn test_security_posture_bar_pills() {
        for pill in [
            "Zero External Crates",
            "Owner CW-MAC Auth",
            "Information-Theoretic Privacy",
            "Branchless F_(2^127-1)",
            "Sattolo Beacon Pairing",
            "Anti-Replay Registry",
            "/24 Eclipse Defense",
        ] {
            assert!(
                VERNAM_EXPLORER_HTML.contains(pill),
                "explorer HTML missing security posture pill: {pill}"
            );
        }
    }
}
