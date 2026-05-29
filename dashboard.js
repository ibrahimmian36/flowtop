/* Dashboard composition for flowtop. Same layout idioms as xtop /
 * blktop / airtop — top rule, content strips, zip()'d split row — but
 * the panels are tuned for TCP connection state.
 *
 * The signature visual is the "state weather" heatmap: each row is a
 * TCP state, each column is a render tick, and the cell color is the
 * log-normalized number of *transitions into* that state during that
 * tick. New SYN_SENTs make the SYN_SENT row light up; close storms
 * paint the CLOSE row red; a steady ESTABLISHED hum says the server's
 * doing fine. Below it sits a stacked-segment bar showing the standing
 * army — how the currently-active connections divide across states. */

import {
  fg, bg, bold, dim, ital, RESET, EOL,
  HEAT, SILENT_BG, EIGHTH,
  C_AXIS, C_DIM, C_ALERT,
  STATE_INFO, stateOf, HEATMAP_STATES, ACTIVE_STATES,
  TCP_ESTABLISHED, TCP_SYN_SENT, TCP_LISTEN, TCP_TIME_WAIT, TCP_CLOSE,
  heatCell, stackedBar, sparkline,
  fmtAddr, fmtEndpoint, fmtAge, mmss, compactNum,
  vlen, clipAnsi, fixw, padVis,
} from "./render.js";

import {
  tot, transHist, retransHist, activeHist,
  liveRates, activeStateDist,
  topProcs, topEndpoints, recentEvents,
  currentConns,
  aName, aAddr, startTime,
  TICK_MS, WINDOW_MS,
} from "./state.js";

const MIN_COLS = 80;
const MIN_ROWS = 28;

/* ---- layout helpers (mirror xtop/blktop) --------------------------- */
function topRule(C, title) {
  const head = ` ▌ ${title} `;
  return bold + fg(51) + head + RESET + fg(C_AXIS) +
    "─".repeat(Math.max(0, C - head.length)) + RESET + EOL;
}
function botRule(C) { return fg(C_AXIS) + "─".repeat(C) + RESET + EOL; }
function sectionBar(C, text) {
  return `${fg(45)}  ${text} ${fg(C_AXIS)}${"─".repeat(Math.max(0, C - vlen(text) - 3))}${RESET}${EOL}`;
}
function sectionTitle(lw, left, right) {
  return `${fg(45)}${left}${" ".repeat(Math.max(1, lw - left.length))}${fg(C_AXIS)}│ ` +
    `${fg(45)}${right}${RESET}${EOL}`;
}
function zip(L, R, lw, rw, rows) {
  const h = Math.max(L.length, R.length);
  const bl = " ".repeat(lw), br = " ".repeat(rw);
  for (let i = 0; i < h; i++)
    rows.push(`${L[i] ?? bl}${fg(C_AXIS)}│${RESET} ${R[i] ?? br}${EOL}`);
}

/* ---- panel: header status line ------------------------------------- */
function headerLine(C) {
  const r = liveRates();
  const live = bold + fg(46) + "●" + RESET + fg(252) + " LIVE " + RESET;
  const up = fg(C_DIM) + mmss(Date.now() - startTime) + RESET;
  const active = fg(252) + compactNum(r.activeNow) + RESET + fg(C_DIM) + " active" + RESET;
  const out = fg(STATE_INFO[TCP_SYN_SENT].color) + "→ " + RESET +
              fg(252) + compactNum(tot.connectsOut) + RESET +
              fg(C_DIM) + " out" + RESET;
  const acc = fg(STATE_INFO[TCP_LISTEN].color) + "← " + RESET +
              fg(252) + compactNum(tot.acceptsIn) + RESET +
              fg(C_DIM) + " in" + RESET;
  const cl = fg(C_DIM) + "✕ " + compactNum(tot.closes) + " closed" + RESET;
  const rst = tot.resets > 0
    ? fg(C_ALERT) + "⚡ " + compactNum(tot.resets) + " reset" + RESET
    : fg(C_DIM) + "0 reset" + RESET;
  const rtx = tot.retrans > 0
    ? fg(C_ALERT) + bold + "⚠ " + compactNum(tot.retrans) + " retrans" + RESET
    : fg(C_DIM) + "0 retrans" + RESET;
  /* Compact variants for tight terminals: drop the words after the
   * number, keep the glyph + count so the same info is still visible. */
  const clT  = fg(C_DIM) + "✕ " + compactNum(tot.closes) + RESET;
  const rstT = tot.resets > 0
    ? fg(C_ALERT) + "⚡ " + compactNum(tot.resets) + RESET
    : fg(C_DIM) + "⚡0" + RESET;
  const rtxT = tot.retrans > 0
    ? fg(C_ALERT) + bold + "⚠ " + compactNum(tot.retrans) + RESET
    : fg(C_DIM) + "⚠0" + RESET;
  const SEP = fg(C_DIM) + "   " + RESET;
  const SEP_TIGHT = fg(C_DIM) + "  " + RESET;
  const parts = [live + up, active, out + " " + acc, cl, rst, rtx];
  const partsTight = [live + up, active, out + " " + acc, clT, rstT, rtxT];
  let line = parts.join(SEP);
  if (vlen(line) > C) line = partsTight.join(SEP_TIGHT);
  return clipAnsi(line, C) + EOL;
}

/* ---- panel: state weather heatmap (signature) ---------------------- */
/* Each row is a TCP state, ordered top→bottom by lifecycle position
 * (LISTEN at top, terminal states at bottom). Cells are colored by
 * log-normalized count of *transitions into* that state in the tick.
 * Counts vary widely (idle ticks vs connect storms), so log-scaling
 * keeps the visual readable. */
function panelWeather(C, H) {
  const labelW = 11;                  /* widest: "NEW_SYN_R " */
  const sepW = 2;                     /* " │"  */
  const stripW = C - labelW - sepW - 1;
  if (stripW < 10) return [];

  /* per-row counts over the visible tick window */
  const visTicks = Math.min(stripW, Math.max(...HEATMAP_STATES.map(
    (s) => transHist.get(s)?.length ?? 0)));
  let maxCount = 0;
  const perState = new Map();
  for (const s of HEATMAP_STATES) {
    const h = transHist.get(s) ?? [];
    const start = Math.max(0, h.length - visTicks);
    const arr = new Int32Array(visTicks);
    for (let t = 0; t < visTicks; t++) {
      arr[t] = h[start + t] ?? 0;
      if (arr[t] > maxCount) maxCount = arr[t];
    }
    perState.set(s, arr);
  }
  const logMax = Math.log(1 + maxCount);
  const norm = (v) => maxCount > 0 ? Math.log(1 + v) / logMax : -1;

  /* Choose which states to render. If H >= HEATMAP_STATES.length we
   * draw all of them; otherwise we drop the rarest "terminal" states
   * (CLOSE, CLOSING) first so the dynamic states stay visible. */
  const dropOrder = [TCP_CLOSE, /* terminal */
    /* drop CLOSING last among the "anomalous" since it's rare */
  ];
  const list = HEATMAP_STATES.slice();
  while (list.length > H) {
    let dropped = false;
    for (const d of dropOrder) {
      const idx = list.indexOf(d);
      if (idx >= 0) { list.splice(idx, 1); dropped = true; break; }
    }
    if (!dropped) list.pop();         /* fallback */
  }

  const out = [];
  for (const s of list) {
    const info = stateOf(s);
    const arr = perState.get(s);
    const label = fg(info.color) + info.name + RESET;
    const axis = padVis(label, labelW - 1) + fg(C_AXIS) + " │" + RESET;
    let strip = "";
    const lead = stripW - visTicks;
    for (let i = 0; i < lead; i++) strip += heatCell(-1);
    for (let i = 0; i < visTicks; i++) {
      const v = arr[i];
      strip += v > 0 ? heatCell(norm(v)) : heatCell(-1);
    }
    out.push(axis + " " + strip + EOL);
  }
  return out;
}

/* ---- panel: current state distribution bar -------------------------- */
function panelStateBar(C) {
  const counts = activeStateDist();
  let total = 0;
  for (const v of counts.values()) total += v;

  /* leading label and total */
  const head = fg(45) + "  ACTIVE NOW " + RESET + fg(252) + compactNum(total) +
               RESET + fg(C_DIM) + " conns " + RESET;
  const headLen = vlen(head);
  const barW = Math.max(12, C - headLen - 2);

  if (total === 0) {
    return [head + fg(C_DIM) + ital + "(no active connections)" + RESET + EOL, ""];
  }

  /* build segments ordered by canonical lifecycle */
  const segs = [];
  for (const s of HEATMAP_STATES) {
    if (s === TCP_CLOSE) continue;
    const c = counts.get(s) ?? 0;
    if (c <= 0) continue;
    segs.push({ frac: c / total, color: stateOf(s).color });
  }
  const bar = stackedBar(segs, barW);

  /* legend, condensed: ●ESTAB 14  ◌TIME_W 7  ▤LISTEN 3 */
  const legParts = [];
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  for (const [s, n] of sorted) {
    const info = stateOf(s);
    legParts.push(fg(info.color) + info.glyph + " " + info.name + RESET +
                  fg(C_DIM) + " " + n + RESET);
  }
  const leg = "  " + legParts.join("  ");
  return [head + bar, leg];
}

/* ---- panel: top remote endpoints ----------------------------------- */
/* For each endpoint shows: address+port, total conns in window,
 * a mini stacked bar of its state distribution. */
function panelTopEndpoints(W, H) {
  const list = topEndpoints(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no outbound endpoints yet…" + RESET];
  }
  const out = [];
  /* width budget: addr_port + count + retrans? + mini_bar */
  for (let i = 0; i < Math.min(H, list.length); i++) {
    const e = list[i];
    const ep = aAddr(fmtEndpoint(e.family, e.addr, e.port));
    const epStr = fixw(fg(252) + ep + RESET, 26);
    const cn = fg(C_DIM) + fixw(compactNum(e.conns) + " conn", 9) + RESET;
    const rx = e.retrans > 0
      ? fg(C_ALERT) + fixw("⚠ " + compactNum(e.retrans), 6) + RESET
      : fg(C_DIM) + fixw("·", 6) + RESET;

    /* state distribution mini-bar across the endpoint's tracked states */
    let total = 0;
    for (const v of e.states.values()) total += v;
    const usedW = 26 + 1 + 9 + 1 + 6 + 1;  /* visible widths used so far */
    const barW = Math.max(6, W - usedW);
    let bar;
    if (total > 0) {
      const segs = [];
      for (const s of HEATMAP_STATES) {
        const c = e.states.get(s) ?? 0;
        if (c <= 0) continue;
        segs.push({ frac: c / total, color: stateOf(s).color });
      }
      bar = stackedBar(segs, barW);
    } else {
      bar = fg(C_AXIS) + "▱".repeat(barW) + RESET;
    }

    const line = epStr + " " + cn + " " + rx + " " + bar;
    out.push(clipAnsi(line, W));
  }
  while (out.length < H) out.push(" ".repeat(W));
  return out;
}

/* ---- panel: top processes ------------------------------------------ */
function panelTopProcs(W, H) {
  const list = topProcs(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no process-attributed conns yet…" + RESET];
  }
  const showRetrans = W >= 36;
  const commW = Math.min(15, Math.max(10, W - 24));
  const out = [];
  for (let i = 0; i < Math.min(H, list.length); i++) {
    const p = list[i];
    const comm = fixw(fg(252) + aName(p.comm) + RESET, commW);
    const pid = fg(C_DIM) + ("pid " + p.pid).padEnd(9) + RESET;
    const conns = fg(STATE_INFO[TCP_ESTABLISHED].color) +
                  fixw(compactNum(p.conns) + " conn", 8) + RESET;
    const rx = showRetrans
      ? "  " + (p.retrans > 0
          ? fg(C_ALERT) + "⚠ " + p.retrans + " rtx" + RESET
          : fg(C_DIM) + "· 0 rtx" + RESET)
      : "";
    const line = comm + " " + pid + " " + conns + rx;
    out.push(clipAnsi(line, W));
  }
  while (out.length < H) out.push(" ".repeat(W));
  return out;
}

/* ---- panel: live event feed ---------------------------------------- */
/* Each row is one transition or one retransmit; newest first.
 * Format: 00:00  ●ESTAB→FIN_W1  10.0.0.5:443 ⇠ 192.168.1.2:53412  pid 1284 nginx
 *         (or:) 00:00  ⚠ RETRANS    10.0.0.5:443 → 192.168.1.2:53412  pid 1284 nginx
 */
function panelFeed(C, H) {
  const list = recentEvents(H);
  if (list.length === 0) {
    return [fg(C_DIM) + ital + "  no events yet…" + RESET];
  }
  /* Endpoint column width adapts to terminal width so IPv6 fits when
   * there's room. At 80c → 20 each; at 120c → 28 each. */
  const epW = Math.max(20, Math.min(28, Math.floor((C - 50) / 2)));
  const out = [];
  for (let i = 0; i < Math.min(H, list.length); i++) {
    const e = list[i];
    const ts = fg(C_DIM) + mmss(Math.max(0, e.ts - startTime)) + RESET;
    const local = aAddr(fmtEndpoint(e.family, e.saddr, e.sport));
    const remote = aAddr(fmtEndpoint(e.family, e.daddr, e.dport));
    let kindStr;
    if (e.kind === "retrans") {
      kindStr = fg(C_ALERT) + bold + "⚠ RETRANS" + RESET + "  " +
                fg(252) + fixw(local, epW) + RESET +
                fg(C_DIM) + " → " + RESET +
                fg(252) + fixw(remote, epW) + RESET;
    } else {
      const oinfo = stateOf(e.oldstate);
      const ninfo = stateOf(e.newstate);
      const arrow = (e.dir === "in")
        ? fg(C_DIM) + " ⇠ " + RESET
        : fg(C_DIM) + " ⇢ " + RESET;
      const trans = fg(oinfo.color) + oinfo.name + RESET +
                    fg(C_DIM) + "→" + RESET +
                    fg(ninfo.color) + ninfo.name + RESET;
      kindStr = fixw(trans, 22) + " " +
                fg(252) + fixw(local, epW) + RESET +
                arrow +
                fg(252) + fixw(remote, epW) + RESET;
    }
    const proc = (e.pid > 0)
      ? fg(C_DIM) + "  pid " + e.pid + " " + RESET + fg(248) + aName(e.comm) + RESET
      : "";
    const line = " " + ts + "  " + kindStr + proc;
    out.push(clipAnsi(line, C));
  }
  while (out.length < H) out.push(" ".repeat(C));
  return out;
}

/* ---- top-level composition ----------------------------------------- */
export function renderDashboard(C, R) {
  if (C < MIN_COLS || R < MIN_ROWS) {
    return clearScreen() + smallTerm(C, R);
  }
  const rows = [];

  /* chrome */
  rows.push(topRule(C, "FLOWTOP · live TCP connection observatory"));
  rows.push(headerLine(C));
  rows.push("");

  /* adaptive sizing */
  const showMid = R >= 30;
  const winSec = Math.round(WINDOW_MS / 1000);
  /* chrome: topRule + header + blank + weatherTitle + blank?
   *       + barRow1 + barRow2 + blank + (midTitle + blank?)
   *       + feedTitle + blank + botRule
   * Conservative count: */
  const chrome = 2 /* top + header */ + 1 /* blank */
               + 1 /* weather title */
               + 1 /* blank */
               + 2 /* state bar (head+bar line, then legend line) */
               + 1 /* blank */
               + (showMid ? 1 + 1 : 0) /* mid title + blank */
               + 1 /* feed title */
               + 1 /* bottom rule */;

  const content = R - chrome;
  /* signature gets a generous chunk; ~half of content at R=30, more at R=44 */
  const weatherH = Math.max(8, Math.min(HEATMAP_STATES.length,
                            Math.round(content * (showMid ? 0.45 : 0.55))));
  const midH = showMid ? Math.max(4, Math.round(content * 0.30)) : 0;
  const feedH = Math.max(3, content - weatherH - midH);

  /* signature: state weather */
  rows.push(sectionBar(C, "STATE WEATHER · transitions into each TCP state, log-normalized"));
  const wx = panelWeather(C, weatherH);
  for (let i = 0; i < weatherH; i++) rows.push(wx[i] ?? " ".repeat(C));
  rows.push("");

  /* standing distribution: two lines (bar + legend) */
  const sb = panelStateBar(C);
  rows.push(sb[0]);
  rows.push(sb[1]);

  /* mid row: top endpoints | top procs */
  if (showMid) {
    rows.push("");
    const lw = Math.floor((C - 2) * 0.62);
    const rw = C - lw - 2;
    rows.push(sectionTitle(lw,
      "TOP REMOTE ENDPOINTS · " + winSec + "s window",
      "TOP PROCESSES · " + winSec + "s window"));
    const L = panelTopEndpoints(lw, midH);
    const R2 = panelTopProcs(rw, midH);
    zip(L, R2, lw, rw, rows);
  }

  /* feed */
  rows.push("");
  rows.push(sectionBar(C, "CONNECTION FEED · live transitions and retransmits, newest first"));
  const fd = panelFeed(C, feedH);
  for (let i = 0; i < feedH; i++) rows.push(fd[i] ?? " ".repeat(C));

  rows.push(botRule(C));

  /* clip to R rows and join */
  const out = rows.slice(0, R).map((l) => l.endsWith(EOL) || l.includes("\x1b[K") ? l : l + EOL);
  return clearScreen() + out.join("\n");
}

export function clearScreen() {
  return "\x1b[H\x1b[2J";
}

function smallTerm(C, R) {
  const msg = `flowtop needs ≥ ${MIN_COLS} cols × ${MIN_ROWS} rows · current ${C}×${R}`;
  return msg + "\n";
}
