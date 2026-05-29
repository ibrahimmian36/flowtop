/* Pure terminal-rendering toolkit for flowtop: ANSI escapes, color
 * ramps, a braille canvas, address formatters, and the TCP state
 * palette. No application state, no I/O — safe to import anywhere. */

export const ESC = "\x1b[";
export const HOME = `${ESC}H`;
export const CLEAR = `${ESC}2J${ESC}H`;
export const HIDE = `${ESC}?25l`;
export const SHOW = `${ESC}?25h`;
export const RESET = `${ESC}0m`;
export const EOL = `${ESC}K`;
export const bold = `${ESC}1m`;
export const dim = `${ESC}2m`;
export const ital = `${ESC}3m`;
export const fg = (n) => `${ESC}38;5;${n}m`;
export const bg = (n) => `${ESC}48;5;${n}m`;

/* low→high heat ramp, and the silent / muted slots */
export const HEAT = [17, 18, 19, 20, 26, 32, 39, 45, 51, 50, 48, 46, 82, 118,
  154, 190, 226, 220, 214, 208, 202, 196, 197, 231];
export const SILENT_BG = 234;
export const EIGHTH = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/* axis + dim colors */
export const C_AXIS = 238;
export const C_DIM = 240;
export const C_ALERT = 196;        /* retransmits, errors */

/* TCP state codes — the kernel's TCP_* enum.
 *   include/net/tcp_states.h */
export const TCP_ESTABLISHED  = 1;
export const TCP_SYN_SENT     = 2;
export const TCP_SYN_RECV     = 3;
export const TCP_FIN_WAIT1    = 4;
export const TCP_FIN_WAIT2    = 5;
export const TCP_TIME_WAIT    = 6;
export const TCP_CLOSE        = 7;
export const TCP_CLOSE_WAIT   = 8;
export const TCP_LAST_ACK     = 9;
export const TCP_LISTEN       = 10;
export const TCP_CLOSING      = 11;
export const TCP_NEW_SYN_RECV = 12;

/* Per-state metadata: short name, full name, color, sort priority,
 * and a one-glyph marker for the connection feed.
 *   - "fresh" states (SYN_SENT/RECV) → cool blues
 *   - active (ESTABLISHED/LISTEN)    → green / bright cyan
 *   - closing (FIN_WAIT*, LAST_ACK)  → amber / orange
 *   - terminal (TIME_WAIT, CLOSE)    → purple / dim
 *   - anomalous (CLOSING)            → red */
export const STATE_INFO = {
  [TCP_ESTABLISHED]:  { name: "ESTAB",     full: "ESTABLISHED",    color: 84,  glyph: "●", sort: 1 },
  [TCP_SYN_SENT]:     { name: "SYN_SENT",  full: "SYN_SENT",       color: 51,  glyph: "→", sort: 2 },
  [TCP_SYN_RECV]:     { name: "SYN_RECV",  full: "SYN_RECV",       color: 39,  glyph: "←", sort: 3 },
  [TCP_NEW_SYN_RECV]: { name: "NEW_SYN_R", full: "NEW_SYN_RECV",   color: 39,  glyph: "←", sort: 4 },
  [TCP_FIN_WAIT1]:    { name: "FIN_W1",    full: "FIN_WAIT1",      color: 215, glyph: "⇢", sort: 5 },
  [TCP_FIN_WAIT2]:    { name: "FIN_W2",    full: "FIN_WAIT2",      color: 208, glyph: "⇢", sort: 6 },
  [TCP_CLOSE_WAIT]:   { name: "CLOSE_W",   full: "CLOSE_WAIT",     color: 220, glyph: "⇠", sort: 7 },
  [TCP_LAST_ACK]:     { name: "LAST_ACK",  full: "LAST_ACK",       color: 202, glyph: "⇠", sort: 8 },
  [TCP_TIME_WAIT]:    { name: "TIME_W",    full: "TIME_WAIT",      color: 141, glyph: "◌", sort: 9 },
  [TCP_CLOSING]:      { name: "CLOSING",   full: "CLOSING",        color: 196, glyph: "⚠", sort: 10 },
  [TCP_CLOSE]:        { name: "CLOSE",     full: "CLOSE",          color: 244, glyph: "✕", sort: 11 },
  [TCP_LISTEN]:       { name: "LISTEN",    full: "LISTEN",         color: 87,  glyph: "▤", sort: 12 },
};
export const UNKNOWN_STATE = { name: "?",   full: "UNKNOWN",   color: 244, glyph: "?", sort: 99 };
export function stateOf(s) { return STATE_INFO[s] ?? UNKNOWN_STATE; }

/* States we draw rows for in the big "state weather" heatmap.
 * Ordered top→bottom roughly by lifecycle position so the visual
 * reads like a state diagram unrolled along the y-axis. */
export const HEATMAP_STATES = [
  TCP_LISTEN, TCP_SYN_RECV, TCP_SYN_SENT, TCP_ESTABLISHED,
  TCP_FIN_WAIT1, TCP_FIN_WAIT2, TCP_CLOSE_WAIT, TCP_LAST_ACK,
  TCP_TIME_WAIT, TCP_CLOSING, TCP_CLOSE,
];

/* States that count as "currently active" for the distribution bar
 * and active-conn counter. CLOSE is terminal; we keep it around for
 * a few seconds in the connection feed but it's not an active conn. */
export const ACTIVE_STATES = new Set([
  TCP_ESTABLISHED, TCP_SYN_SENT, TCP_SYN_RECV, TCP_NEW_SYN_RECV,
  TCP_FIN_WAIT1, TCP_FIN_WAIT2, TCP_CLOSE_WAIT, TCP_LAST_ACK,
  TCP_TIME_WAIT, TCP_CLOSING, TCP_LISTEN,
]);

/* ---- formatters ---------------------------------------------------- */

/* IPv4 dot-quad from the first 4 bytes of a 16-byte addr buffer. */
export function fmtIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

/* IPv6 lowercase with longest run of zero groups collapsed to "::".
 * Also handles IPv4-mapped (::ffff:a.b.c.d) inline. */
export function fmtIPv6(bytes) {
  const g = new Array(8);
  for (let i = 0; i < 8; i++) g[i] = (bytes[i * 2] << 8) | bytes[i * 2 + 1];

  /* IPv4-mapped: ::ffff:V4 */
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 &&
      g[4] === 0 && g[5] === 0xffff) {
    return `::ffff:${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }

  /* find the longest run of zero groups (≥2) to collapse */
  let bestStart = -1, bestLen = 0;
  let curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (curStart === -1) { curStart = i; curLen = 1; }
      else curLen++;
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) bestStart = -1;

  let out = "";
  for (let i = 0; i < 8; i++) {
    if (i === bestStart) { out += i === 0 ? "::" : ":"; i += bestLen - 1; continue; }
    if (out.length > 0 && !out.endsWith(":")) out += ":";
    out += g[i].toString(16);
  }
  return out;
}

export function fmtAddr(family, bytes) {
  if (family === 10 /* AF_INET6 */) return fmtIPv6(bytes);
  return fmtIPv4(bytes);
}

/* "host:port" with the host bracketed if it's IPv6 (avoids ambiguity
 * with the ':' inside an IPv6 literal). */
export function fmtEndpoint(family, bytes, port) {
  const addr = fmtAddr(family, bytes);
  if (family === 10) return `[${addr}]:${port}`;
  return `${addr}:${port}`;
}

export function fmtPort(p) { return String(p); }

export function mmss(ms) {
  const t = Math.floor(ms / 1000);
  const h = Math.floor(t / 3600);
  const m = Math.floor((t % 3600) / 60);
  const s = t % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${p(h)}:${p(m)}:${p(s)}` : `${p(m)}:${p(s)}`;
}

export function compactNum(n) {
  if (!isFinite(n)) return "—";
  if (n >= 1e9) return (n / 1e9).toFixed(n >= 1e10 ? 0 : 1) + "G";
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(0) + "k";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(Math.round(n));
}

/* humanize an elapsed-ms count into 1–2 char units */
export function fmtAge(ms) {
  if (!isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return Math.round(ms) + "ms";
  const s = Math.round(ms / 1000);
  if (s < 60) return s + "s";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m";
  const h = Math.round(m / 60);
  return h + "h";
}

/* visible-length + ANSI-aware clip / pad */
export function vlen(s) {
  return s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").length;
}
export function clip(s, n) {
  s = String(s ?? "");
  if (n <= 0) return "";
  if (s.length <= n) return s;
  if (n === 1) return "…";
  return s.slice(0, n - 1) + "…";
}
export function clipAnsi(s, n) {
  let out = "", vis = 0, i = 0;
  while (i < s.length) {
    if (s[i] === "\x1b") {
      const m = /^\x1b\[[0-9;?]*[A-Za-z]/.exec(s.slice(i));
      if (m) { out += m[0]; i += m[0].length; continue; }
    }
    if (vis >= n) break;
    out += s[i]; vis++; i++;
  }
  return out + RESET;
}
export function fixw(s, w) {
  const v = vlen(s);
  if (v < w) s = s + " ".repeat(w - v);
  return clipAnsi(s, w);
}
export function padVis(s, n) {
  const pad = n - vlen(s);
  return pad > 0 ? s + " ".repeat(pad) : s;
}

/* one heat cell: v<0 → idle (dark bg), else a bg-colored block */
export function heatCell(v) {
  if (v < 0) return bg(SILENT_BG) + " " + RESET;
  return bg(HEAT[Math.min(HEAT.length - 1, Math.floor(v * HEAT.length))]) + " " + RESET;
}

/* horizontal stacked-segment bar. segs = [{frac, color}], frac sums ≤ 1.
 * Pads remainder with a dim "▱" so the bar always has fixed width. */
export function stackedBar(segs, width) {
  let used = 0;
  let out = "";
  for (let i = 0; i < segs.length; i++) {
    const w = i === segs.length - 1
      ? Math.max(0, width - used)
      : Math.max(0, Math.round(segs[i].frac * width));
    if (w <= 0) continue;
    out += fg(segs[i].color) + "▰".repeat(w) + RESET;
    used += w;
  }
  if (used < width) out += fg(C_AXIS) + "▱".repeat(width - used) + RESET;
  return out;
}

/* one-cell sparkline using the EIGHTH bar glyphs, w cells wide.
 * Right-aligned: leading cells (when hist is short) get spaces. */
export function sparkline(hist, w, color = 51) {
  if (w <= 0 || hist.length === 0) return " ".repeat(Math.max(0, w));
  const vis = Math.min(w, hist.length);
  const start = hist.length - vis;
  let max = 0;
  for (let i = start; i < hist.length; i++) if (hist[i] > max) max = hist[i];
  let out = "";
  for (let i = 0; i < w - vis; i++) out += " ";
  if (max === 0) {
    for (let i = 0; i < vis; i++) out += fg(C_AXIS) + EIGHTH[0] + RESET;
  } else {
    for (let i = 0; i < vis; i++) {
      const v = hist[start + i] / max;
      const idx = Math.max(1, Math.min(8, Math.round(v * 8)));
      out += fg(color) + EIGHTH[idx] + RESET;
    }
  }
  return out;
}

/* Braille canvas — same shape as xtop/blktop's: each cell packs a
 * 2×4 dot grid, so cw×ch cells give 2cw×4ch pixels. One fg color per
 * cell (last writer wins). (0,0) top-left. Kept here so any future
 * line/curve panel can use it without depending on the others. */
const BRAILLE_DOT = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]];
export function brailleCanvas(cw, ch) {
  const PW = cw * 2, PH = ch * 4;
  const mask = new Int32Array(cw * ch);
  const color = new Array(cw * ch).fill(0);
  return {
    PW, PH,
    set(px, py, col) {
      if (px < 0 || px >= PW || py < 0 || py >= PH) return;
      const i = (py >> 2) * cw + (px >> 1);
      mask[i] |= BRAILLE_DOT[py & 3][px & 1];
      if (col) color[i] = col;
    },
    rows() {
      const out = [];
      for (let cy = 0; cy < ch; cy++) {
        let line = "";
        for (let cx = 0; cx < cw; cx++) {
          const i = cy * cw + cx, m = mask[i];
          line += m === 0 ? " " : fg(color[i] || 51) + String.fromCodePoint(0x2800 + m) + RESET;
        }
        out.push(line);
      }
      return out;
    },
  };
}
