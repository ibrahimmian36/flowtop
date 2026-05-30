/* Application state + ingest for flowtop.
 *
 * The BPF side emits two kinds of records to one ringbuf:
 *   kind 0  state transition (inet_sock_set_state)
 *   kind 1  retransmit         (tcp_retransmit_skb)
 *
 * The model below maintains:
 *   • a Map of currently-tracked connections keyed by sock pointer
 *   • per-tick counts of *transitions into* each state — the "weather"
 *     for the signature heatmap
 *   • per-tick retransmit counts
 *   • a rolling per-process aggregator (conns opened, retrans count)
 *   • a rolling per-remote-endpoint aggregator (conns, current states)
 *   • a recent-events feed for the live panel
 *
 * pid/comm captured in BPF are best-effort: TCP state transitions often
 * happen in softirq context where `current` is whichever task got
 * interrupted (frequently swapper or a kworker). We compensate with
 * a first-real-pid-wins rule: the first transition whose pid maps to
 * a non-kernel-ish task wins and is remembered for that sock. */

import {
  TCP_ESTABLISHED, TCP_SYN_SENT, TCP_SYN_RECV, TCP_NEW_SYN_RECV,
  TCP_FIN_WAIT1, TCP_FIN_WAIT2, TCP_CLOSE_WAIT, TCP_LAST_ACK,
  TCP_TIME_WAIT, TCP_CLOSING, TCP_CLOSE, TCP_LISTEN,
  HEATMAP_STATES, ACTIVE_STATES,
} from "./render.js";

export const TICK_MS = 200;          /* render cadence + sample spacing */
export const WINDOW_MS = 10000;      /* rolling window: top procs, endpoints */
export const HIST_LEN = 240;         /* ticks of history retained (~48 s) */
const CLOSE_FADE_MS = 5_000;         /* keep CLOSE'd conns visible briefly  */
const ENDPOINT_STALE_MS = 60_000;
const PROC_STALE_MS = 60_000;
const FEED_KEEP = 200;

/* ---- counters + rolling history ------------------------------------ */
export const startTime = Date.now();
export const tot = {
  events: 0,        /* total ringbuf events seen */
  connectsOut: 0,   /* SYN_SENT firsts */
  acceptsIn: 0,    /* SYN_RECV firsts */
  closes: 0,        /* transitions into CLOSE */
  retrans: 0,       /* total retransmits */
  resets: 0,        /* ESTABLISHED → CLOSE skipping FIN_WAIT (heuristic) */
};

/* per-tick counters: rolled into history each `advance()` */
const tickTransIn = new Map();   /* state → count of transitions INTO it */
let tickRetrans = 0;
export const transHist = new Map();   /* state → number[] of HIST_LEN ticks */
for (const s of HEATMAP_STATES) transHist.set(s, []);
export const retransHist = [];
export const activeHist = [];         /* total active conns per tick */

function pushHist(arr, v) { arr.push(v); if (arr.length > HIST_LEN) arr.shift(); }

/* ---- connection table --------------------------------------------- */
/* key: sk (sock pointer, as bigint or number); value: ConnInfo */
const conns = new Map();

/* Determine direction at first sight.
 *   first newstate == SYN_SENT  → outbound (we initiated)
 *   first newstate == SYN_RECV  → inbound (we received SYN)
 *   first newstate == LISTEN    → listening socket (server side)
 *   anything else               → "unknown" (sock observed mid-life) */
function inferDir(newstate) {
  if (newstate === TCP_SYN_SENT) return "out";
  if (newstate === TCP_SYN_RECV || newstate === TCP_NEW_SYN_RECV) return "in";
  if (newstate === TCP_LISTEN) return "listen";
  return "?";
}

/* Heuristic: pids 0 (swapper) and 2 (kthreadd) and processes whose
 * comm starts with "kworker" or "swapper" are not real owners. We let
 * a later state transition with a "real" pid overwrite. */
function isKernelComm(comm) {
  if (!comm) return true;
  return comm.startsWith("swapper") || comm.startsWith("kworker") ||
         comm.startsWith("ksoftirq") || comm === "0" || comm === "?";
}

/* ---- anonymize (screenshot-safe relabeling) ------------------------ */
const anon = !!globalThis.yeet?.args?.anonymize;
const aliasMaps = { name: new Map(), addr: new Map() };
function aliasGen(kind, key, prefix) {
  const m = aliasMaps[kind];
  let a = m.get(key);
  if (!a) { a = prefix + String(m.size + 1).padStart(2, "0"); m.set(key, a); }
  return a;
}
export function aName(s) { return anon && s ? aliasGen("name", s, "proc-") : s; }
export function aAddr(s) { return anon && s ? aliasGen("addr", s, "host-") : s; }

/* ---- aggregators (rolling, per-window) ----------------------------- */
const procStats = new Map();    /* "pid:comm" → {pid, comm, conns, retrans, lastSeen} */
const endpointStats = new Map(); /* "addr:port" → {family, addr[16], port, conns, retrans, states, lastSeen} */

function getProc(pid, comm) {
  const key = pid + ":" + comm;
  let p = procStats.get(key);
  if (!p) { p = { pid, comm, conns: 0, retrans: 0, lastSeen: 0 }; procStats.set(key, p); }
  return p;
}
function getEndpoint(family, addrBytes, port) {
  const addrCopy = new Uint8Array(16);
  for (let i = 0; i < 16; i++) addrCopy[i] = addrBytes[i] | 0;
  /* key string: family + raw bytes + port */
  let key = String(family) + ":";
  for (let i = 0; i < 16; i++) key += addrCopy[i].toString(16).padStart(2, "0");
  key += ":" + port;
  let e = endpointStats.get(key);
  if (!e) {
    e = { family, addr: addrCopy, port, conns: 0, retrans: 0, states: new Map(), lastSeen: 0 };
    endpointStats.set(key, e);
  }
  return e;
}

/* ---- recent events feed -------------------------------------------- */
const feed = [];
function pushFeed(rec) { feed.push(rec); if (feed.length > FEED_KEEP) feed.shift(); }

/* ---- ingest -------------------------------------------------------- */
/* Decoded BPF event shape (see flowtop.bpf.c):
 *   ts_ns, sk, oldstate, newstate, family, sport, dport,
 *   saddr[16], daddr[16], pid, comm, kind */
function num(v) { return typeof v === "bigint" ? Number(v) : v; }
function bigKey(v) { return typeof v === "bigint" ? v.toString(16) : String(v); }
function bytesAsArray(b) {
  const out = new Uint8Array(16);
  if (!b) return out;
  for (let i = 0; i < 16; i++) out[i] = b[i] | 0;
  return out;
}

export function onEvent(e) {
  if (!e) return;
  tot.events++;
  const kind = num(e.kind) | 0;
  const now = Date.now();
  const sk = bigKey(e.sk);
  const family = num(e.family) | 0;
  const sport = num(e.sport) & 0xffff;
  const dport = num(e.dport) & 0xffff;
  const saddr = bytesAsArray(e.saddr);
  const daddr = bytesAsArray(e.daddr);
  const pid = num(e.pid) | 0;
  const comm = String(e.comm || "?");

  if (kind === 1) {
    /* retransmit */
    tot.retrans++; tickRetrans++;
    const c = conns.get(sk);
    if (c) {
      c.retrans++;
      c.lastUpdate = now;
      /* mirror into per-proc / per-endpoint */
      const p = getProc(c.pid, c.comm); p.retrans++; p.lastSeen = now;
      const ep = getEndpoint(c.family, c.daddr, c.dport); ep.retrans++; ep.lastSeen = now;
      pushFeed({ ts: now, kind: "retrans", sk, family: c.family, saddr: c.saddr, sport: c.sport,
                 daddr: c.daddr, dport: c.dport, pid: c.pid, comm: c.comm });
    } else {
      /* retransmit on a conn we never saw transition through — record
       * the addrs from the event itself so it isn't entirely opaque */
      pushFeed({ ts: now, kind: "retrans", sk, family, saddr, sport, daddr, dport, pid, comm });
    }
    return;
  }

  /* kind === 0: state transition */
  const oldstate = num(e.oldstate) | 0;
  const newstate = num(e.newstate) | 0;

  /* per-tick into-state count for the heatmap */
  tickTransIn.set(newstate, (tickTransIn.get(newstate) ?? 0) + 1);

  /* connection table maintenance */
  let c = conns.get(sk);
  const firstSight = !c;
  if (!c) {
    c = {
      sk, family, saddr, sport, daddr, dport,
      state: newstate, prevState: oldstate,
      dir: inferDir(newstate),
      pid, comm,
      firstSeen: now, lastUpdate: now,
      established_at: 0, closed_at: 0,
      retrans: 0,
    };
    conns.set(sk, c);
  } else {
    /* pid/comm: first real owner wins */
    if (isKernelComm(c.comm) && !isKernelComm(comm)) {
      c.pid = pid; c.comm = comm;
    }
    /* if we've never had a sport (saw LISTEN'd accept hit ESTABLISHED), fill */
    if (c.sport === 0 && sport !== 0) c.sport = sport;
    if (c.dport === 0 && dport !== 0) c.dport = dport;
    if (family && c.family !== family) c.family = family;
    c.prevState = c.state;
    c.state = newstate;
    c.lastUpdate = now;
  }

  /* counters */
  if (firstSight) {
    if (c.dir === "out") tot.connectsOut++;
    else if (c.dir === "in") tot.acceptsIn++;
  } else {
    /* missed firsts: if newstate is SYN_SENT but we didn't catch the
     * sk at creation (unlikely), still count it */
    if (oldstate === TCP_CLOSE && newstate === TCP_SYN_SENT) tot.connectsOut++;
    if (oldstate === TCP_LISTEN && newstate === TCP_SYN_RECV) tot.acceptsIn++;
  }
  if (newstate === TCP_ESTABLISHED && c.established_at === 0) c.established_at = now;
  if (newstate === TCP_CLOSE) {
    tot.closes++;
    /* abrupt close from ESTABLISHED is most likely an RST from the peer */
    if (oldstate === TCP_ESTABLISHED) tot.resets++;
    c.closed_at = now;
  }

  /* aggregators (only for non-LISTEN, non-CLOSE — we don't want LISTEN
   * sockets dominating the "top processes" list, nor short-lived CLOSE
   * transitions inflating the count) */
  if (firstSight && newstate !== TCP_LISTEN && newstate !== TCP_CLOSE) {
    const p = getProc(pid, comm); p.conns++; p.lastSeen = now;
    /* only outbound conns have a "remote endpoint" worth aggregating
     * on a per-daddr basis (server inbound is one daddr=us per peer) */
    if (c.dir === "out") {
      const ep = getEndpoint(family, daddr, dport);
      ep.conns++; ep.lastSeen = now;
      ep.states.set(newstate, (ep.states.get(newstate) ?? 0) + 1);
    }
  }
  /* endpoint state mutation: on later transitions of an outbound conn,
   * update its remote endpoint's state map */
  if (!firstSight && c.dir === "out") {
    const ep = getEndpoint(c.family, c.daddr, c.dport);
    /* decrement previous state, increment new */
    const prev = oldstate;
    if (ep.states.has(prev)) {
      const v = ep.states.get(prev) - 1;
      if (v <= 0) ep.states.delete(prev);
      else ep.states.set(prev, v);
    }
    ep.states.set(newstate, (ep.states.get(newstate) ?? 0) + 1);
    ep.lastSeen = now;
  }

  pushFeed({
    ts: now, kind: "state", sk,
    family: c.family, saddr: c.saddr, sport: c.sport,
    daddr: c.daddr, dport: c.dport,
    oldstate, newstate, dir: c.dir,
    pid: c.pid, comm: c.comm,
  });
}

/* ---- per-tick roll + reaping --------------------------------------- */
export function advance() {
  const now = Date.now();

  /* roll the per-state-into counters into history */
  for (const s of HEATMAP_STATES) {
    const v = tickTransIn.get(s) ?? 0;
    pushHist(transHist.get(s), v);
  }
  tickTransIn.clear();
  pushHist(retransHist, tickRetrans); tickRetrans = 0;

  /* active conns: count those whose state is in ACTIVE_STATES */
  let active = 0;
  for (const c of conns.values()) if (ACTIVE_STATES.has(c.state)) active++;
  pushHist(activeHist, active);

  /* reap: CLOSEd conns past the fade window are removed entirely */
  for (const [sk, c] of conns) {
    if (c.state === TCP_CLOSE && c.closed_at > 0 && now - c.closed_at > CLOSE_FADE_MS) {
      conns.delete(sk);
    }
  }
  /* reap stale aggregators */
  for (const [k, p] of procStats) if (now - p.lastSeen > PROC_STALE_MS) procStats.delete(k);
  for (const [k, e] of endpointStats) if (now - e.lastSeen > ENDPOINT_STALE_MS) endpointStats.delete(k);

  /* prune the feed log to entries within the window (cap is FEED_KEEP regardless) */
  while (feed.length && now - feed[0].ts > WINDOW_MS * 3) feed.shift();
}

/* ---- accessors ----------------------------------------------------- */
const oneSecTicks = Math.max(1, Math.round(1000 / TICK_MS));
function sumTail(arr, n) {
  const start = Math.max(0, arr.length - n);
  let s = 0;
  for (let i = start; i < arr.length; i++) s += arr[i];
  return s;
}

export function liveRates() {
  const winTicks = Math.round(WINDOW_MS / TICK_MS);
  return {
    eventsLastSec: 0, /* placeholder for any future per-sec metric */
    retransLastWin: sumTail(retransHist, winTicks),
    activeNow: activeHist.length ? activeHist[activeHist.length - 1] : 0,
  };
}

/* Current state distribution of *active* connections, sorted by the
 * canonical lifecycle order in HEATMAP_STATES. */
export function activeStateDist() {
  const counts = new Map();
  for (const c of conns.values()) {
    if (!ACTIVE_STATES.has(c.state)) continue;
    counts.set(c.state, (counts.get(c.state) ?? 0) + 1);
  }
  return counts;
}

export function topProcs(n) {
  const now = Date.now();
  const list = [...procStats.values()]
    .filter((p) => now - p.lastSeen <= WINDOW_MS * 6);  /* ~60 s window */
  list.sort((a, b) => (b.conns + b.retrans * 2) - (a.conns + a.retrans * 2));
  return list.slice(0, n);
}

export function topEndpoints(n) {
  const now = Date.now();
  const list = [...endpointStats.values()]
    .filter((e) => now - e.lastSeen <= WINDOW_MS * 6);
  list.sort((a, b) => (b.conns + b.retrans * 5) - (a.conns + a.retrans * 5));
  return list.slice(0, n);
}

export function recentEvents(n) { return feed.slice(-n).reverse(); }

/* exported for the connection-feed panel; useful for tests too */
export function currentConns() { return conns; }
