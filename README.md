# flowtop

> *`ss`, with the time axis you always wanted.*

`flowtop` is a live observatory for the Linux TCP stack. Every state
transition every socket on the box passes through — `SYN_SENT`,
`ESTABLISHED`, `FIN_WAIT1`, `TIME_WAIT`, all of it — gets tapped from
the kernel by one BPF tracepoint, joined with every retransmit by a
second, and drawn as a **state-weather heatmap** that rolls across your
terminal. It's `netstat -ant` for the people who actually wanted to
*watch* the TCP state machine breathe.

It's built on [**yeet**](https://yeet.cx), a runtime
that makes a kernel-side BPF program, a per-tick render loop, and a JS
state model feel like one program.

<!-- To record the demo GIF, run `vhs assets/flowtop.tape` on a Linux box
     with yeet installed, then add:
     ![flowtop](assets/flowtop.gif)
     here. -->

---

## Sixty-second primer

Every TCP socket is a finite state machine. It starts in `CLOSE`. When
your app calls `connect()` it moves to `SYN_SENT`. When the SYN/ACK
comes back it transitions to `ESTABLISHED`. Data flows. When your app
calls `close()` it walks the four-way teardown: `FIN_WAIT1` →
`FIN_WAIT2` → `TIME_WAIT` → `CLOSE`. The other side has its own
mirrored walk: `CLOSE_WAIT` → `LAST_ACK` → `CLOSE`. A listening server
sits in `LISTEN` and each accepted connection passes through
`SYN_RECV` on its way to `ESTABLISHED`.

That state machine is where almost every interesting TCP story lives:

- A burst of `SYN_SENT` with no follow-up `ESTABLISHED` is a connection
  storm hitting an unreachable host (or a SYN flood).
- A pile-up in `TIME_WAIT` is short-lived client connections — typical
  for HTTP/1.1 without keepalive, sometimes a sign of an exhausted
  ephemeral port range.
- A jump from `ESTABLISHED` straight to `CLOSE`, skipping the FIN-wait
  states, is an RST — somebody hung up on the other end of the line.
- A row of retransmits with no corresponding state change is a network
  problem, not an application problem.

`ss -tan` shows you a still photograph of all that. `flowtop` shows you
the **movie**.

---

## What you're looking at

```
 ▌ FLOWTOP · live TCP connection observatory ──────────────────────────────────────
● LIVE 02:14   142 active   → 4.2k out ← 1.8k in   ✕ 5.6k closed   ⚡ 23 reset   ⚠ 87 retrans

  STATE WEATHER · transitions into each TCP state, log-normalized ────────────────
LISTEN     │ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
SYN_RECV   │ ▒░▒▒░░▒░▒░▒▒▒░░▒▒▒░▒░▒▒░▒░░▒▒░░▒▒░▒▒░░▒▒░▒░▒▒░▒▒▒░░▒▒░▒░▒▒░▒░░▒▒░▒
SYN_SENT   │ ▓▓▓▓▒▓▓▓▓▒▓▓▓▓▓▓▓▓▒▓▓▓▓▓▒▓▓▓▓▒▓▓▓▓▓▓▒▓▓▓▓▓▒▓▓▓▓▓▒▓▓▓▓▒▓▓▓▓▓▒▓▓▓
ESTAB      │ ████████████████████████████████████████████████████████████████████
FIN_W1     │ ▒▒▓▒▒▓▒▒▒▓▒▒▓▒▒▒▓▓▒▒▒▓▒▒▒▓▒▒▓▒▒▒▓▒▒▒▓▓▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▓▒▒▓
FIN_W2     │ ▒▓▒▒▓▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒
CLOSE_W    │ ░▒░░▒░▒░░▒░░░▒░░▒░░░▒░░░▒░░▒░░▒░░▒░░░▒░░▒░░▒░▒░░▒░░░▒░░▒░░░▒░░▒
LAST_ACK   │ ▒░░▒░▒░░▒░░░▒░░▒░░░▒░░▒░░░▒░░▒░░▒░░░▒░░▒░░▒░░░▒░░░▒░░▒░░░▒░░▒░░
TIME_W     │ ▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒
CLOSING    │
CLOSE      │ ▒▓▒▒▒▒▓▒▒▒▒▓▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▓▒▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒▓▒▒▒

  ACTIVE NOW 142 conns ▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰
  ● ESTAB 118  ◌ TIME_W 14  ▤ LISTEN 4  ⇢ FIN_W1 3  → SYN_SENT 2

TOP REMOTE ENDPOINTS · 10s window               │ TOP PROCESSES · 10s window
10.0.0.50:5432             142 conn  ⚠ 8   ▰▰▰▰▰│ envoy         pid 5500  3.2k conn  ⚠ 41 rtx
[2606:4700:4700:1111]:443   98 conn  ⚠ 6   ▰▰▰▰ │ node          pid 2031  1.1k conn  ⚠ 22 rtx
104.16.28.35:443            74 conn  ⚠ 4   ▰▰▰▰▰│ nginx         pid 1242   894 conn  ⚠ 12 rtx
8.8.8.8:53                  68 conn  ·     ▰▰▰▰▰│ prometheus    pid 6611   612 conn  ⚠ 8 rtx
1.1.1.1:443                 52 conn  ⚠ 2   ▰▰▰  │ psql          pid 3344   238 conn  ⚠ 4 rtx

  CONNECTION FEED · live transitions and retransmits, newest first ──────────────
 02:14  ESTAB→FIN_W1           10.0.0.12:54812          ⇢ 10.0.0.50:5432       pid 3344 psql
 02:14  ⚠ RETRANS              10.0.0.12:38114          → [2606:4700:4700:1111]:443  pid 5500 envoy
 02:14  TIME_W→CLOSE           10.0.0.12:48119          ⇢ 104.16.28.35:443     pid 1844 node
 02:13  LISTEN→SYN_RECV        10.0.0.12:443            ⇠ 198.51.100.7:42118   pid 1242 nginx
 02:13  ESTAB→CLOSE            10.0.0.12:55021          ⇢ 8.8.8.8:443          pid 2099 python3
```

### Panel by panel

**Header.** Uptime, currently-active connections, total outbound connects
seen (the `SYN_SENT` firsts), total inbound accepts seen (the `SYN_RECV`
firsts), total closes, RSTs (red), and retransmits (red, bold). RSTs are
inferred heuristically — an `ESTABLISHED → CLOSE` transition that skipped
the FIN_WAIT states is almost always an RST.

**State weather.** The signature view. One row per TCP state. Each
column is one render tick (200 ms). Cell color is the
log-normalized count of *transitions into* that state in that tick.
Bright streaks across `SYN_SENT` are connect bursts; bright streaks
across `TIME_W` are connection closures; a horizontal smear across
`ESTAB` is steady traffic; a flash across `CLOSE` skipping the FIN
states is bad news.

**Active now.** A stacked-segment bar showing the current state
distribution of all live connections. Colors match the state weather.
Legend underneath gives counts for the top five states.

**Top remote endpoints** (left). For *outbound* connections only —
servers don't aggregate well on the destination side, because every
inbound peer has us as the destination. Per endpoint: address+port,
total connections in the window, retransmit count (red ⚠ if any), and a
mini state-distribution bar.

**Top processes** (right). Pid + comm, connections opened in the
window, retransmits-on-its-sockets (red ⚠ if any). See *caveats* below
for why this is "best-effort".

**Connection feed.** Every state transition and every retransmit,
newest first. State transitions show the old → new state, the
local-side endpoint, the remote endpoint with a direction arrow
(`⇢` outbound, `⇠` inbound), and the pid/comm. Retransmits are red
and bold and start with `⚠ RETRANS`.

---

## How it works

Two BTF-typed tracepoints, one ringbuf:

| BPF program          | hook                                | what it does                                                |
|----------------------|-------------------------------------|-------------------------------------------------------------|
| `on_set_state`       | `tp_btf/inet_sock_set_state`        | emit `(old, new, sk, family, sport, dport, addrs, comm)`    |
| `on_retrans`         | `tp_btf/tcp_retransmit_skb`         | emit a retransmit record for the corresponding `sk`         |

The userspace side is one ringbuf subscriber and a `setInterval` tick.
The kernel-side program is straight-line: read the sock_common fields
via CO-RE, branch on `family` (`AF_INET` copies 4 bytes; `AF_INET6`
reads `skc_v6_*` into the 16-byte buffer), submit the record. No maps,
no per-CPU arrays, nothing to leak across program reloads.

The JS side maintains:

- A `Map` of currently-tracked sockets keyed by sock pointer
- Per-tick counts of transitions *into* each state — the weather data
- Per-tick retransmit counts
- A rolling per-process aggregator (conns opened, retransmits on those
  conns)
- A rolling per-remote-endpoint aggregator (for outbound conns only)
- A bounded ring of recent events for the feed

---

## Requirements

- **Linux ≥ 5.5** for BTF-typed tracepoints. CO-RE handles kernel-struct
  drift across versions.
- **CAP_BPF + CAP_PERFMON** (or root) to load the program.
- **clang** + **bpftool** to build.
- A terminal with 256-color support and Unicode. State weather cells use
  the 256-color background range; the stacked bars and braille axes use
  Unicode block chars.
- Minimum sensible terminal size: **80 × 28**. Below that the panels
  collapse and you get a "needs larger terminal" message.

---

## Build & run

```sh
make
sudo yeet main.js                # all sockets, all transitions
sudo yeet main.js -- --anonymize # screenshot-safe: aliases comm + addrs
```

To stop, hit `Ctrl-C`. The cursor is restored on exit.

---

## Caveats — read these before you panic at the numbers

- **Pid attribution is best-effort.** TCP state transitions happen
  inside the network stack, often in softirq context, which means
  `current` at hook time is frequently a `kworker` or `swapper` rather
  than the application that owns the socket. flowtop mitigates this
  with a *first-real-pid-wins* rule: the first transition for a sock
  whose `comm` doesn't look like a kernel thread (i.e. doesn't start
  with `swapper`, `kworker`, or `ksoftirq`) is remembered as the
  socket's owner and the comm/pid don't get overwritten by later
  softirq-context transitions. Sockets created entirely inside the
  kernel (e.g. NFS client) will keep their kthread attribution.
- **Sockets created before flowtop starts won't appear until they
  transition.** Long-lived idle connections that never send data
  between flowtop's startup and shutdown will be invisible to it.
  flowtop never reads `/proc/net/tcp` to backfill — it shows you what
  the kernel is doing *now*, not what's already there.
- **Connection direction is inferred at first sight.** Outbound
  connections are caught at `CLOSE → SYN_SENT`. Inbound accepts are
  caught at `LISTEN → SYN_RECV` (or `NEW_SYN_RECV` on newer kernels).
  If we catch a socket mid-life — for example one that was already
  `ESTABLISHED` when flowtop started but transitioned afterward — the
  direction will be marked `?` until it closes.
- **Top-remote-endpoints aggregates only outbound conns.** Server-side
  inbound has a fanout of one daddr=us-the-server per peer, so the
  numbers would be meaningless. If you want a top-talkers view for an
  inbound-heavy workload, look at the connection feed and the active
  state distribution instead.
- **The ringbuf can drop events under extreme load.** flowtop uses a
  256 KiB ringbuf and processes one event at a time on the JS side. On
  a machine running tens of thousands of TCP transitions per second
  (e.g. a heavily loaded load balancer) you may see the kernel drop
  events when the JS side gets behind. The counts will under-report;
  the heatmap will under-color. Nothing will lie about a transition
  that did make it through.
- **RST counting is heuristic.** flowtop counts an
  `ESTABLISHED → CLOSE` transition that skipped the FIN_WAIT states as
  an RST. This is correct for the vast majority of resets, but a peer
  that sends `FIN` immediately after the last data byte can occasionally
  produce an `ESTABLISHED → CLOSE` directly in `inet_sock_set_state` if
  the FIN_WAIT walk is short-circuited. The over-count is small in
  practice.

---

## License

Apache 2.0.
