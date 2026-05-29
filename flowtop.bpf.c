#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* flowtop — live TCP connection observatory.
 *
 * Two BTF-typed tracepoints:
 *
 *   inet_sock_set_state   →  fires on *every* TCP state transition
 *                            (LISTEN→SYN_RECV, SYN_SENT→ESTABLISHED,
 *                            ESTABLISHED→FIN_WAIT_1, …). A single hook
 *                            captures the whole connection lifecycle.
 *
 *   tcp_retransmit_skb    →  fires when the stack retransmits a segment.
 *                            Best signal for "the network is unhappy."
 *
 * Both feed one ringbuf. JS sorts events apart by the `kind` discriminator.
 * We snapshot the sock pointer as connection identity, plus addresses and
 * ports out of `struct sock_common`. */

#define COMM_LEN 16
#define ADDR_LEN 16                  /* IPv4 in first 4 bytes; IPv6 fills it */

#define AF_INET   2
#define AF_INET6 10

#define FLOW_KIND_STATE   0
#define FLOW_KIND_RETRANS 1

struct flow_evt {
    __u64 ts_ns;
    __u64 sk;                        /* sock pointer = connection identity  */
    __u32 oldstate;                  /* TCP_* enum, 0 for retransmit events */
    __u32 newstate;
    __u32 family;                    /* AF_INET or AF_INET6                 */
    __u16 sport;                     /* host byte order                     */
    __u16 dport;                     /* host byte order (we ntohs in BPF)   */
    __u8  saddr[ADDR_LEN];           /* network byte order; v4 in [0..3]    */
    __u8  daddr[ADDR_LEN];
    __u32 pid;                       /* best-effort: current at hook time   */
    char  comm[COMM_LEN];
    __u8  kind;                      /* FLOW_KIND_*                         */
    __u8  _pad[3];
};
__attribute__((used)) static const struct flow_evt __flow_evt_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

/* Pull the family-aware address+port info out of struct sock into the
 * pre-reserved ringbuf record. Inline so both hook paths use the same
 * read sequence and the verifier sees a single straight-line program. */
static __always_inline void fill_sock(struct flow_evt *e, struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->family = family;

    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);            /* host order */
    __u16 dp_n = BPF_CORE_READ(sk, __sk_common.skc_dport);        /* net  order */
    e->dport = __builtin_bswap16(dp_n);                           /* → host     */

    /* zero both buffers; the family-specific copy fills the relevant bytes */
    __builtin_memset(e->saddr, 0, ADDR_LEN);
    __builtin_memset(e->daddr, 0, ADDR_LEN);

    if (family == AF_INET) {
        __u32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &s4, 4);
        __builtin_memcpy(e->daddr, &d4, 4);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
    }
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(on_set_state, struct sock *sk, int oldstate, int newstate)
{
    struct flow_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns    = bpf_ktime_get_ns();
    e->sk       = (__u64)sk;
    e->oldstate = oldstate;
    e->newstate = newstate;
    e->kind     = FLOW_KIND_STATE;
    fill_sock(e, sk);
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(on_retrans, struct sock *sk, struct sk_buff *skb)
{
    struct flow_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns    = bpf_ktime_get_ns();
    e->sk       = (__u64)sk;
    e->oldstate = 0;
    e->newstate = 0;
    e->kind     = FLOW_KIND_RETRANS;
    fill_sock(e, sk);
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
