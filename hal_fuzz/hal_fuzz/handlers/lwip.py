from unicorn.arm_const import *

from ..models.tcp import TCP
from ..globs import debug_enabled
from ..handlers.generic import hal_assert
from ..handlers.generic.malloc import _malloc, _free, malloc, free
from . import fuzz

from binascii import hexlify
import struct

ERR_OK = 0

PBUF_RAM = 0 # /* pbuf data is stored in RAM */
PBUF_ROM = 1 # /* pbuf data is stored in ROM */
PBUF_REF = 2 # /* pbuf comes from the pbuf pool */
PBUF_POOL= 3 # /* pbuf payload refers to RAM */

""" from lwip/pbuf.h
typedef enum {
  PBUF_TRANSPORT,
  PBUF_IP,
  PBUF_LINK,
  PBUF_RAW
} pbuf_layer;

typedef enum {
  PBUF_RAM, /* pbuf data is stored in RAM */
  PBUF_ROM, /* pbuf data is stored in ROM */
  PBUF_REF, /* pbuf comes from the pbuf pool */
  PBUF_POOL /* pbuf payload refers to RAM */
} pbuf_type;


/** indicates this packet's data should be immediately passed to the application */
#define PBUF_FLAG_PUSH      0x01U
/** indicates this is a custom pbuf: pbuf_free and pbuf_header handle such a
    a pbuf differently */
#define PBUF_FLAG_IS_CUSTOM 0x02U
/** indicates this pbuf is UDP multicast to be looped back */
#define PBUF_FLAG_MCASTLOOP 0x04U
/** indicates this pbuf was received as link-level broadcast */
#define PBUF_FLAG_LLBCAST   0x08U
/** indicates this pbuf was received as link-level multicast */
#define PBUF_FLAG_LLMCAST   0x10U
/** indicates this pbuf includes a TCP FIN flag */
#define PBUF_FLAG_TCP_FIN   0x20U

struct pbuf {
  /** next pbuf in singly linked pbuf chain */
  struct pbuf *next;

  /** pointer to the actual data in the buffer */
  void *payload;

  /**
   * total length of this buffer and all next buffers in chain
   * belonging to the same packet.
   *
   * For non-queue packet chains this is the invariant:
   * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
   */
  u16_t tot_len;

  /** length of this buffer */
  u16_t len;

  /** pbuf_type as u8_t instead of enum to save space */
  u8_t /*pbuf_type*/ type;

  /** misc flags */
  u8_t flags;

  /**
   * the reference count always equals the number of pointers
   * that refer to this pbuf. This can be pointers from an application,
   * the stack itself, or pbuf->next pointers from a chain.
   */
  u16_t ref;
};
"""
PBUF_SIZE = 2 * 4 + 2 * 2 + 2 * 1 + 2

"""
/* the TCP protocol control block */
struct tcp_pcb {
/** common PCB members */
  IP_PCB;
/** protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb);

  /* ports are in host byte order */
  u16_t remote_port;
  
  u8_t flags;
#define TF_ACK_DELAY   ((u8_t)0x01U)   /* Delayed ACK. */
#define TF_ACK_NOW     ((u8_t)0x02U)   /* Immediate ACK. */
#define TF_INFR        ((u8_t)0x04U)   /* In fast recovery. */
#define TF_TIMESTAMP   ((u8_t)0x08U)   /* Timestamp option enabled */
#define TF_RXCLOSED    ((u8_t)0x10U)   /* rx closed by tcp_shutdown */
#define TF_FIN         ((u8_t)0x20U)   /* Connection was closed locally (FIN segment enqueued). */
#define TF_NODELAY     ((u8_t)0x40U)   /* Disable Nagle algorithm */
#define TF_NAGLEMEMERR ((u8_t)0x80U)   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */

  /* the rest of the fields are in host byte order
     as we have to do some math with them */

  /* Timers */
  u8_t polltmr, pollinterval;
  u8_t last_timer;
  u32_t tmr;

  /* receiver variables */
  u32_t rcv_nxt;   /* next seqno expected */
  u16_t rcv_wnd;   /* receiver window available */
  u16_t rcv_ann_wnd; /* receiver window to announce */
  u32_t rcv_ann_right_edge; /* announced right edge of window */

  /* Retransmission timer. */
  s16_t rtime;

  u16_t mss;   /* maximum segment size */

  /* RTT (round trip time) estimation variables */
  u32_t rttest; /* RTT estimate in 500ms ticks */
  u32_t rtseq;  /* sequence number being timed */
  s16_t sa, sv; /* @todo document this */

  s16_t rto;    /* retransmission time-out */
  u8_t nrtx;    /* number of retransmissions */

  /* fast retransmit/recovery */
  u8_t dupacks;
  u32_t lastack; /* Highest acknowledged seqno. */

  /* congestion avoidance/control variables */
  u16_t cwnd;
  u16_t ssthresh;

  /* sender variables */
  u32_t snd_nxt;   /* next new seqno to be sent */
  u32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                             window update. */
  u32_t snd_lbb;       /* Sequence number of next byte to be buffered. */
  u16_t snd_wnd;   /* sender window */
  u16_t snd_wnd_max; /* the maximum sender window announced by the remote host */

  u16_t acked;

  u16_t snd_buf;   /* Available buffer space for sending (in bytes). */
#define TCP_SNDQUEUELEN_OVERFLOW (0xffffU-3)
  u16_t snd_queuelen; /* Available buffer space for sending (in tcp_segs). */

#if TCP_OVERSIZE
  /* Extra bytes available at the end of the last pbuf in unsent. */
  u16_t unsent_oversize;
#endif /* TCP_OVERSIZE */ 

  /* These are ordered by sequence number: */
  struct tcp_seg *unsent;   /* Unsent (queued) segments. */
  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */
#if TCP_QUEUE_OOSEQ  
  struct tcp_seg *ooseq;    /* Received out of sequence segments. */
#endif /* TCP_QUEUE_OOSEQ */

  struct pbuf *refused_data; /* Data previously received but not yet taken by upper layer */

#if LWIP_CALLBACK_API
  /* Function to be called when more send buffer space is available. */
  tcp_sent_fn sent;
  /* Function to be called when (in-sequence) data has arrived. */
  tcp_recv_fn recv;
  /* Function to be called when a connection has been set up. */
  tcp_connected_fn connected;
  /* Function which is called periodically. */
  tcp_poll_fn poll;
  /* Function to be called whenever a fatal error occurs. */
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */

#if LWIP_TCP_TIMESTAMPS
  u32_t ts_lastacksent;
  u32_t ts_recent;
#endif /* LWIP_TCP_TIMESTAMPS */

  /* idle time before KEEPALIVE is sent */
  u32_t keep_idle;
#if LWIP_TCP_KEEPALIVE
  u32_t keep_intvl;
  u32_t keep_cnt;
#endif /* LWIP_TCP_KEEPALIVE */
  
  /* Persist timer counter */
  u8_t persist_cnt;
  /* Persist timer back-off */
  u8_t persist_backoff;

  /* KEEPALIVE counter */
  u8_t keep_cnt_sent;
};
"""
PCB_SIZE = 208
OFF_PCB_SNDBUF = 102

def _print_pcb(uc, pcb):
    obj = pcbs[pcb]
    cb_arg_buf = uc.mem_read(obj.cb_arg, 12)
    if debug_enabled:
        print("PCB at 0x{:x}, port: {}, cb_arg: {:x} ({}), accept_cb: {:x}, recv_cb: {:x}".format(pcb, obj.port, obj.cb_arg, hexlify(cb_arg_buf), obj.accept_cb, obj.recv_cb))

def _create_pbuf(uc, contents):
    pbuf = _malloc(uc, PBUF_SIZE)
    next = 0
    # XXX: to be able to fuzz this thing at all we need to work around a bug in httpd (adding 5 for constant sizeof("GET /")) offset into buffer in http_getPageName in httpd.c
    payload = _malloc(uc, len(contents)+5)
    tot_len = len(contents)
    buf_len = len(contents)
    type = PBUF_RAM
    flags = 0  # TODO: implement flags
    ref = 1
    
    # Now write contents to actual memory
    uc.mem_write(pbuf, struct.pack("<IIHHBBH", next, payload, tot_len, buf_len, type, flags, ref))
    uc.mem_write(payload, contents)
    return pbuf

def pbuf_free(uc):
    # TODO: could implement policies for corruptions of other fields
    pbuf = uc.reg_read(UC_ARM_REG_R0)
    payload = struct.unpack("<I", uc.mem_read(pbuf + 4, 4))[0]
    ref = struct.unpack("<H", uc.mem_read(pbuf + PBUF_SIZE - 2, 2))[0]
    if ref == 1:
        _free(uc, payload)
        _free(uc, pbuf)

memp_sizes = [32, 152, 28, 16, 32, 24, 16, 16, 1536]
def memp_free(uc):
    buf = uc.reg_read(UC_ARM_REG_R1)
    uc.reg_write(UC_ARM_REG_R0, buf)
    free(uc)

def memp_malloc(uc):
    type = uc.reg_read(UC_ARM_REG_R0)
    uc.reg_write(UC_ARM_REG_R0, memp_sizes[type])
    malloc(uc)

class PCB():
    cb_arg = 0
    accept_cb = None
    recv_cb = None
    port = None

    def __init__(self):
        pass
        

pcbs = {}

"""
#define          tcp_mss(pcb)             (((pcb)->flags & TF_TIMESTAMP) ? ((pcb)->mss - 12)  : (pcb)->mss)
#define          tcp_sndbuf(pcb)          ((pcb)->snd_buf)
#define          tcp_sndqueuelen(pcb)     ((pcb)->snd_queuelen)
#define          tcp_nagle_disable(pcb)   ((pcb)->flags |= TF_NODELAY)
#define          tcp_nagle_enable(pcb)    ((pcb)->flags &= ~TF_NODELAY)
#define          tcp_nagle_disabled(pcb)  (((pcb)->flags & TF_NODELAY) != 0)
"""
# here a buffer has to be allocated by LWIP.
# We can just pass this one to the actual function for now
def tcp_new(uc):
    obj = _malloc(uc, PCB_SIZE)
    uc.mem_write(obj+OFF_PCB_SNDBUF, b"\xff\xff") # for now, set a very high snd_buf length
    pcbs[obj] = PCB()
    uc.reg_write(UC_ARM_REG_R0, obj)

def tcp_bind(uc):
    pcb = uc.reg_read(UC_ARM_REG_R0)
    port = uc.reg_read(UC_ARM_REG_R2)
    assert(pcb in pcbs)
    pcbs[pcb].port = port

def tcp_listen(uc):
    pcb = uc.reg_read(UC_ARM_REG_R0)
    TCP.listen(pcbs[pcb].port)

def tcp_listen_with_backlog(uc):
    tcp_listen(uc)

def tcp_accept(uc):
    pcb = uc.reg_read(UC_ARM_REG_R0)
    callback = uc.reg_read(UC_ARM_REG_R1)
    hal_assert(uc, "lwip pcb structure not initialized before accept", pcb in pcbs)
    pcbs[pcb].accept_cb = callback
    
    if debug_enabled:
        print("### tcp_accept called. pcb: {}, callback: {}".format(pcb, callback))
    # as we emulate the connection instantly being established
    _invoke_accept_cb(uc)

def _invoke_accept_cb(uc, pcb=None):
    if pcb is None:
        pcb = list(pcbs.keys())[0]
    # static err_t http_accept(void *arg, struct tcp_pcb *pcb, err_t err)
    uc.reg_write(UC_ARM_REG_R0, pcbs[pcb].cb_arg)
    uc.reg_write(UC_ARM_REG_R1, pcb)
    uc.reg_write(UC_ARM_REG_R2, 0)
    uc.reg_write(UC_ARM_REG_PC, pcbs[pcb].accept_cb)

def _invoke_recv_cb(uc, pcb=None):
    if pcb is None:
        pcb = list(pcbs.keys())[0]
    
    if debug_enabled:
        print("### using pcb for recv callback: {}, pcb: {}".format(pcb, pcbs[pcb]))
    _print_pcb(uc, pcb)
    
    # static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
    
    uc.reg_write(UC_ARM_REG_R0, pcbs[pcb].cb_arg)
    uc.reg_write(UC_ARM_REG_R1, pcb)
    # XXX: todo: pbuf struct
    pbuf = _create_pbuf(uc, fuzz.get_fuzz(fuzz.fuzz_remaining()))
    uc.reg_write(UC_ARM_REG_R2, pbuf)
    uc.reg_write(UC_ARM_REG_R3, 0)

    uc.reg_write(UC_ARM_REG_PC, pcbs[pcb].recv_cb)
    
    if debug_enabled:
        print("Calling recv callback with arguments: r0={:x}, r1: {:x}, r2: {:x}, r3: {:x}".format(
            uc.reg_read(UC_ARM_REG_R0),
            uc.reg_read(UC_ARM_REG_R1),
            uc.reg_read(UC_ARM_REG_R2),
            uc.reg_read(UC_ARM_REG_R3)
        ))

def tcp_setprio(uc):
    pass

def tcp_arg(uc):
    pcb = uc.reg_read(UC_ARM_REG_R0)
    callback_arg = uc.reg_read(UC_ARM_REG_R1)
    hal_assert(uc, "lwip pcb structure not known when tcp_arg is called", pcb in pcbs)
    if debug_enabled:
        print("### Setting tcp_arg to {:x}".format(callback_arg))
    pcbs[pcb].cb_arg = callback_arg

def tcp_recv(uc):
    """
    Sets the user callback for an incoming packet
    """
    pcb = uc.reg_read(UC_ARM_REG_R0)
    callback = uc.reg_read(UC_ARM_REG_R1)
    hal_assert(uc, "lwip pcb structure not known when tcp_recv is called", pcb in pcbs)
    if debug_enabled:
        print("### Setting tcp_recv callback: {}".format(callback))
    pcbs[pcb].recv_cb = callback

# err_t tcp_close(struct tcp_pcb *pcb)
def tcp_close(uc):
    _free(uc, uc.reg_read(UC_ARM_REG_R0))
    uc.reg_write(ERR_OK)

def tcp_err(uc):
    pass

def tcp_poll(uc):
    pass

def tcp_recved(uc):
    if debug_enabled:
        print("### tcp_recved called")

# err_t tcp_write(struct tcp_pcb *pcb, const void *arg, u16_t len, u8_t apiflags)
def tcp_write(uc):
    buf = uc.reg_read(UC_ARM_REG_R1)
    length = uc.reg_read(UC_ARM_REG_R2)
    contents = uc.mem_read(buf, length)
    print("### tcp_write: {}".format(contents))

def tick(uc):
    if debug_enabled:
        print("-------------------- Ticking, got pcbs: {}".format(pcbs))
    """
    Tick to ask for an incoming TCP packet. Here
    a lot of the magic happens:
    We need to call the recv callback with the expected
    arguments
    """
    _invoke_recv_cb(uc)


def tcp_next_iss_hack(uc):
    uc.reg_write(UC_ARM_REG_R0, 0)


def inet_cksum(uc):
    uc.reg_write(UC_ARM_REG_R0, 0)
