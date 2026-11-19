/* SPDX-License-Identifier: MIT */
/* UNPA report: samples per-domain BPF maps, keeps flow history, renders a
 * TUI / plain text / JSON view. Contract: report.h.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "report.h"
#include "unpa.h"

#ifndef UNPA_VERSION
#define UNPA_VERSION "0.6.2.1"
#endif

#define CAP_FLOWS_DEFAULT 16384u
#define SPARK_N 60
#define BATCH 512
#define MAXC 14
#define CELL 192
#define TL_MIN 1440 /* per-minute timeline: 24 hours */
#define CH 18 /* classic per-connection history width */
#define MAX_FILTERS 1024

enum { V_CLASSIC, V_LIVE, V_HIST, V_IFACE, V_NS, V_COUNT };
enum { S_RATE, S_BYTES, S_PKTS, S_LAST, S_COUNT };

struct fent {
	struct fent *next;
	unsigned idx;
	unsigned stamp;
	int domain;
	bool hidden; /* baseline-only "ghost": not yet seen with traffic */
	struct flow_key key;
	double first_seen, last_seen;
	__u64 created_ns, last_pkts, last_bytes;
	__u64 total_pkts, total_bytes, dpk, dby;
	double pps, bps;
	struct fent *peer; /* same conversation, opposite direction */
	float *h;	   /* CH-slot rate history, only while recently active */
	unsigned char zeros;
	bool logged;
};

struct link {
	int domain;
	unsigned ifindex;
	int dir;
	char name[48], label[64];
	bool gone;
	__u64 pk, by, unp, err, cre;
	__u64 dpk, dby, dunp, derr, dcre;
	double pps, bps;
	float hist[SPARK_N];
	unsigned hhead, hcount;
};

struct domain {
	char name[64];
	int ffd, lfd;
	bool gone;
	unsigned entries, nactive, nhist, nlinks, cap;
};

struct filter {
	int family, plen;
	bool exclude;
	__u8 addr[16];
};

struct sb {
	char *p;
	size_t len, cap;
	bool oom;
};

struct rowref {
	double key, last;
	unsigned idx;
};

struct col {
	const char *title;
	int w, minw, maxw, drop;
	bool right, on;
};

struct tbl {
	struct col c[MAXC];
	int n;
};

struct ln {
	struct sb *sb;
	int col, cols;
	bool color, plain;
};

struct report {
	size_t limit;
	bool json, tui, color, paused, help;
	size_t hlimit;
	double idle;
	struct domain *dom;
	size_t ndom, capdom;
	struct link *lnk;
	size_t nlnk, caplnk;
	struct filter *flt;
	size_t nflt, capflt;
	bool has_include;
	struct fent **ents, **bucket;
	size_t nent, capent, nbucket;
	struct rowref *rows;
	size_t caprows;
	struct flow_key *bkeys;
	struct counters *bvals;
	unsigned tick;
	double start, now;
	__u64 fence_ns, fence_pending, tick_ns;
	/* tally */
	__u64 tx_by, rx_by, tx_pk, rx_pk, unp_total;
	double tx_bps, rx_bps, tx_pps, rx_pps, peak_tx, peak_rx;
	float txh[SPARK_N], rxh[SPARK_N];
	unsigned hh_head, hh_count;
	size_t nactive, nhist, dropped;
	double peak_total;
	/* long-term timeline (per minute), optional flow log */
	__u64 tl_tx[TL_MIN], tl_rx[TL_MIN];
	long tl_min;
	FILE *log;
	double wall0;
	bool grouped, expanded;
	size_t cl_lines;
	/* ui */
	int view, sort;
	bool reverse;
	size_t scroll, page;
	double maxbps;
	char pend[32];
	size_t npend;
	struct sb out;
};

/* ---------- terminal state (restored by destroy or atexit) ---------- */
static struct {
	bool active, atexit_set;
	struct termios saved;
	bool have_termios;
} g_term;

static void term_restore(void)
{
	static const char s[] = "\x1b[0m\x1b[?25h\x1b[?7h\x1b[?1049l";
	if (!g_term.active)
		return;
	g_term.active = false;
	if (g_term.have_termios)
		(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_term.saved);
	g_term.have_termios = false;
	if (write(STDOUT_FILENO, s, sizeof(s) - 1) < 0) {
		/* nothing sensible to do */
	}
}

/* ---------- helpers ---------- */
static double mono_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static __u64 mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + (__u64)ts.tv_nsec;
}

static void *grow(void *p, size_t *cap, size_t need, size_t esz)
{
	size_t nc;
	void *n;

	if (need <= *cap)
		return p;
	nc = *cap ? *cap : 8;
	while (nc < need)
		nc *= 2;
	n = realloc(p, nc * esz);
	if (!n)
		return NULL;
	*cap = nc;
	return n;
}

static void sb_put(struct sb *b, const char *s, size_t n)
{
	if (b->oom)
		return;
	if (b->len + n + 1 > b->cap) {
		size_t nc = b->cap ? b->cap : 4096;
		char *np;

		while (nc < b->len + n + 1)
			nc *= 2;
		np = realloc(b->p, nc);
		if (!np) {
			b->oom = true;
			return;
		}
		b->p = np;
		b->cap = nc;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = 0;
}

static void sb_puts(struct sb *b, const char *s)
{
	sb_put(b, s, strlen(s));
}

static void sb_printf(struct sb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_printf(struct sb *b, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n < sizeof(tmp)) {
		sb_put(b, tmp, (size_t)n);
		return;
	}
	{
		char *big = malloc((size_t)n + 1);

		if (!big) {
			b->oom = true;
			return;
		}
		va_start(ap, fmt);
		vsnprintf(big, (size_t)n + 1, fmt, ap);
		va_end(ap);
		sb_put(b, big, (size_t)n);
		free(big);
	}
}

/* Length of the valid, printable UTF-8 sequence at s (0 if invalid/control). */
static int u8len(const unsigned char *s)
{
	unsigned c = s[0], cp;
	int n, i;

	if (c < 0x20 || c == 0x7f)
		return 0;
	if (c < 0x80)
		return 1;
	if (c >= 0xC2 && c <= 0xDF) {
		n = 2;
		cp = c & 0x1f;
	} else if ((c & 0xF0) == 0xE0) {
		n = 3;
		cp = c & 0x0f;
	} else if (c >= 0xF0 && c <= 0xF4) {
		n = 4;
		cp = c & 0x07;
	} else {
		return 0;
	}
	for (i = 1; i < n; i++) {
		if ((s[i] & 0xC0) != 0x80)
			return 0;
		cp = (cp << 6) | (s[i] & 0x3f);
	}
	if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
	    (cp >= 0xD800 && cp <= 0xDFFF) || cp < 0xA0)
		return (c < 0x80) ? 1 : 0;
	return n;
}

static size_t ucount(const char *s)
{
	size_t n = 0;

	for (; *s; s++)
		if (((unsigned char)*s & 0xC0) != 0x80)
			n++;
	return n;
}

/* Copy src to dst replacing control/invalid bytes by '?'. */
static void clean(char *dst, size_t sz, const char *src)
{
	size_t o = 0;

	if (!sz)
		return;
	while (*src && o + 5 < sz) {
		int n = u8len((const unsigned char *)src);

		if (!n) {
			dst[o++] = '?';
			src++;
			continue;
		}
		memcpy(dst + o, src, (size_t)n);
		o += (size_t)n;
		src += n;
	}
	dst[o] = 0;
}

/* ---------- human formatting ---------- */
static void fmt_bytes(char *b, size_t sz, double v)
{
	static const char *u[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
	int i = 0;

	while (v >= 1024.0 && i < 5) {
		v /= 1024.0;
		i++;
	}
	if (i == 0)
		snprintf(b, sz, "%.0f B", v);
	else
		snprintf(b, sz, "%.1f %s", v, u[i]);
}

static void fmt_rate(char *b, size_t sz, double v)
{
	static const char *u[] = { "B/s", "KB/s", "MB/s", "GB/s", "TB/s" };
	int i = 0;

	while (v >= 1000.0 && i < 4) {
		v /= 1000.0;
		i++;
	}
	if (i == 0)
		snprintf(b, sz, "%.0f %s", v, u[i]);
	else
		snprintf(b, sz, "%.1f %s", v, u[i]);
}

static void fmt_count(char *b, size_t sz, double v)
{
	static const char *u[] = { "", "k", "M", "G", "T" };
	int i = 0;

	while (v >= 1000.0 && i < 4) {
		v /= 1000.0;
		i++;
	}
	if (i == 0)
		snprintf(b, sz, "%.0f", v);
	else
		snprintf(b, sz, "%.1f%s", v, u[i]);
}

static void fmt_dur(char *b, size_t sz, double s)
{
	unsigned long t = s > 0 ? (unsigned long)s : 0;

	if (t < 60)
		snprintf(b, sz, "%lus", t);
	else if (t < 3600)
		snprintf(b, sz, "%lum%02lus", t / 60, t % 60);
	else if (t < 86400)
		snprintf(b, sz, "%luh%02lum", t / 3600, (t % 3600) / 60);
	else
		snprintf(b, sz, "%lud%02luh", t / 86400, (t % 86400) / 3600);
}

static void fmt_ago(char *b, size_t sz, double s)
{
	unsigned long t = s > 0 ? (unsigned long)s : 0;

	if (t < 60)
		snprintf(b, sz, "%lus ago", t);
	else if (t < 3600)
		snprintf(b, sz, "%lum ago", t / 60);
	else if (t < 86400)
		snprintf(b, sz, "%luh ago", t / 3600);
	else
		snprintf(b, sz, "%lud ago", t / 86400);
}

static const char *dir_name(int d)
{
	return d == UNPA_GUEST_TX ? "TX" : "RX";
}

static void fmt_proto(char *b, size_t sz, unsigned p)
{
	switch (p) {
	case 6: snprintf(b, sz, "TCP"); break;
	case 17: snprintf(b, sz, "UDP"); break;
	case 1: snprintf(b, sz, "ICMP"); break;
	case 58: snprintf(b, sz, "ICMP6"); break;
	default: snprintf(b, sz, "%u", p);
	}
}

static void fmt_addr(char *b, size_t sz, const struct flow_key *k, const __u8 *a, unsigned port)
{
	char ip[INET6_ADDRSTRLEN] = "?";

	if (k->family == 4)
		inet_ntop(AF_INET, a, ip, sizeof(ip));
	else
		inet_ntop(AF_INET6, a, ip, sizeof(ip));
	if (k->family == 6 && port)
		snprintf(b, sz, "[%s]:%u", ip, port);
	else if (k->family == 6)
		snprintf(b, sz, "%s", ip);
	else if (port)
		snprintf(b, sz, "%s:%u", ip, port);
	else
		snprintf(b, sz, "%s", ip);
}

/* ---------- filters ---------- */
static int parse_filter(const char *s, struct filter *f)
{
	char tmp[96];
	const char *slash;
	char *end;
	size_t n;
	int maxp;

	if (!s || !*s)
		return -EINVAL;
	slash = strchr(s, '/');
	n = slash ? (size_t)(slash - s) : strlen(s);
	if (n == 0 || n >= sizeof(tmp))
		return -EINVAL;
	memcpy(tmp, s, n);
	tmp[n] = 0;
	memset(f->addr, 0, sizeof(f->addr));
	if (inet_pton(AF_INET, tmp, f->addr) == 1) {
		f->family = 4;
		maxp = 32;
	} else if (inet_pton(AF_INET6, tmp, f->addr) == 1) {
		f->family = 6;
		maxp = 128;
	} else {
		return -EINVAL;
	}
	f->plen = maxp;
	if (slash) {
		long v;

		if (!slash[1])
			return -EINVAL;
		errno = 0;
		v = strtol(slash + 1, &end, 10);
		if (errno || *end || v < 0 || v > maxp)
			return -EINVAL;
		f->plen = (int)v;
	}
	return 0;
}

static bool filter_hit(const struct filter *f, const __u8 *a, int fam)
{
	int full, rem;

	if (f->family != fam)
		return false;
	full = f->plen / 8;
	rem = f->plen % 8;
	if (full && memcmp(f->addr, a, (size_t)full))
		return false;
	if (rem) {
		unsigned m = (0xffu << (8 - rem)) & 0xffu;

		if ((f->addr[full] & m) != (a[full] & m))
			return false;
	}
	return true;
}

int report_validate_filter(const char *s)
{
	struct filter f;

	return parse_filter(s, &f);
}

int report_add_filter(struct report *r, const char *s, bool exclude)
{
	struct filter f;
	void *n;
	int e = parse_filter(s, &f);

	if (e)
		return e;
	if (r->nflt >= MAX_FILTERS)
		return -ENOSPC;
	n = grow(r->flt, &r->capflt, r->nflt + 1, sizeof(*r->flt));
	if (!n)
		return -ENOMEM;
	r->flt = n;
	f.exclude = exclude;
	r->flt[r->nflt++] = f;
	if (!exclude)
		r->has_include = true;
	return 0;
}

static bool flow_allowed(const struct report *r, const struct flow_key *k)
{
	bool inc = !r->has_include;
	size_t i;

	for (i = 0; i < r->nflt; i++) {
		const struct filter *f = &r->flt[i];
		bool hit = filter_hit(f, k->src, k->family) || filter_hit(f, k->dst, k->family);

		if (!hit)
			continue;
		if (f->exclude)
			return false;
		inc = true;
	}
	return inc;
}

/* ---------- flow history table ---------- */
static bool ent_active(const struct report *r, const struct fent *e)
{
	return !e->hidden && r->now - e->last_seen <= r->idle;
}

static uint32_t fhash(int dom, const struct flow_key *k)
{
	const unsigned char *p = (const unsigned char *)k;
	uint32_t h = 2166136261u ^ (uint32_t)dom * 16777619u;
	size_t i;

	for (i = 0; i < sizeof(*k); i++)
		h = (h ^ p[i]) * 16777619u;
	return h ^ (h >> 15);
}

static struct fent *fent_find(const struct report *r, int dom, const struct flow_key *k)
{
	struct fent *e = r->bucket[fhash(dom, k) & (r->nbucket - 1)];

	for (; e; e = e->next)
		if (e->domain == dom && !memcmp(&e->key, k, sizeof(*k)))
			return e;
	return NULL;
}

static void fent_remove(struct report *r, struct fent *e)
{
	struct fent **pp = &r->bucket[fhash(e->domain, &e->key) & (r->nbucket - 1)];
	struct fent *last;

	while (*pp && *pp != e)
		pp = &(*pp)->next;
	if (*pp)
		*pp = e->next;
	if (e->peer)
		e->peer->peer = NULL;
	free(e->h);
	last = r->ents[--r->nent];
	if (last != e) {
		r->ents[e->idx] = last;
		last->idx = e->idx;
	}
	free(e);
}

static int cmp_asc(const void *a, const void *b)
{
	const struct rowref *x = a, *y = b;

	if (x->key != y->key)
		return x->key < y->key ? -1 : 1;
	if (x->last != y->last)
		return x->last < y->last ? -1 : 1;
	return x->idx < y->idx ? -1 : x->idx > y->idx;
}

static int rows_reserve(struct report *r, size_t n)
{
	void *p = grow(r->rows, &r->caprows, n, sizeof(*r->rows));

	if (!p)
		return -ENOMEM;
	r->rows = p;
	return 0;
}

/* Drop the least recently active entries (ghosts, then inactive, then active). */
static void evict_some(struct report *r)
{
	size_t k = r->hlimit / 32, i, worst = 0;
	struct fent **victims = NULL;

	if (!k)
		k = 1;
	if (k > r->nent)
		k = r->nent;
	if (!r->nent)
		return;
	if (k > 1 && rows_reserve(r, r->nent) == 0)
		victims = malloc(k * sizeof(*victims));
	if (!victims) {
		double wk = 1e300, wl = 1e300;

		for (i = 0; i < r->nent; i++) {
			const struct fent *e = r->ents[i];
			double c = e->hidden ? 0 : ent_active(r, e) ? 2 : 1;

			if (c < wk || (c == wk && e->last_seen < wl)) {
				wk = c;
				wl = e->last_seen;
				worst = i;
			}
		}
		if (!r->ents[worst]->hidden)
			r->fence_pending = r->tick_ns;
		fent_remove(r, r->ents[worst]);
		return;
	}
	for (i = 0; i < r->nent; i++) {
		const struct fent *e = r->ents[i];

		r->rows[i].key = e->hidden ? 0 : ent_active(r, e) ? 2 : 1;
		r->rows[i].last = e->last_seen;
		r->rows[i].idx = (unsigned)i;
	}
	qsort(r->rows, r->nent, sizeof(*r->rows), cmp_asc);
	for (i = 0; i < k; i++)
		victims[i] = r->ents[r->rows[i].idx];
	for (i = 0; i < k; i++) {
		if (!victims[i]->hidden)
			r->fence_pending = r->tick_ns;
		fent_remove(r, victims[i]);
	}
	free(victims);
}

static int buckets_grow(struct report *r)
{
	size_t nb = r->nbucket * 2, i;
	struct fent **b = calloc(nb, sizeof(*b));

	if (!b)
		return -ENOMEM;
	for (i = 0; i < r->nent; i++) {
		struct fent *e = r->ents[i];
		struct fent **slot = &b[fhash(e->domain, &e->key) & (nb - 1)];

		e->next = *slot;
		*slot = e;
	}
	free(r->bucket);
	r->bucket = b;
	r->nbucket = nb;
	return 0;
}

/* Entries are kept for the whole run: eviction only happens when the user
 * set an explicit --history cap. Allocation failure drops new flows (counted
 * in r->dropped and shown in the UI) instead of aborting a long capture.
 */
static struct fent *fent_add(struct report *r, int dom, const struct flow_key *k)
{
	struct fent *e;
	void *p;

	if (r->hlimit && r->nent >= r->hlimit)
		evict_some(r);
	if (r->nent >= r->nbucket && buckets_grow(r))
		return NULL;
	p = grow(r->ents, &r->capent, r->nent + 1, sizeof(*r->ents));
	if (!p)
		return NULL;
	r->ents = p;
	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;
	e->domain = dom;
	e->key = *k;
	e->idx = (unsigned)r->nent;
	r->ents[r->nent++] = e;
	{
		struct fent **b = &r->bucket[fhash(dom, k) & (r->nbucket - 1)];
		struct flow_key rk = *k;
		struct fent *peer;

		e->next = *b;
		*b = e;
		/* Link the opposite direction of the same conversation. */
		rk.direction ^= 1;
		rk.sport = k->dport;
		rk.dport = k->sport;
		memcpy(rk.src, k->dst, sizeof(rk.src));
		memcpy(rk.dst, k->src, sizeof(rk.dst));
		peer = fent_find(r, dom, &rk);
		if (peer && peer != e && !peer->peer) {
			e->peer = peer;
			peer->peer = e;
		}
	}
	return e;
}

static void history_clear(struct report *r)
{
	size_t i;

	for (i = 0; i < r->nent; i++) {
		free(r->ents[i]->h);
		free(r->ents[i]);
	}
	r->nent = 0;
	memset(r->bucket, 0, r->nbucket * sizeof(*r->bucket));
	r->fence_ns = mono_ns();
	r->scroll = 0;
}

/* ---------- lifecycle ---------- */
struct report *report_create(size_t limit, bool json, size_t history_limit, double idle_seconds)
{
	struct report *r = calloc(1, sizeof(*r));
	size_t nb = 1024;

	if (!r)
		return NULL;
	r->limit = limit;
	r->json = json;
	r->hlimit = history_limit; /* 0 = keep every flow for the whole run */
	r->idle = idle_seconds > 0 ? idle_seconds : 5.0;
	r->color = !getenv("NO_COLOR");
	while (nb < r->hlimit * 2 && nb < (1u << 26))
		nb *= 2;
	r->nbucket = nb;
	r->bucket = calloc(nb, sizeof(*r->bucket));
	r->bkeys = malloc(BATCH * sizeof(*r->bkeys));
	r->bvals = malloc(BATCH * sizeof(*r->bvals));
	if (!r->bucket || !r->bkeys || !r->bvals) {
		free(r->bucket);
		free(r->bkeys);
		free(r->bvals);
		free(r);
		errno = ENOMEM;
		return NULL;
	}
	r->sort = S_BYTES;
	r->grouped = true;
	{
		struct timespec ts;

		clock_gettime(CLOCK_REALTIME, &ts);
		r->wall0 = (double)ts.tv_sec + ts.tv_nsec / 1e9;
	}
	r->start = r->now = mono_s();
	r->tick_ns = mono_ns();
	r->tick = 0;
	return r;
}

static void log_flow(struct report *r, const struct fent *e);

void report_destroy(struct report *r)
{
	size_t i;

	if (!r)
		return;
	if (r->tui)
		term_restore();
	r->tui = false;
	if (r->log) {
		for (i = 0; i < r->nent; i++)
			if (!r->ents[i]->hidden && !r->ents[i]->logged)
				log_flow(r, r->ents[i]);
		fclose(r->log);
		r->log = NULL;
	}
	for (i = 0; i < r->nent; i++) {
		free(r->ents[i]->h);
		free(r->ents[i]);
	}
	free(r->ents);
	free(r->bucket);
	free(r->rows);
	free(r->bkeys);
	free(r->bvals);
	free(r->dom);
	free(r->lnk);
	free(r->flt);
	free(r->out.p);
	free(r);
}

bool report_terminal_enter(struct report *r)
{
	struct termios t;

	if (r->tui)
		return true;
	if (r->json || !isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
		return false;
	if (tcgetattr(STDIN_FILENO, &g_term.saved) < 0)
		return false;
	t = g_term.saved;
	t.c_lflag &= ~(tcflag_t)(ICANON | ECHO | ISIG | IEXTEN);
	t.c_iflag &= ~(tcflag_t)(IXON | ICRNL);
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) < 0)
		return false;
	g_term.have_termios = true;
	g_term.active = true;
	if (!g_term.atexit_set) {
		g_term.atexit_set = true;
		atexit(term_restore);
	}
	if (write(STDOUT_FILENO, "\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[2J", 23) < 0) {
		term_restore();
		return false;
	}
	r->tui = true;
	return true;
}

bool report_tui_active(const struct report *r)
{
	return r->tui;
}

/* ---------- domains and links ---------- */
int report_add_domain(struct report *r, const char *nsname, int flows_fd, int links_fd)
{
	void *p = grow(r->dom, &r->capdom, r->ndom + 1, sizeof(*r->dom));
	struct domain *d;

	if (!p)
		return -ENOMEM;
	r->dom = p;
	d = &r->dom[r->ndom];
	memset(d, 0, sizeof(*d));
	clean(d->name, sizeof(d->name), nsname && *nsname ? nsname : "host");
	d->ffd = flows_fd;
	d->lfd = links_fd;
	d->cap = CAP_FLOWS_DEFAULT;
	{
		struct bpf_map_info mi;
		__u32 len = sizeof(mi);

		memset(&mi, 0, sizeof(mi));
		if (bpf_obj_get_info_by_fd(flows_fd, &mi, &len) == 0 && mi.max_entries)
			d->cap = mi.max_entries;
	}
	return (int)r->ndom++;
}

static struct link *link_find(struct report *r, int dom, unsigned ifindex, int dir)
{
	size_t i;

	for (i = 0; i < r->nlnk; i++) {
		struct link *l = &r->lnk[i];

		if (l->domain == dom && l->ifindex == ifindex && l->dir == dir)
			return l;
	}
	return NULL;
}

int report_add_link(struct report *r, int domain, const char *ifname, unsigned int ifindex,
		    const char *label)
{
	void *p;
	int dir;

	if (domain < 0 || (size_t)domain >= r->ndom)
		return -EINVAL;
	if (link_find(r, domain, ifindex, 0)) {
		for (dir = 0; dir < 2; dir++) {
			struct link *l = link_find(r, domain, ifindex, dir);

			if (l && label)
				clean(l->label, sizeof(l->label), label);
		}
		return 0;
	}
	p = grow(r->lnk, &r->caplnk, r->nlnk + 2, sizeof(*r->lnk));
	if (!p)
		return -ENOMEM;
	r->lnk = p;
	for (dir = 0; dir < 2; dir++) {
		struct link *l = &r->lnk[r->nlnk++];

		memset(l, 0, sizeof(*l));
		l->domain = domain;
		l->ifindex = ifindex;
		l->dir = dir == 0 ? UNPA_GUEST_TX : UNPA_GUEST_RX;
		if (ifname && *ifname)
			clean(l->name, sizeof(l->name), ifname);
		else
			snprintf(l->name, sizeof(l->name), "if%u", ifindex);
		if (label)
			clean(l->label, sizeof(l->label), label);
	}
	r->dom[domain].nlinks++;
	return 0;
}

void report_link_gone(struct report *r, int domain, unsigned int ifindex)
{
	size_t i;

	for (i = 0; i < r->nlnk; i++)
		if (r->lnk[i].domain == domain && r->lnk[i].ifindex == ifindex)
			r->lnk[i].gone = true;
}

void report_domain_gone(struct report *r, int domain)
{
	size_t i;

	if (domain < 0 || (size_t)domain >= r->ndom)
		return;
	r->dom[domain].gone = true;
	r->dom[domain].entries = 0;
	for (i = 0; i < r->nlnk; i++)
		if (r->lnk[i].domain == domain)
			r->lnk[i].gone = true;
}

/* ---------- sampling ---------- */
static __u64 delta64(__u64 cur, __u64 prev)
{
	return cur >= prev ? cur - prev : cur;
}

static void push_hist(float *h, unsigned *head, unsigned *count, double v)
{
	h[*head] = (float)v;
	*head = (*head + 1) % SPARK_N;
	if (*count < SPARK_N)
		(*count)++;
}

static void sample_links(struct report *r, int di, double secs)
{
	size_t i;

	for (i = 0; i < r->nlnk; i++) {
		struct link *l = &r->lnk[i];
		struct link_key lk;
		struct link_counters lc;

		if (l->domain != di || l->gone)
			continue;
		memset(&lk, 0, sizeof(lk));
		lk.ifindex = l->ifindex;
		lk.direction = (__u8)l->dir;
		if (bpf_map_lookup_elem(r->dom[di].lfd, &lk, &lc) != 0)
			continue;
		l->dpk = delta64(lc.packets, l->pk);
		l->dby = delta64(lc.bytes, l->by);
		l->dunp = delta64(lc.unparsed, l->unp);
		l->derr = delta64(lc.flow_errors, l->err);
		l->dcre = delta64(lc.flow_creates, l->cre);
		l->pk = lc.packets;
		l->by = lc.bytes;
		l->unp = lc.unparsed;
		l->err = lc.flow_errors;
		l->cre = lc.flow_creates;
		l->pps = (double)l->dpk / secs;
		l->bps = (double)l->dby / secs;
		push_hist(l->hist, &l->hhead, &l->hcount, l->bps);
	}
}

static int process_flow(struct report *r, int di, const struct flow_key *k,
			const struct counters *v)
{
	struct fent *e;
	__u64 dp, db;

	if (!flow_allowed(r, k))
		return 0;
	e = fent_find(r, di, k);
	if (e) {
		if (e->stamp == r->tick)
			return 0;
		e->stamp = r->tick;
		if (v->created_ns != e->created_ns) {
			dp = v->packets;
			db = v->bytes;
			e->created_ns = v->created_ns;
		} else {
			dp = delta64(v->packets, e->last_pkts);
			db = delta64(v->bytes, e->last_bytes);
		}
		e->last_pkts = v->packets;
		e->last_bytes = v->bytes;
		if (dp || db) {
			if (e->hidden) {
				e->hidden = false;
				e->first_seen = r->now;
			}
			e->total_pkts += dp;
			e->total_bytes += db;
			e->dpk = dp;
			e->dby = db;
			e->last_seen = r->now;
		}
		return 0;
	}
	e = fent_add(r, di, k);
	if (!e) {
		r->dropped++;
		return 0;
	}
	e->stamp = r->tick;
	e->created_ns = v->created_ns;
	e->last_pkts = v->packets;
	e->last_bytes = v->bytes;
	e->first_seen = e->last_seen = r->now;
	if (v->created_ns < r->fence_ns) {
		e->hidden = true; /* known before a clear/eviction: baseline only */
	} else {
		e->total_pkts = e->dpk = v->packets;
		e->total_bytes = e->dby = v->bytes;
	}
	return 0;
}

static int sample_flows(struct report *r, int di)
{
	int fd = r->dom[di].ffd;
	size_t CAP_FLOWS = r->dom[di].cap;
	__u64 token[2] = { 0, 0 };
	size_t seen = 0, iter;
	bool first = true, fallback = false;
	int err = 0;

	for (iter = 0; iter < 2 * (CAP_FLOWS / BATCH) + 8 && seen < 2 * CAP_FLOWS; iter++) {
		__u32 cnt = BATCH, i;
		int rc, e;
		LIBBPF_OPTS(bpf_map_batch_opts, opts);

		errno = 0;
		rc = bpf_map_lookup_batch(fd, first ? NULL : token, token, r->bkeys, r->bvals, &cnt,
					  &opts);
		e = rc ? (errno ? errno : -rc) : 0;
		if (e && e != ENOENT && cnt == 0) {
			fallback = true;
			break;
		}
		if (cnt > BATCH)
			cnt = BATCH;
		for (i = 0; i < cnt; i++) {
			int pe = process_flow(r, di, &r->bkeys[i], &r->bvals[i]);

			if (pe)
				err = pe;
		}
		seen += cnt;
		first = false;
		if (e)
			break; /* ENOENT: complete; other errors: partial, stamps protect re-reads */
	}
	if (fallback && seen == 0) {
		struct flow_key k, nk;
		struct counters v;
		bool have = false;
		size_t steps;

		memset(&k, 0, sizeof(k));
		for (steps = 0; steps < 2 * CAP_FLOWS; steps++) {
			if (bpf_map_get_next_key(fd, have ? &k : NULL, &nk) != 0)
				break;
			k = nk;
			have = true;
			if (bpf_map_lookup_elem(fd, &k, &v) != 0)
				continue;
			if (process_flow(r, di, &k, &v))
				err = -ENOMEM;
			seen++;
		}
	}
	r->dom[di].entries = seen > CAP_FLOWS ? (unsigned)CAP_FLOWS : (unsigned)seen;
	return err;
}

static void iflabel(char *b, size_t sz, struct report *r, int dom, unsigned ifindex);

static void log_esc(char *dst, size_t sz, const char *src)
{
	size_t i = 0;

	for (; *src && i + 1 < sz; src++)
		dst[i++] = (*src == '"' || *src == '\\' || (unsigned char)*src < 0x20) ? '_' : *src;
	dst[i] = 0;
}

/* One JSON line per flow direction when it goes idle (and at exit): an
 * append-only record for long-term analysis.
 */
static void log_flow(struct report *r, const struct fent *e)
{
	char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN], ifn[96], ifc[96], ns[96], nsc[96];
	int fam = e->key.family == 6 ? AF_INET6 : AF_INET;

	if (!r->log)
		return;
	inet_ntop(fam, e->key.src, s, sizeof(s));
	inet_ntop(fam, e->key.dst, d, sizeof(d));
	iflabel(ifn, sizeof(ifn), r, e->domain, e->key.ifindex);
	log_esc(ifc, sizeof(ifc), ifn);
	log_esc(nsc, sizeof(nsc), r->dom[e->domain].name);
	(void)ns;
	fprintf(r->log,
		"{\"first\":%.3f,\"last\":%.3f,\"ns\":\"%s\",\"iface\":\"%s\",\"dir\":\"%s\",\"family\":%u,\"proto\":%u,\"src\":\"%s\",\"sport\":%u,\"dst\":\"%s\",\"dport\":%u,\"packets\":%llu,\"bytes\":%llu}\n",
		r->wall0 + (e->first_seen - r->start), r->wall0 + (e->last_seen - r->start), nsc, ifc,
		e->key.direction == UNPA_GUEST_TX ? "TX" : "RX", e->key.family, e->key.proto, s,
		e->key.sport, d, e->key.dport, (unsigned long long)e->total_pkts,
		(unsigned long long)e->total_bytes);
}

int report_set_log(struct report *r, const char *path)
{
	if (!r || !path)
		return -EINVAL;
	r->log = fopen(path, "a");
	if (!r->log)
		return -errno;
	setvbuf(r->log, NULL, _IOLBF, 0);
	return 0;
}

static void compute_tally(struct report *r, double secs)
{
	__u64 txd = 0, rxd = 0;

	size_t i;

	r->tx_by = r->rx_by = r->tx_pk = r->rx_pk = r->unp_total = 0;
	r->tx_bps = r->rx_bps = r->tx_pps = r->rx_pps = 0;
	for (i = 0; i < r->nlnk; i++) {
		const struct link *l = &r->lnk[i];

		r->unp_total += l->unp;
		if (l->dir == UNPA_GUEST_TX) {
			txd += l->dby;
			r->tx_by += l->by;
			r->tx_pk += l->pk;
			r->tx_bps += l->bps;
			r->tx_pps += l->pps;
		} else {
			rxd += l->dby;
			r->rx_by += l->by;
			r->rx_pk += l->pk;
			r->rx_bps += l->bps;
			r->rx_pps += l->pps;
		}
	}
	if (r->tx_bps + r->rx_bps > r->peak_total)
		r->peak_total = r->tx_bps + r->rx_bps;
	{
		long m = (long)((r->now - r->start) / 60.0);

		while (r->tl_min < m) {
			r->tl_min++;
			r->tl_tx[r->tl_min % TL_MIN] = r->tl_rx[r->tl_min % TL_MIN] = 0;
			if (m - r->tl_min > TL_MIN)
				r->tl_min = m - TL_MIN;
		}
		r->tl_tx[m % TL_MIN] += txd;
		r->tl_rx[m % TL_MIN] += rxd;
	}
	if (r->tx_bps > r->peak_tx)
		r->peak_tx = r->tx_bps;
	if (r->rx_bps > r->peak_rx)
		r->peak_rx = r->rx_bps;
	/* TX and RX share one ring head so they stay aligned. */
	{
		unsigned h = r->hh_head, c = r->hh_count;

		push_hist(r->txh, &h, &c, r->tx_bps);
		push_hist(r->rxh, &r->hh_head, &r->hh_count, r->rx_bps);
	}

	for (i = 0; i < r->ndom; i++)
		r->dom[i].nactive = r->dom[i].nhist = 0;
	r->nactive = r->nhist = 0;
	for (i = 0; i < r->nent; i++) {
		struct fent *e = r->ents[i];

		e->bps = (double)e->dby / secs;
		e->pps = (double)e->dpk / secs;
		if (e->h) {
			memmove(e->h, e->h + 1, (CH - 1) * sizeof(float));
			e->h[CH - 1] = (float)e->bps;
			if (e->bps > 0)
				e->zeros = 0;
			else if (++e->zeros >= CH) {
				free(e->h);
				e->h = NULL;
			}
		} else if (e->bps > 0 && !e->hidden) {
			e->h = calloc(CH, sizeof(float));
			if (e->h) {
				e->h[CH - 1] = (float)e->bps;
				e->zeros = 0;
			}
		}
		if (e->hidden)
			continue;
		if (e->dby)
			e->logged = false;
		else if (r->log && !e->logged && !ent_active(r, e)) {
			log_flow(r, e);
			e->logged = true;
		}
		r->nhist++;
		r->dom[e->domain].nhist++;
		if (ent_active(r, e)) {
			r->nactive++;
			r->dom[e->domain].nactive++;
		}
	}
}

static int render(struct report *r);

int report_tick(struct report *r, double seconds)
{
	int err = 0;
	size_t i;

	if (!(seconds > 0.0))
		seconds = 1e-3;
	r->tick++;
	r->now = mono_s();
	r->tick_ns = mono_ns();
	if (r->fence_pending > r->fence_ns)
		r->fence_ns = r->fence_pending;
	for (i = 0; i < r->nent; i++)
		r->ents[i]->dpk = r->ents[i]->dby = 0;
	for (i = 0; i < r->nlnk; i++)
		r->lnk[i].dpk = r->lnk[i].dby = r->lnk[i].dunp = r->lnk[i].derr = r->lnk[i].dcre = 0,
		r->lnk[i].pps = r->lnk[i].bps = 0;
	for (i = 0; i < r->ndom; i++) {
		int e;

		if (r->dom[i].gone)
			continue;
		sample_links(r, (int)i, seconds);
		e = sample_flows(r, (int)i);
		if (e)
			err = e;
	}
	compute_tally(r, seconds);
	if (!(r->tui && r->paused)) {
		int e = render(r);

		if (e && !err)
			err = e;
	}
	return err;
}

int report_render(struct report *r)
{
	return render(r);
}

/* ---------- drawing primitives ---------- */
#define FG_TX 78
#define FG_RX 214
#define FG_DIM 244
#define FG_BRIGHT 255
#define FG_ACCENT 51

static void ln_style(struct ln *l, const char *attr, int fg, int bg)
{
	char b[64];
	int n;

	if (l->sb->oom || l->plain)
		return;
	n = snprintf(b, sizeof(b), "\x1b[0%s%s", attr && *attr ? ";" : "", attr ? attr : "");
	if (l->color && fg >= 0)
		n += snprintf(b + n, sizeof(b) - (size_t)n, ";38;5;%d", fg);
	if (l->color && bg >= 0)
		n += snprintf(b + n, sizeof(b) - (size_t)n, ";48;5;%d", bg);
	sb_put(l->sb, b, (size_t)n);
	sb_put(l->sb, "m", 1);
}

/* Appends at most nch characters of s, honouring the line width budget. */
static void ln_putn(struct ln *l, const char *s, size_t nch)
{
	const char *start = s;
	size_t n = 0;

	while (*s && n < nch && l->col + (int)n < l->cols) {
		do
			s++;
		while (((unsigned char)*s & 0xC0) == 0x80);
		n++;
	}
	sb_put(l->sb, start, (size_t)(s - start));
	l->col += (int)n;
}

static void ln_put(struct ln *l, const char *s)
{
	ln_putn(l, s, (size_t)-1);
}

static void ln_rep(struct ln *l, const char *ch, int n)
{
	while (n-- > 0 && l->col < l->cols) {
		sb_puts(l->sb, ch);
		l->col++;
	}
}

static void ln_printf(struct ln *l, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void ln_printf(struct ln *l, const char *fmt, ...)
{
	char tmp[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	ln_put(l, tmp);
}

static void ln_cell(struct ln *l, const char *s, int w, bool right)
{
	size_t n = ucount(s);

	if (w <= 0)
		return;
	if (n > (size_t)w) {
		ln_putn(l, s, (size_t)w - 1);
		ln_put(l, "\xe2\x80\xa6");
		return;
	}
	if (right)
		ln_rep(l, " ", w - (int)n);
	ln_put(l, s);
	if (!right)
		ln_rep(l, " ", w - (int)n);
}

static void ln_begin(struct ln *l, int row)
{
	l->col = 0;
	if (!l->plain) {
		char b[32];
		int n = snprintf(b, sizeof(b), "\x1b[%d;1H", row);

		sb_put(l->sb, b, (size_t)n);
	}
}

static void ln_end(struct ln *l)
{
	if (l->plain) {
		while (l->sb->len && l->sb->p[l->sb->len - 1] == ' ')
			l->sb->len--;
		if (l->sb->p)
			l->sb->p[l->sb->len] = 0;
		sb_put(l->sb, "\n", 1);
		return;
	}
	sb_puts(l->sb, "\x1b[0m\x1b[K");
}

static const char *const blocks[] = { "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
				      "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88" };

static int ring_vals(const float *h, unsigned head, unsigned count, int width, double *out)
{
	int m = (int)count < width ? (int)count : width, j;

	for (j = 0; j < m; j++) {
		unsigned back = (unsigned)(m - 1 - j);

		out[j] = h[(head + SPARK_N - 1 - back) % SPARK_N];
	}
	return m;
}

static void spark_str(char *b, size_t sz, const double *v, int m, int width)
{
	double mx = 1.0;
	size_t o = 0;
	int j;

	for (j = 0; j < m; j++)
		if (v[j] > mx)
			mx = v[j];
	for (j = m; j < width && o + 2 < sz; j++)
		b[o++] = ' ';
	for (j = 0; j < m && o + 4 < sz; j++) {
		int lv = v[j] <= 0 ? 0 : (int)(v[j] / mx * 7.0 + 0.5);

		if (lv > 7)
			lv = 7;
		memcpy(b + o, blocks[lv], 3);
		o += 3;
	}
	b[o] = 0;
}

static void bar_str(char *b, size_t sz, double frac, int w)
{
	static const char *const part[] = { "", "\xe2\x96\x8f", "\xe2\x96\x8e", "\xe2\x96\x8d",
					    "\xe2\x96\x8c", "\xe2\x96\x8b", "\xe2\x96\x8a",
					    "\xe2\x96\x89" };
	int eighths, full, i, used = 0;
	size_t o = 0;

	if (!(frac > 0))
		frac = 0;
	if (frac > 1)
		frac = 1;
	eighths = (int)(frac * w * 8 + 0.5);
	full = eighths / 8;
	for (i = 0; i < full && o + 4 < sz; i++, used++) {
		memcpy(b + o, "\xe2\x96\x88", 3);
		o += 3;
	}
	if (used < w && eighths % 8 && o + 4 < sz) {
		size_t pl = strlen(part[eighths % 8]);

		memcpy(b + o, part[eighths % 8], pl);
		o += pl;
		used++;
	}
	while (used++ < w && o + 2 < sz)
		b[o++] = ' ';
	b[o] = 0;
}

/* ---------- tables ---------- */
static void tc(struct tbl *t, int i, const char *title, int w, bool right, int drop)
{
	t->c[i].title = title;
	t->c[i].w = w;
	t->c[i].right = right;
	t->c[i].drop = drop;
	t->c[i].on = true;
	t->c[i].maxw = 0;
	t->c[i].minw = 0;
	if (i >= t->n)
		t->n = i + 1;
}

static void tflex(struct tbl *t, int i, int minw, int maxw)
{
	t->c[i].minw = minw;
	t->c[i].maxw = maxw;
	t->c[i].w = minw;
}

/* Drops low-priority columns until the table fits, then sizes the flex column. */
static void tbl_fit(struct tbl *t, int cols)
{
	for (;;) {
		int used = 1, shown = 0, best = -1, i, fixed = 0, flex = -1;

		for (i = 0; i < t->n; i++) {
			if (!t->c[i].on)
				continue;
			shown++;
			used += t->c[i].w;
			if (t->c[i].maxw) {
				flex = i;
			} else {
				fixed += t->c[i].w;
			}
			if (t->c[i].drop > 0 && (best < 0 || t->c[i].drop < t->c[best].drop))
				best = i;
		}
		used += shown > 0 ? shown - 1 : 0;
		if (used <= cols || best < 0) {
			if (flex >= 0) {
				int avail = cols - 1 - fixed - (shown - 1);

				if (avail > t->c[flex].maxw)
					avail = t->c[flex].maxw;
				if (avail < 4)
					avail = 4;
				t->c[flex].w = avail;
			}
			return;
		}
		t->c[best].on = false;
	}
}

static void tbl_header(struct ln *l, const struct tbl *t)
{
	int i, first = 1;

	ln_style(l, "1", 252, 238);
	ln_put(l, " ");
	for (i = 0; i < t->n; i++) {
		if (!t->c[i].on)
			continue;
		if (!first)
			ln_put(l, " ");
		first = 0;
		ln_cell(l, t->c[i].title, t->c[i].w, t->c[i].right);
	}
	ln_rep(l, " ", l->cols - l->col);
}

static void tbl_row(struct ln *l, const struct tbl *t, char cell[][CELL], const int *cfg,
		    const char *attr, int rowfg)
{
	int i, first = 1;

	ln_put(l, " ");
	for (i = 0; i < t->n; i++) {
		if (!t->c[i].on)
			continue;
		if (!first) {
			ln_style(l, attr, rowfg, -1);
			ln_put(l, " ");
		}
		first = 0;
		ln_style(l, attr, cfg[i] >= 0 ? cfg[i] : rowfg, -1);
		ln_cell(l, cell[i], t->c[i].w, t->c[i].right);
	}
}

/* ---------- views ---------- */
static const char *const sort_names[S_COUNT] = { "rate", "total bytes", "packets", "last seen" };
static const char *const view_names[V_COUNT] = { "Classic", "Live flows", "History", "Interfaces",
						 "Namespaces" };

enum { F_ST, F_NS, F_IF, F_DIR, F_PROTO, F_FLOW, F_RATE, F_BAR, F_TOTAL, F_PKTS, F_FIRST, F_DUR,
       F_LAST };
enum { I_NS, I_IF, I_STATE, I_TXR, I_TXT, I_TXP, I_RXR, I_RXT, I_RXP, I_UNP, I_ERR, I_SPK };
enum { N_NS, N_STATE, N_IFS, N_ACT, N_HIST, N_TXR, N_RXR, N_TXT, N_RXT, N_MAP, N_UNP };

static size_t view_count(const struct report *r, int view)
{
	switch (view) {
	case V_CLASSIC: return r->cl_lines;
	case V_LIVE: return r->nactive;
	case V_HIST: return r->nhist;
	case V_IFACE: return r->nlnk / 2;
	default: return r->ndom;
	}
}

/* Fills r->rows with the sorted rows of a view; returns -ENOMEM or 0. */
static int build_view(struct report *r, int view, size_t *np)
{
	size_t i, n = 0, need = (view == V_LIVE || view == V_HIST) ? r->nent : view == V_IFACE ? r->nlnk / 2 : r->ndom;

	if (rows_reserve(r, need ? need : 1))
		return -ENOMEM;
	r->maxbps = 1.0;
	for (i = 0; i < need; i++) {
		double k = 0, last = 0;

		if ((view == V_LIVE || view == V_HIST)) {
			const struct fent *e = r->ents[i];

			if (e->hidden || (view == V_LIVE && !ent_active(r, e)))
				continue;
			switch (r->sort) {
			case S_RATE: k = e->bps; break;
			case S_BYTES: k = (double)e->total_bytes; break;
			case S_PKTS: k = (double)e->total_pkts; break;
			default: k = e->last_seen; break;
			}
			last = e->last_seen;
			if (e->bps > r->maxbps)
				r->maxbps = e->bps;
		} else if (view == V_IFACE) {
			const struct link *t = &r->lnk[2 * i], *x = &r->lnk[2 * i + 1];

			switch (r->sort) {
			case S_RATE: k = t->bps + x->bps; break;
			case S_BYTES: k = (double)(t->by + x->by); break;
			case S_PKTS: k = (double)(t->pk + x->pk); break;
			default: k = -(double)i; break;
			}
			last = -(double)i;
		} else {
			size_t j;

			for (j = 0; j < r->nlnk; j++) {
				const struct link *l = &r->lnk[j];

				if (l->domain != (int)i)
					continue;
				switch (r->sort) {
				case S_RATE: k += l->bps; break;
				case S_BYTES: k += (double)l->by; break;
				case S_PKTS: k += (double)l->pk; break;
				default: break;
				}
			}
			if (r->sort == S_LAST)
				k = -(double)i;
			last = -(double)i;
		}
		r->rows[n].key = r->reverse ? k : -k;
		r->rows[n].last = -last;
		r->rows[n].idx = (unsigned)i;
		n++;
	}
	qsort(r->rows, n, sizeof(*r->rows), cmp_asc);
	*np = n;
	return 0;
}

static void tbl_setup(const struct report *r, int view, struct tbl *t, int cols)
{
	bool multi = r->ndom > 1;

	memset(t, 0, sizeof(*t));
	if ((view == V_LIVE || view == V_HIST)) {
		bool hist = view == V_HIST;

		tc(t, F_ST, "", 1, false, 8);
		tc(t, F_NS, "NAMESPACE", 10, false, 5);
		tc(t, F_IF, "IFACE", 12, false, 0);
		tc(t, F_DIR, "DIR", 4, false, 9);
		tc(t, F_PROTO, "PROTO", 5, false, 6);
		tc(t, F_FLOW, "FLOW", 18, false, 0);
		tflex(t, F_FLOW, 18, 62);
		tc(t, F_RATE, "RATE", 10, true, hist ? 7 : 0);
		tc(t, F_BAR, "", 6, false, 1);
		tc(t, F_TOTAL, "TOTAL", 9, true, 0);
		tc(t, F_PKTS, "PKTS", 7, true, 3);
		tc(t, F_FIRST, "FIRST", 8, true, 4);
		tc(t, F_DUR, hist ? "DURATION" : "AGE", 8, true, 2);
		tc(t, F_LAST, "LAST", 8, true, 0);
		t->c[F_NS].on = multi;
		t->c[F_ST].on = hist;
		t->c[F_BAR].on = !hist;
		t->c[F_FIRST].on = hist;
		t->c[F_LAST].on = hist;
		t->c[F_ST].drop = hist ? 8 : 0;
	} else if (view == V_IFACE) {
		tc(t, I_NS, "NAMESPACE", 10, false, 6);
		tc(t, I_IF, "IFACE", 12, false, 0);
		tflex(t, I_IF, 12, 28);
		tc(t, I_STATE, "STATE", 5, false, 0);
		tc(t, I_TXR, "TX RATE", 10, true, 0);
		tc(t, I_TXT, "TX TOTAL", 9, true, 7);
		tc(t, I_TXP, "TX PKTS", 7, true, 4);
		tc(t, I_RXR, "RX RATE", 10, true, 0);
		tc(t, I_RXT, "RX TOTAL", 9, true, 8);
		tc(t, I_RXP, "RX PKTS", 7, true, 5);
		tc(t, I_UNP, "UNPARS", 7, true, 2);
		tc(t, I_ERR, "ERRORS", 7, true, 3);
		tc(t, I_SPK, "TRAFFIC", 12, false, 1);
	} else {
		tc(t, N_NS, "NAMESPACE", 10, false, 0);
		tflex(t, N_NS, 10, 30);
		tc(t, N_STATE, "STATE", 5, false, 0);
		tc(t, N_IFS, "IFACES", 6, true, 3);
		tc(t, N_ACT, "ACTIVE", 7, true, 2);
		tc(t, N_HIST, "HISTORY", 7, true, 4);
		tc(t, N_TXR, "TX RATE", 10, true, 0);
		tc(t, N_RXR, "RX RATE", 10, true, 0);
		tc(t, N_TXT, "TX TOTAL", 9, true, 6);
		tc(t, N_RXT, "RX TOTAL", 9, true, 7);
		tc(t, N_MAP, "MAP FILL", 11, false, 5);
		tc(t, N_UNP, "UNPARS", 7, true, 1);
	}
	tbl_fit(t, cols);
}

static void iflabel(char *b, size_t sz, struct report *r, int dom, unsigned ifindex)
{
	const struct link *l = link_find(r, dom, ifindex, UNPA_GUEST_TX);

	if (!l)
		snprintf(b, sz, "if%u", ifindex);
	else if (l->label[0])
		snprintf(b, sz, "%s(%s)", l->name, l->label);
	else
		snprintf(b, sz, "%s", l->name);
}

static void fill_flow(struct report *r, int view, const struct fent *e, char cell[][CELL], int *cfg,
		      const char **attr, int *fg)
{
	bool act = ent_active(r, e);
	char s[INET6_ADDRSTRLEN + 16], d[INET6_ADDRSTRLEN + 16];
	bool tx = e->key.direction == UNPA_GUEST_TX;
	char p[16];

	*attr = act ? "" : "2";
	*fg = act ? 252 : 243;
	snprintf(cell[F_ST], CELL, "%s", act ? "\xe2\x97\x8f" : "\xe2\x97\x8b");
	cfg[F_ST] = act ? 82 : 240;
	snprintf(cell[F_NS], CELL, "%s", r->dom[e->domain].name);
	iflabel(cell[F_IF], CELL, r, e->domain, e->key.ifindex);
	snprintf(cell[F_DIR], CELL, "%s", tx ? "\xe2\x86\x91 TX" : "\xe2\x86\x93 RX");
	cfg[F_DIR] = act ? (tx ? FG_TX : FG_RX) : -1;
	fmt_proto(p, sizeof(p), e->key.proto);
	snprintf(cell[F_PROTO], CELL, "%s", p);
	fmt_addr(s, sizeof(s), &e->key, e->key.src, e->key.sport);
	fmt_addr(d, sizeof(d), &e->key, e->key.dst, e->key.dport);
	snprintf(cell[F_FLOW], CELL, "%s \xe2\x86\x92 %s", s, d);
	fmt_rate(cell[F_RATE], CELL, e->bps);
	bar_str(cell[F_BAR], CELL, e->bps / r->maxbps, 6);
	cfg[F_BAR] = act ? (tx ? FG_TX : FG_RX) : -1;
	fmt_bytes(cell[F_TOTAL], CELL, (double)e->total_bytes);
	fmt_count(cell[F_PKTS], CELL, (double)e->total_pkts);
	fmt_ago(cell[F_FIRST], CELL, r->now - e->first_seen);
	fmt_dur(cell[F_DUR], CELL, view == V_HIST ? e->last_seen - e->first_seen : r->now - e->first_seen);
	fmt_ago(cell[F_LAST], CELL, r->now - e->last_seen);
}

static void fill_iface(struct report *r, size_t k, char cell[][CELL], int *cfg, const char **attr,
		       int *fg)
{
	const struct link *t = &r->lnk[2 * k], *x = &r->lnk[2 * k + 1];
	double v[SPARK_N], w[SPARK_N], sum[SPARK_N];
	int mt, mx, m, j;

	*attr = t->gone ? "2" : "";
	*fg = t->gone ? 243 : 252;
	snprintf(cell[I_NS], CELL, "%s", r->dom[t->domain].name);
	iflabel(cell[I_IF], CELL, r, t->domain, t->ifindex);
	snprintf(cell[I_STATE], CELL, "%s", t->gone ? "GONE" : "UP");
	cfg[I_STATE] = t->gone ? 196 : 82;
	fmt_rate(cell[I_TXR], CELL, t->bps);
	fmt_bytes(cell[I_TXT], CELL, (double)t->by);
	fmt_count(cell[I_TXP], CELL, (double)t->pk);
	fmt_rate(cell[I_RXR], CELL, x->bps);
	fmt_bytes(cell[I_RXT], CELL, (double)x->by);
	fmt_count(cell[I_RXP], CELL, (double)x->pk);
	fmt_count(cell[I_UNP], CELL, (double)(t->unp + x->unp));
	fmt_count(cell[I_ERR], CELL, (double)(t->err + x->err));
	cfg[I_ERR] = (t->err + x->err) ? 196 : -1;
	cfg[I_TXR] = t->gone ? -1 : FG_TX;
	cfg[I_RXR] = t->gone ? -1 : FG_RX;
	mt = ring_vals(t->hist, t->hhead, t->hcount, 12, v);
	mx = ring_vals(x->hist, x->hhead, x->hcount, 12, w);
	m = mt > mx ? mt : mx;
	for (j = 0; j < m; j++) {
		double a = j >= m - mt ? v[j - (m - mt)] : 0, b = j >= m - mx ? w[j - (m - mx)] : 0;

		sum[j] = a + b;
	}
	spark_str(cell[I_SPK], CELL, sum, m, 12);
	cfg[I_SPK] = FG_ACCENT;
}

static double map_fill_pct(const struct domain *d)
{
	return d->gone || !d->cap ? 0.0 : 100.0 * (double)d->entries / (double)d->cap;
}

static void fill_ns(struct report *r, size_t i, char cell[][CELL], int *cfg, const char **attr,
		    int *fg)
{
	const struct domain *d = &r->dom[i];
	double txb = 0, rxb = 0;
	__u64 txt = 0, rxt = 0, unp = 0, pk = 0;
	size_t j;
	double pct = map_fill_pct(d);
	char bar[64];

	for (j = 0; j < r->nlnk; j++) {
		const struct link *l = &r->lnk[j];

		if (l->domain != (int)i)
			continue;
		unp += l->unp;
		pk += l->pk;
		if (l->dir == UNPA_GUEST_TX) {
			txb += l->bps;
			txt += l->by;
		} else {
			rxb += l->bps;
			rxt += l->by;
		}
	}
	*attr = d->gone ? "2" : "";
	*fg = d->gone ? 243 : 252;
	snprintf(cell[N_NS], CELL, "%s", d->name);
	snprintf(cell[N_STATE], CELL, "%s", d->gone ? "GONE" : "UP");
	cfg[N_STATE] = d->gone ? 196 : 82;
	snprintf(cell[N_IFS], CELL, "%u", d->nlinks);
	snprintf(cell[N_ACT], CELL, "%u", d->nactive);
	snprintf(cell[N_HIST], CELL, "%u", d->nhist);
	fmt_rate(cell[N_TXR], CELL, txb);
	fmt_rate(cell[N_RXR], CELL, rxb);
	cfg[N_TXR] = d->gone ? -1 : FG_TX;
	cfg[N_RXR] = d->gone ? -1 : FG_RX;
	fmt_bytes(cell[N_TXT], CELL, (double)txt);
	fmt_bytes(cell[N_RXT], CELL, (double)rxt);
	bar_str(bar, sizeof(bar), pct / 100.0, 5);
	snprintf(cell[N_MAP], CELL, "%s%3.0f%%", bar, pct);
	cfg[N_MAP] = pct >= 80 ? 196 : pct >= 50 ? 214 : 78;
	snprintf(cell[N_UNP], CELL, "%.1f%%", pk + unp ? 100.0 * (double)unp / (double)(pk + unp) : 0.0);
}

static void fill_row(struct report *r, int view, unsigned idx, char cell[][CELL], int *cfg,
		     const char **attr, int *fg)
{
	int i;

	for (i = 0; i < MAXC; i++) {
		cell[i][0] = 0;
		cfg[i] = -1;
	}
	if ((view == V_LIVE || view == V_HIST))
		fill_flow(r, view, r->ents[idx], cell, cfg, attr, fg);
	else if (view == V_IFACE)
		fill_iface(r, idx, cell, cfg, attr, fg);
	else
		fill_ns(r, idx, cell, cfg, attr, fg);
}

/* ---------- output ---------- */
static int write_all(const char *p, size_t n)
{
	while (n) {
		ssize_t w = write(STDOUT_FILENO, p, n);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0; /* terminal busy: drop this frame */
			return -errno;
		}
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

static int flush_out(struct report *r)
{
	int e;

	if (r->out.oom) {
		r->out.oom = false;
		r->out.len = 0;
		return -ENOMEM;
	}
	e = write_all(r->out.p ? r->out.p : "", r->out.len);
	r->out.len = 0;
	return e;
}

static double unparsed_pct(const struct report *r)
{
	__u64 pk = r->tx_pk + r->rx_pk;

	return pk + r->unp_total ? 100.0 * (double)r->unp_total / (double)(pk + r->unp_total) : 0.0;
}

static double map_max_pct(const struct report *r)
{
	double m = 0;
	size_t i;

	for (i = 0; i < r->ndom; i++)
		if (map_fill_pct(&r->dom[i]) > m)
			m = map_fill_pct(&r->dom[i]);
	return m;
}

static size_t live_ndom(const struct report *r)
{
	size_t i, n = 0;

	for (i = 0; i < r->ndom; i++)
		n += !r->dom[i].gone;
	return n;
}

static void kv(struct ln *l, const char *label, const char *val, int fg)
{
	ln_style(l, "", FG_DIM, -1);
	ln_put(l, label);
	ln_style(l, "1", fg, -1);
	ln_put(l, val);
}

static void tally_line(struct report *r, struct ln *l, bool tx, int sw)
{
	char a[32], b[32], c[32], s[SPARK_N * 3 + 8];
	double v[SPARK_N];
	int m = ring_vals(tx ? r->txh : r->rxh, r->hh_head, r->hh_count, sw, v);
	int fg = tx ? FG_TX : FG_RX;

	spark_str(s, sizeof(s), v, m, sw);
	ln_style(l, "1", fg, -1);
	ln_put(l, tx ? " \xe2\x86\x91 TX " : " \xe2\x86\x93 RX ");
	fmt_rate(a, sizeof(a), tx ? r->tx_bps : r->rx_bps);
	ln_style(l, "1", FG_BRIGHT, -1);
	ln_cell(l, a, 10, true);
	ln_style(l, "", fg, -1);
	ln_put(l, " ");
	ln_put(l, s);
	fmt_bytes(b, sizeof(b), (double)(tx ? r->tx_by : r->rx_by));
	kv(l, "  total ", b, FG_BRIGHT);
	fmt_count(b, sizeof(b), (double)(tx ? r->tx_pk : r->rx_pk));
	kv(l, "  pkts ", b, FG_BRIGHT);
	fmt_rate(c, sizeof(c), tx ? r->peak_tx : r->peak_rx);
	kv(l, "  peak ", c, fg);
}

static void stats_line(struct report *r, struct ln *l)
{
	char b[64];
	double mp = map_max_pct(r), up = unparsed_pct(r);

	snprintf(b, sizeof(b), "%zu", r->nactive);
	kv(l, " flows ", b, 82);
	snprintf(b, sizeof(b), " active / %zu history", r->nhist);
	kv(l, "", b, FG_BRIGHT);
	snprintf(b, sizeof(b), "%zu", live_ndom(r));
	kv(l, "  \xc2\xb7 ns ", b, FG_BRIGHT);
	snprintf(b, sizeof(b), "%zu", r->nlnk / 2);
	kv(l, "  \xc2\xb7 ifs ", b, FG_BRIGHT);
	snprintf(b, sizeof(b), "%.0f%%", mp);
	kv(l, "  \xc2\xb7 map ", b, mp >= 80 ? 196 : mp >= 50 ? 214 : 78);
	snprintf(b, sizeof(b), "%.1f%%", up);
	kv(l, "  \xc2\xb7 unparsed ", b, up >= 10 ? 196 : up >= 1 ? 214 : 78);
}

static const char *const help_lines[] = {
	"Keys",
	"  1 .. 5         Classic / Live flows / History / Interfaces / Namespaces",
	"  g              Classic: group by interface / flat list",
	"  x              Classic: show all connections per group / top 5",
	"  Tab, Shift-Tab next / previous view",
	"  s              cycle sort: rate, total bytes, packets, last seen",
	"  r              reverse sort order",
	"  p, Space       pause / resume the display (counting continues)",
	"  Up Down PgUp PgDn Home End   scroll",
	"  c              clear flow history",
	"  ? h            toggle this help",
	"  q, Ctrl-C      quit",
	"",
	"Flows are 'active' when they carried traffic within the idle window;",
	"older ones stay listed in History (dimmed) until evicted by the history cap.",
};

static int render_tui(struct report *r)
{
	struct winsize ws;
	struct ln l = { &r->out, 0, 80, r->color, false };
	int W = 80, H = 24, row = 1, avail;
	size_t n = 0, first, last, i;
	struct tbl t;
	char buf[96];
	int sw;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
		W = ws.ws_col;
		H = ws.ws_row;
	}
	l.cols = W;
	r->out.len = 0;
	sw = W >= 110 ? 30 : W >= 90 ? 20 : W >= 70 ? 12 : 8;
	if (build_view(r, r->view, &n))
		return -ENOMEM;
	avail = H - 7;
	if (avail < 1)
		avail = 1;
	if (r->limit && (size_t)avail > r->limit)
		avail = (int)r->limit;
	r->page = (size_t)avail;
	if (r->scroll + (size_t)avail > n)
		r->scroll = n > (size_t)avail ? n - (size_t)avail : 0;
	first = r->scroll;
	last = first + (size_t)avail < n ? first + (size_t)avail : n;

#define LINE_OK() (row <= H)
	/* banner */
	ln_begin(&l, row);
	ln_style(&l, "1", 16, 51);
	ln_put(&l, " UNPA NetHound " UNPA_VERSION " \xc2\xb7 eBPF ");
	ln_style(&l, "", FG_DIM, -1);
	fmt_dur(buf, sizeof(buf), r->now - r->start);
	ln_printf(&l, "  up %s  idle>%.0fs", buf, r->idle);
	if (r->paused) {
		ln_style(&l, "1", 16, 208);
		ln_put(&l, "  PAUSED ");
	}
	ln_end(&l);
	row++;
	if (LINE_OK()) {
		ln_begin(&l, row++);
		tally_line(r, &l, true, sw);
		ln_end(&l);
	}
	if (LINE_OK()) {
		ln_begin(&l, row++);
		tally_line(r, &l, false, sw);
		ln_end(&l);
	}
	if (LINE_OK()) {
		ln_begin(&l, row++);
		stats_line(r, &l);
		ln_end(&l);
	}
	if (LINE_OK()) {
		int v;

		ln_begin(&l, row++);
		for (v = 0; v < V_COUNT; v++) {
			bool cur = v == r->view;

			ln_style(&l, cur ? "1" : "", cur ? 16 : 250, cur ? 51 : -1);
			if (v == V_LIVE)
				snprintf(buf, sizeof(buf), " %d %s (%zu) ", v + 1, view_names[v], r->nactive);
			else if (v == V_HIST)
				snprintf(buf, sizeof(buf), " %d %s (%zu) ", v + 1, view_names[v], r->nhist);
			else
				snprintf(buf, sizeof(buf), " %d %s ", v + 1, view_names[v]);
			ln_put(&l, buf);
			ln_style(&l, "", FG_DIM, -1);
			ln_put(&l, " ");
		}
		ln_style(&l, "", FG_DIM, -1);
		ln_printf(&l, " sort: %s %s", sort_names[r->sort], r->reverse ? "\xe2\x96\xb2" : "\xe2\x96\xbc");
		ln_end(&l);
	}
	tbl_setup(r, r->view, &t, W);
	if (LINE_OK()) {
		ln_begin(&l, row++);
		if (r->help) {
			ln_style(&l, "1", 252, 238);
			ln_put(&l, " Help");
			ln_rep(&l, " ", W - l.col);
		} else {
			tbl_header(&l, &t);
		}
		ln_end(&l);
	}
	if (r->help) {
		for (i = 0; i < sizeof(help_lines) / sizeof(*help_lines) && row < H; i++) {
			ln_begin(&l, row++);
			ln_style(&l, i == 0 ? "1" : "", i == 0 ? FG_ACCENT : 252, -1);
			ln_put(&l, " ");
			ln_put(&l, help_lines[i]);
			ln_end(&l);
		}
	} else {
		for (i = first; i < last && row < H; i++) {
			char cell[MAXC][CELL];
			int cfg[MAXC], fg = 252;
			const char *attr = "";

			fill_row(r, r->view, r->rows[i].idx, cell, cfg, &attr, &fg);
			ln_begin(&l, row++);
			tbl_row(&l, &t, cell, cfg, attr, fg);
			ln_end(&l);
		}
		if (n == 0 && row < H) {
			ln_begin(&l, row++);
			ln_style(&l, "2", FG_DIM, -1);
			ln_put(&l, r->view == V_LIVE ? "  waiting for traffic\xe2\x80\xa6" : "  nothing to show yet");
			ln_end(&l);
		}
	}
	while (row < H) {
		ln_begin(&l, row++);
		ln_end(&l);
	}
	if (row == H) {
		ln_begin(&l, row);
		ln_style(&l, "", 250, 236);
		ln_put(&l, " 1-4 views \xc2\xb7 Tab \xc2\xb7 s sort \xc2\xb7 r rev \xc2\xb7 p pause \xc2\xb7 c clear \xc2\xb7 ? help \xc2\xb7 q quit");
		if (!r->help && n) {
			snprintf(buf, sizeof(buf), "%zu-%zu/%zu ", first + 1, last, n);
			if (l.col + (int)strlen(buf) < W) {
				ln_rep(&l, " ", W - l.col - (int)strlen(buf));
				ln_put(&l, buf);
			}
		}
		ln_rep(&l, " ", W - l.col);
		ln_end(&l);
	}
#undef LINE_OK
	return flush_out(r);
}

/* ---------- plain text and JSON ---------- */
#include "classic.inc"

__attribute__((unused)) static int render_plain(struct report *r)
{
	struct ln l = { &r->out, 0, 200, false, true };
	char a[32], b[32], c[32], d[32], line[256];
	static const int views[] = { V_IFACE, V_LIVE };
	int vi;

	r->out.len = 0;
	fmt_rate(a, sizeof(a), r->tx_bps);
	fmt_bytes(b, sizeof(b), (double)r->tx_by);
	fmt_rate(c, sizeof(c), r->rx_bps);
	fmt_bytes(d, sizeof(d), (double)r->rx_by);
	snprintf(line, sizeof(line),
		 "[%.0fs] TX %s (%s) RX %s (%s) | flows %zu active / %zu history | ns %zu ifs %zu | map %.0f%% | unparsed %.1f%%",
		 r->now - r->start, a, b, c, d, r->nactive, r->nhist, live_ndom(r), r->nlnk / 2,
		 map_max_pct(r), unparsed_pct(r));
	ln_begin(&l, 0);
	ln_put(&l, line);
	ln_end(&l);
	for (vi = 0; vi < 2; vi++) {
		int view = views[vi];
		size_t n = 0, i, show;
		struct tbl t;

		if (view == V_LIVE && r->limit == 0)
			break;
		if (build_view(r, view, &n))
			return -ENOMEM;
		show = view == V_LIVE && n > r->limit ? r->limit : n;
		if (view == V_IFACE && n == 0)
			continue;
		if (view == V_LIVE && n == 0)
			continue;
		tbl_setup(r, view, &t, 160);
		ln_begin(&l, 0);
		ln_end(&l);
		ln_begin(&l, 0);
		tbl_header(&l, &t);
		ln_end(&l);
		for (i = 0; i < show; i++) {
			char cell[MAXC][CELL];
			int cfg[MAXC], fg;
			const char *attr;

			fill_row(r, view, r->rows[i].idx, cell, cfg, &attr, &fg);
			ln_begin(&l, 0);
			tbl_row(&l, &t, cell, cfg, attr, fg);
			ln_end(&l);
		}
	}
	return flush_out(r);
}

static void jstr(struct sb *b, const char *s)
{
	char tmp[256];
	const char *p;

	clean(tmp, sizeof(tmp), s);
	sb_put(b, "\"", 1);
	for (p = tmp; *p; p++) {
		if (*p == '"' || *p == '\\')
			sb_put(b, "\\", 1);
		sb_put(b, p, 1);
	}
	sb_put(b, "\"", 1);
}

static void jaddr(struct sb *b, const struct flow_key *k, const __u8 *a)
{
	char ip[INET6_ADDRSTRLEN] = "";

	if (!inet_ntop(k->family == 4 ? AF_INET : AF_INET6, a, ip, sizeof(ip)))
		ip[0] = 0;
	jstr(b, ip);
}

static int render_json(struct report *r)
{
	struct sb *b = &r->out;
	size_t i, n = 0, show;
	unsigned ent = 0, cap = 0;

	r->out.len = 0;
	for (i = 0; i < r->ndom; i++) {
		if (r->dom[i].gone)
			continue;
		ent += r->dom[i].entries;
		cap += r->dom[i].cap;
	}
	sb_printf(b,
		  "{\"seconds\":%.3f,\"namespaces\":%zu,\"flow_entries\":%u,\"flow_capacity\":%u,\"history_flows\":%zu,\"active_flows\":%zu,\"links\":[",
		  r->now - r->start, live_ndom(r), ent, cap, r->nhist, r->nactive);
	for (i = 0; i < r->nlnk; i++) {
		const struct link *l = &r->lnk[i];

		sb_puts(b, i ? ",{\"namespace\":" : "{\"namespace\":");
		jstr(b, r->dom[l->domain].name);
		sb_puts(b, ",\"interface\":");
		jstr(b, l->name);
		sb_printf(b, ",\"ifindex\":%u,\"label\":", l->ifindex);
		jstr(b, l->label);
		sb_printf(b,
			  ",\"direction\":\"%s\",\"packets\":%llu,\"bytes\":%llu,\"delta_packets\":%llu,\"delta_bytes\":%llu,\"packets_per_second\":%.3f,\"bytes_per_second\":%.3f,\"unparsed\":%llu,\"flow_errors\":%llu,\"flow_creates\":%llu,\"delta_unparsed\":%llu,\"delta_flow_errors\":%llu,\"delta_flow_creates\":%llu,\"gone\":%s}",
			  dir_name(l->dir), (unsigned long long)l->pk, (unsigned long long)l->by,
			  (unsigned long long)l->dpk, (unsigned long long)l->dby, l->pps, l->bps,
			  (unsigned long long)l->unp, (unsigned long long)l->err,
			  (unsigned long long)l->cre, (unsigned long long)l->dunp,
			  (unsigned long long)l->derr, (unsigned long long)l->dcre,
			  l->gone ? "true" : "false");
	}
	sb_puts(b, "],\"flows\":[");
	if (r->limit && build_view(r, V_LIVE, &n))
		return -ENOMEM;
	show = n > r->limit ? r->limit : n;
	for (i = 0; r->limit && i < show; i++) {
		const struct fent *e = r->ents[r->rows[i].idx];
		char ifn[160];
		const struct link *lk = link_find(r, e->domain, e->key.ifindex, UNPA_GUEST_TX);

		sb_puts(b, i ? ",{\"namespace\":" : "{\"namespace\":");
		jstr(b, r->dom[e->domain].name);
		sb_puts(b, ",\"interface\":");
		if (lk)
			snprintf(ifn, sizeof(ifn), "%s", lk->name);
		else
			snprintf(ifn, sizeof(ifn), "if%u", e->key.ifindex);
		jstr(b, ifn);
		sb_printf(b, ",\"ifindex\":%u,\"label\":", e->key.ifindex);
		jstr(b, lk ? lk->label : "");
		sb_printf(b,
			  ",\"direction\":\"%s\",\"packets\":%llu,\"bytes\":%llu,\"delta_packets\":%llu,\"delta_bytes\":%llu,\"packets_per_second\":%.3f,\"bytes_per_second\":%.3f,\"family\":%u,\"protocol\":%u,\"src\":",
			  dir_name(e->key.direction), (unsigned long long)e->total_pkts,
			  (unsigned long long)e->total_bytes, (unsigned long long)e->dpk,
			  (unsigned long long)e->dby, e->pps, e->bps, e->key.family, e->key.proto);
		jaddr(b, &e->key, e->key.src);
		sb_puts(b, ",\"dst\":");
		jaddr(b, &e->key, e->key.dst);
		sb_printf(b,
			  ",\"sport\":%u,\"dport\":%u,\"first_seen_s_ago\":%.3f,\"last_seen_s_ago\":%.3f,\"active\":%s}",
			  e->key.sport, e->key.dport, r->now - e->first_seen, r->now - e->last_seen,
			  ent_active(r, e) ? "true" : "false");
	}
	sb_puts(b, "]}\n");
	return flush_out(r);
}

static int render(struct report *r)
{
	if (r->json)
		return render_json(r);
	if (r->tui && r->view != V_CLASSIC)
		return render_tui(r);
	return render_classic(r);
}

/* ---------- input ---------- */
static bool scroll_by(struct report *r, long d)
{
	size_t old = r->scroll, n = view_count(r, r->view);

	if (d < 0)
		r->scroll = (size_t)(-d) > r->scroll ? 0 : r->scroll - (size_t)(-d);
	else
		r->scroll += (size_t)d;
	if (r->scroll > n)
		r->scroll = n ? n - 1 : 0;
	return r->scroll != old;
}

static void set_view(struct report *r, int v)
{
	r->view = ((v % V_COUNT) + V_COUNT) % V_COUNT;
	r->scroll = 0;
}

static int csi_action(struct report *r, char fin, int p0)
{
	long page = r->page ? (long)r->page : 10;

	switch (fin) {
	case 'A': return scroll_by(r, -1);
	case 'B': return scroll_by(r, 1);
	case 'H': r->scroll = 0; return 1;
	case 'F': r->scroll = SIZE_MAX / 2; return scroll_by(r, 0) || 1;
	case 'Z': set_view(r, r->view - 1); return 1;
	case '~':
		if (p0 == 5)
			return scroll_by(r, -page);
		if (p0 == 6)
			return scroll_by(r, page);
		if (p0 == 1 || p0 == 7) {
			r->scroll = 0;
			return 1;
		}
		if (p0 == 4 || p0 == 8) {
			r->scroll = SIZE_MAX / 2;
			return scroll_by(r, 0) || 1;
		}
		return 0;
	default: return 0;
	}
}

int report_handle_input(struct report *r, const char *buf, size_t n)
{
	char in[sizeof(r->pend) + 256];
	size_t len = 0, i = 0;
	int ret = REPORT_NONE;

	if (r->npend)
		memcpy(in, r->pend, r->npend);
	len = r->npend;
	r->npend = 0;
	if (n > 256)
		n = 256; /* the rest of a huge paste is not interesting */
	memcpy(in + len, buf, n);
	len += n;

	while (i < len) {
		unsigned char c = (unsigned char)in[i];
		int act = 0;

		if (c == 0x1b) {
			size_t j = i + 1;
			int p0 = 0;
			bool have = false;

			if (j >= len) { /* maybe the start of a sequence split across reads */
				r->pend[r->npend++] = (char)c;
				break;
			}
			if (in[j] != '[' && in[j] != 'O') {
				i++; /* lone ESC (or Alt-key): ignore the ESC, reparse the rest */
				continue;
			}
			j++;
			while (j < len && ((in[j] >= '0' && in[j] <= '9') || in[j] == ';' || in[j] == '?' ||
					   in[j] == ' ')) {
				if (in[j] >= '0' && in[j] <= '9' && !have) {
					p0 = p0 * 10 + (in[j] - '0');
					if (p0 > 9999)
						p0 = 9999;
				} else if (in[j] == ';') {
					have = true;
				}
				j++;
			}
			if (j >= len) {
				if (len - i < sizeof(r->pend)) {
					memcpy(r->pend, in + i, len - i);
					r->npend = len - i;
				}
				break; /* incomplete (or absurdly long) sequence */
			}
			if (in[j] >= 0x40 && in[j] <= 0x7e)
				act = csi_action(r, in[j], p0);
			i = j + 1;
			if (act)
				ret |= REPORT_REDRAW;
			continue;
		}
		i++;
		if (r->help && c != 'q' && c != 3 && c != 4) {
			r->help = false;
			ret |= REPORT_REDRAW;
			continue;
		}
		switch (c) {
		case 'q': case 'Q': case 3: case 4:
			return REPORT_QUIT;
		case '1': case '2': case '3': case '4': case '5':
			set_view(r, c - '1');
			act = 1;
			break;
		case '\t':
			set_view(r, r->view + 1);
			act = 1;
			break;
		case 's':
			r->sort = (r->sort + 1) % S_COUNT;
			act = 1;
			break;
		case 'g':
			r->grouped = !r->grouped;
			act = 1;
			break;
		case 'x':
			r->expanded = !r->expanded;
			act = 1;
			break;
		case 'r':
			r->reverse = !r->reverse;
			act = 1;
			break;
		case 'p': case ' ':
			r->paused = !r->paused;
			act = 1;
			break;
		case 'c':
			history_clear(r);
			r->nhist = r->nactive = 0;
			{
				size_t d;

				for (d = 0; d < r->ndom; d++)
					r->dom[d].nactive = r->dom[d].nhist = 0;
			}
			act = 1;
			break;
		case '?': case 'h':
			r->help = !r->help;
			act = 1;
			break;
		case 'k': act = scroll_by(r, -1); break;
		case 'j': act = scroll_by(r, 1); break;
		default: break;
		}
		if (act)
			ret |= REPORT_REDRAW;
	}
	return ret;
}
