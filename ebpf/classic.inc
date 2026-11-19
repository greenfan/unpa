/* SPDX-License-Identifier: MIT */
/* "Classic" view: the look and feel of the original unpa.py report. Included
 * by report.c (uses its helpers). Bidirectional conversations are merged,
 * totals accumulate for the whole run and sort the table; idle connections
 * remain listed (dimmed) forever.
 */
#include <sys/utsname.h>

#define K_RESET "\033[0m"
#define K_BOLD "\033[1m"
#define K_UL "\033[4m"
#define K_GREY "\033[90m"
#define K_WHITE "\033[37m"
#define K_RED "\033[31m"
#define K_GREEN "\033[32m"
#define K_BLUE "\033[34m"
#define K_BRIGHT "\033[97m"
#define K_PALE "\033[38;5;151m"
#define K_MAGENTA "\033[38;5;140m"
#define K_PURPLE "\033[38;5;183m"
#define K_MOSS "\033[38;5;71m"
#define K_OLIVE "\033[38;5;108m"
#define K_HDR "\033[38;5;65m"

struct crow {
	const struct fent *p, *q; /* p = first-seen direction, q = reverse (or NULL) */
	double bytes, pkts, bps, last, key;
	unsigned grp;
};

struct cgrp {
	int dom;
	unsigned ifindex;
	double bytes, pkts, bps, last, key;
	size_t r0, n;
};

struct clx { /* line window: only lines in [lo, hi) are materialised */
	struct report *r;
	struct sb *b;
	size_t cur, lo, hi;
};

static const char *cc(const struct report *r, const char *code)
{
	return r->color ? code : "";
}
#define CC(x) cc(r, x)

static bool want(struct clx *x)
{
	bool v = x->cur >= x->lo && x->cur < x->hi;

	x->cur++;
	return v;
}

static size_t vwidth(const char *s)
{
	size_t n = 0;

	while (*s) {
		if (*s == 0x1b && s[1] == '[') {
			s += 2;
			while (*s && !(*s >= '@' && *s <= '~'))
				s++;
			if (*s)
				s++;
			continue;
		}
		if (((unsigned char)*s & 0xC0) != 0x80)
			n++;
		s++;
	}
	return n;
}

/* Append s cut/padded to exactly w visible columns (escape sequences kept). */
static void put_fit(struct sb *b, const char *s, size_t w)
{
	size_t vw = vwidth(s), seen = 0;

	if (vw <= w) {
		sb_puts(b, s);
		while (vw++ < w)
			sb_put(b, " ", 1);
		return;
	}
	while (*s) {
		if (*s == 0x1b && s[1] == '[') {
			const char *e = s + 2;

			while (*e && !(*e >= '@' && *e <= '~'))
				e++;
			if (*e)
				e++;
			sb_put(b, s, (size_t)(e - s));
			s = e;
			continue;
		}
		if (((unsigned char)*s & 0xC0) != 0x80) {
			if (seen + 1 >= w)
				break;
			seen++;
		}
		sb_put(b, s, 1);
		s++;
		while (((unsigned char)*s & 0xC0) == 0x80) {
			sb_put(b, s, 1);
			s++;
		}
	}
	sb_puts(b, "\xe2\x80\xa6" K_RESET);
	for (seen++; seen < w; seen++)
		sb_put(b, " ", 1);
}

static void py_bytes(char *b, size_t sz, double v)
{
	static const char *const u[] = { "B", "KB", "MB", "GB", "TB", "PB" };
	int i = 0;

	while (v >= 1024.0 && i < 5) {
		v /= 1024.0;
		i++;
	}
	if (i == 0)
		snprintf(b, sz, "%6.0f %s", v, u[0]);
	else
		snprintf(b, sz, "%6.2f %s", v, u[i]);
}

static void commas(char *b, size_t sz, unsigned long long v)
{
	char t[32];
	size_t n, i, o = 0;

	snprintf(t, sizeof(t), "%llu", v);
	n = strlen(t);
	for (i = 0; i < n && o + 2 < sz; i++) {
		if (i && (n - i) % 3 == 0)
			b[o++] = ',';
		b[o++] = t[i];
	}
	b[o] = 0;
}

static void py_duration(char *b, size_t sz, double s)
{
	if (s > 3600) {
		long m = (long)ceil(s / 60.0);

		snprintf(b, sz, "%ldh %ldm", m / 60, m % 60);
	} else if (s > 600) {
		snprintf(b, sz, "%ldm %lds", (long)s / 60, (long)s % 60);
	} else {
		snprintf(b, sz, "%.1f seconds", s);
	}
}

static const char *vcolor(double k)
{
	if (k == 0)
		return K_GREY;
	if (k < 400)
		return K_WHITE;
	if (k < 1200) {
		if (k < 900)
			return K_WHITE K_BOLD;
		if (k < 1050)
			return (rand() & 1) ? K_WHITE K_BOLD : K_RED;
		return K_RED;
	}
	if (k < 1800)
		return K_RED K_BOLD;
	if (k < 7800) {
		if (k < 3000)
			return K_RED K_BOLD;
		if (k < 5000)
			return (rand() & 1) ? K_RED K_BOLD : K_WHITE;
		return K_WHITE;
	}
	return K_WHITE K_BOLD;
}

static const char *vglyph(double k, bool *bold)
{
	*bold = false;
	if (k == 0)
		return " ";
	if (k < 5)
		return "\xe2\xa3\x80";
	if (k < 400) {
		*bold = k > 200;
		return "\xe2\xa3\xa4";
	}
	if (k < 1200) {
		*bold = k > 800;
		return "\xe2\xa3\xb6";
	}
	if (k < 1800) {
		*bold = k > 1500;
		return k > 1500 ? "\xe2\xa3\xbe" : "\xe2\xa3\xbf";
	}
	if (k < 7800) {
		*bold = k > 6000;
		return k > 6000 ? "\xe2\xa3\xbe" : "\xe2\x94\x8b";
	}
	if (k < 7900) {
		*bold = true;
		return "\xe2\xa3\xbf";
	}
	return "\xe2\x94\x8b";
}

static void put_history(struct report *r, struct sb *b, const struct crow *w)
{
	double prev = 0;
	int i;

	for (i = 0; i < CH; i++) {
		double v = (w->p->h ? w->p->h[i] : 0.0) + (w->q && w->q->h ? w->q->h[i] : 0.0);
		double kbps;
		bool bold;
		const char *g;

		if (v == 0 && prev > 100 * 1024)
			v = prev / 6.0; /* unpa.py smoothing after a fast sample */
		prev = v;
		kbps = v * 8.0 / 1000.0;
		g = vglyph(kbps, &bold);
		if (kbps == 0) {
			sb_put(b, " ", 1);
			continue;
		}
		sb_puts(b, CC(vcolor(kbps)));
		if (bold)
			sb_puts(b, CC(K_BOLD));
		sb_puts(b, g);
		sb_puts(b, CC(K_RESET));
	}
}

static void put_addr(struct report *r, struct sb *b, const struct flow_key *k, bool src, unsigned port,
		     int aw, const char *color)
{
	char a[INET6_ADDRSTRLEN + 2], t[64], pad[16];
	const char *s;
	bool ports = k->proto == 6 || k->proto == 17;
	size_t len;

	inet_ntop(k->family == 6 ? AF_INET6 : AF_INET, src ? k->src : k->dst, a, sizeof(a));
	len = strlen(a);
	s = a;
	if ((int)len > aw) { /* long IPv6: keep the distinguishing tail */
		snprintf(t, sizeof(t), "\xe2\x80\xa6%s", a + len - (size_t)(aw - 1));
		s = t;
	}
	snprintf(pad, sizeof(pad), "%u", port);
	sb_printf(b, "%s%s", CC(color), s);
	{
		int w = (int)vwidth(s);

		for (; w < aw; w++)
			sb_put(b, " ", 1);
	}
	if (ports)
		sb_printf(b, ":%-9u", port);
	else
		sb_puts(b, "          ");
	sb_puts(b, CC(K_RESET));
}

static bool crow_active(const struct report *r, const struct crow *w)
{
	return ent_active(r, w->p) || (w->q && ent_active(r, w->q));
}

static void put_row(struct report *r, struct sb *b, const struct crow *w, bool flat, int aw, bool hist)
{
	const struct flow_key *k = &w->p->key;
	const char *pc, *name;
	char pn[16], tot[32], rate[32], ifl[96];
	bool act = crow_active(r, w);
	const char *ac = act ? K_BRIGHT : K_GREY;
	double kbps = w->bps * 8.0 / 1000.0;

	switch (k->proto) {
	case 6: name = "TCP"; pc = K_BLUE; break;
	case 17: name = "UDP"; pc = K_GREEN; break;
	case 1: name = "ICMP"; pc = K_PALE; break;
	case 58: name = "ICMPv6"; pc = K_PALE; break;
	default: snprintf(pn, sizeof(pn), "IP%u", k->proto); name = pn; pc = K_MAGENTA; break;
	}
	py_bytes(tot, sizeof(tot), w->bytes);
	py_bytes(rate, sizeof(rate), w->bps);
	if (flat) {
		sb_printf(b, "%s%-6s%s Src: ", CC(pc), name, CC(K_RESET));
		put_addr(r, b, k, true, k->sport, aw, ac);
		sb_printf(b, "  %s\xe2\xa5\x84%s  Dst: ", CC(K_WHITE), CC(K_RESET));
		put_addr(r, b, k, false, k->dport, aw, ac);
		iflabel(ifl, sizeof(ifl), r, w->p->domain, k->ifindex);
		{
			char c[96];

			clean(c, sizeof(c), ifl);
			if (strlen(c) > 15) {
				c[12] = '.';
				c[13] = 0;
			}
			sb_printf(b, "  %s%-15s%s ", CC(K_PURPLE), c, CC(K_RESET));
		}
		sb_printf(b, " %s%11s%s ", CC(K_PALE), tot, CC(K_RESET));
	} else {
		sb_printf(b, "  %s%-6s%s ", CC(pc), name, CC(K_RESET));
		put_addr(r, b, k, true, k->sport, aw, ac);
		sb_printf(b, "  %s\xe2\x86\x92%s  ", CC(K_WHITE), CC(K_RESET));
		put_addr(r, b, k, false, k->dport, aw, ac);
		sb_printf(b, "  %sBytes:%s %s%12s%s ", CC(K_WHITE), CC(K_RESET), CC(K_PALE), tot, CC(K_RESET));
	}
	sb_printf(b, "%s%s/s%s ", CC(vcolor(kbps)), rate, CC(K_RESET));
	if (hist)
		put_history(r, b, w);
	if (!act) {
		char d[32];

		fmt_dur(d, sizeof(d), r->now - w->last);
		sb_printf(b, " %sidle %s%s", CC(K_GREY), d, CC(K_RESET));
	}
}

static int cmp_cgrp_key(const void *a, const void *b)
{
	const struct cgrp *x = a, *y = b;

	if (x->dom != y->dom)
		return x->dom < y->dom ? -1 : 1;
	return (x->ifindex > y->ifindex) - (x->ifindex < y->ifindex);
}

static int cmp_row_grp(const void *a, const void *b)
{
	const struct crow *x = a, *y = b;

	if (x->grp != y->grp)
		return x->grp < y->grp ? -1 : 1;
	if (x->key != y->key)
		return x->key > y->key ? -1 : 1;
	return (x->p > y->p) - (x->p < y->p);
}

static int cmp_row_flat(const void *a, const void *b)
{
	const struct crow *x = a, *y = b;

	if (x->key != y->key)
		return x->key > y->key ? -1 : 1;
	return (x->p > y->p) - (x->p < y->p);
}

static int cmp_gord(const void *a, const void *b, void *arg)
{
	const struct cgrp *g = arg;
	size_t i = *(const size_t *)a, j = *(const size_t *)b;

	if (g[i].key != g[j].key)
		return g[i].key > g[j].key ? -1 : 1;
	return (i > j) - (i < j);
}

static double sort_metric(const struct report *r, double bytes, double pkts, double bps, double last)
{
	double k;

	switch (r->sort) {
	case S_RATE: k = bps; break;
	case S_PKTS: k = pkts; break;
	case S_LAST: k = last; break;
	default: k = bytes; break;
	}
	return r->reverse ? -k : k;
}

/* Per-minute 24h timeline folded into at most `cols` buckets of equal length. */
static int timeline(const struct report *r, const __u64 *tl, int cols, double *vals, double *bucket_s,
		    long *span_min)
{
	long m = r->tl_min, span = m + 1 < TL_MIN ? m + 1 : TL_MIN, bm, nb, i, j;

	if (cols < 1)
		return 0;
	bm = (span + cols - 1) / cols;
	nb = (span + bm - 1) / bm;
	for (i = 0; i < nb; i++) {
		double sum = 0;

		for (j = 0; j < bm; j++) {
			long minute = m - span + 1 + i * bm + j;

			if (minute > m)
				break;
			sum += (double)tl[minute % TL_MIN];
		}
		vals[i] = sum / (double)(bm * 60);
	}
	*bucket_s = (double)(bm * 60);
	*span_min = span;
	return (int)nb;
}

static void spark(char *b, size_t sz, const double *v, int n, double *peak)
{
	static const char *const lv[] = { "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
					  "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88" };
	double mx = 0;
	size_t o = 0;
	int i;

	for (i = 0; i < n; i++)
		if (v[i] > mx)
			mx = v[i];
	*peak = mx;
	b[0] = 0;
	for (i = 0; i < n && o + 4 < sz; i++) {
		int l = mx > 0 ? (int)(v[i] / mx * 7.999) : 0;

		if (v[i] <= 0) {
			b[o++] = ' ';
		} else {
			memcpy(b + o, lv[l < 0 ? 0 : l > 7 ? 7 : l], 3);
			o += 3;
		}
		b[o] = 0;
	}
}

struct busy {
	int dom;
	unsigned ifindex;
	double tx, rx;
};

static void add_box_row(struct sb *b, struct report *r, const char *content, size_t inner)
{
	sb_printf(b, "%s\xe2\x94\x82%s ", CC(K_BOLD K_HDR), CC(K_RESET));
	put_fit(b, content, inner - 1);
	sb_printf(b, "%s\xe2\x94\x82%s", CC(K_BOLD K_HDR), CC(K_RESET));
}

static void build_summary(struct report *r, struct clx *x, size_t bw, bool panel, double tot_bytes,
			  double tot_pkts, size_t nconn, size_t nact)
{
	static const char *const sp = "";
	char c[10][600], p[6][300], t1[48], t2[48], t3[48], title[160];
	struct busy top[5];
	size_t ntop = 0, i, j, nc = 0, nrow, inner = bw - 2;
	double cur = r->tx_bps + r->rx_bps, tv[64], rv[64], bs, tp, rp;
	long span;
	char tsp[320], rsp[320], pk[32], dur[32], when[16], tl_label[32];
	struct utsname un;
	struct tm tmv;
	time_t tt = time(NULL);
	int nb, rb;
	struct sb *b = x->b;

	(void)sp;
	/* Right panel: busiest interfaces by current rate. */
	for (i = 0; i < r->nlnk; i++) {
		const struct link *l = &r->lnk[i];
		const struct link *o;
		struct busy cand;

		if (l->dir != UNPA_GUEST_TX)
			continue;
		o = link_find(r, l->domain, l->ifindex, UNPA_GUEST_RX);
		cand = (struct busy){ l->domain, l->ifindex, l->bps, o ? o->bps : 0.0 };
		for (j = 0; j < ntop && j < 5; j++)
			if (cand.tx + cand.rx > top[j].tx + top[j].rx)
				break;
		if (j >= 5)
			continue;
		if (ntop < 5)
			ntop++;
		memmove(&top[j + 1], &top[j], (ntop - 1 - j) * sizeof(top[0]));
		top[j] = cand;
	}
	snprintf(p[0], sizeof(p[0]), "%s%sBusiest Interfaces%s %s(TX \xe2\x86\x91  RX \xe2\x86\x93)%s", CC(K_BOLD), CC(K_MOSS),
		 CC(K_RESET), CC(K_OLIVE), CC(K_RESET));
	for (i = 0; i < 5; i++) {
		if (i < ntop) {
			char nm[96], cl[96];

			iflabel(nm, sizeof(nm), r, top[i].dom, top[i].ifindex);
			clean(cl, sizeof(cl), nm);
			if (strlen(cl) > 14) {
				cl[13] = '.';
				cl[14] = 0;
			}
			py_bytes(t1, sizeof(t1), top[i].tx);
			py_bytes(t2, sizeof(t2), top[i].rx);
			snprintf(p[i + 1], sizeof(p[i + 1]), "%s%-14s%s %s%s/s%s %s%s/s%s", CC(K_BRIGHT), cl, CC(K_RESET),
				 CC(vcolor(top[i].tx * 8 / 1000)), t1, CC(K_RESET), CC(vcolor(top[i].rx * 8 / 1000)), t2,
				 CC(K_RESET));
		} else {
			snprintf(p[i + 1], sizeof(p[i + 1]), "%s(no interface)%s", CC(K_GREY), CC(K_RESET));
		}
	}
	/* Left box rows. */
	uname(&un);
	snprintf(c[nc++], sizeof(c[0]), "%sPlatform: %s%s %s (%s)%s", CC(K_WHITE), CC(K_BRIGHT), un.sysname,
		 un.release, un.nodename, CC(K_RESET));
	py_duration(dur, sizeof(dur), r->now - r->start);
	localtime_r(&tt, &tmv);
	strftime(when, sizeof(when), "%H:%M:%S", &tmv);
	snprintf(c[nc++], sizeof(c[0]), "%sDuration: %s%s%s   %sUpdated: %s%s%s%s", CC(K_WHITE), CC(K_BRIGHT), dur,
		 CC(K_RESET), CC(K_WHITE), CC(K_BRIGHT), when, r->paused ? "  PAUSED" : "", CC(K_RESET));
	py_bytes(t1, sizeof(t1), tot_bytes);
	commas(pk, sizeof(pk), (unsigned long long)tot_pkts);
	snprintf(c[nc++], sizeof(c[0]), "%sCumulative Total: %s%s%s %sin %s%s%s%s packets%s", CC(K_WHITE), CC(K_MOSS), t1,
		 CC(K_RESET), CC(K_WHITE), CC(K_MOSS), pk, CC(K_RESET), CC(K_WHITE), CC(K_RESET));
	py_bytes(t1, sizeof(t1), cur);
	py_bytes(t2, sizeof(t2), r->tx_bps);
	py_bytes(t3, sizeof(t3), r->rx_bps);
	snprintf(c[nc++], sizeof(c[0]), "%sCurrent: %s%s/s%s  %s(\xe2\x86\x91 %s/s  \xe2\x86\x93 %s/s)%s", CC(K_WHITE),
		 CC(vcolor(cur * 8 / 1000)), t1, CC(K_RESET), CC(K_GREY), t2, t3, CC(K_RESET));
	py_bytes(t1, sizeof(t1), r->peak_total);
	snprintf(c[nc++], sizeof(c[0]), "%sTracked Connections: %s%zu%s %s(%zu active)%s  %sPeak: %s%s/s%s", CC(K_WHITE),
		 CC(K_PALE), nconn, CC(K_RESET), CC(K_OLIVE), nact, CC(K_RESET), CC(K_WHITE),
		 CC(vcolor(r->peak_total * 8 / 1000)), t1, CC(K_RESET));
	snprintf(c[nc++], sizeof(c[0]), "%sScope: %s%zu%s namespaces  %s%zu%s interfaces  map fill %s%.0f%%%s  unparsed %s%.1f%%%s",
		 CC(K_WHITE), CC(K_PALE), live_ndom(r), CC(K_WHITE), CC(K_PALE), r->nlnk / 2, CC(K_WHITE), CC(K_PALE),
		 map_max_pct(r), CC(K_WHITE), CC(K_PALE), unparsed_pct(r), CC(K_RESET));
	nb = timeline(r, r->tl_tx, (int)(inner > 60 ? 32 : 16), tv, &bs, &span);
	rb = timeline(r, r->tl_rx, (int)(inner > 60 ? 32 : 16), rv, &bs, &span);
	spark(tsp, sizeof(tsp), tv, nb, &tp);
	spark(rsp, sizeof(rsp), rv, rb, &rp);
	fmt_dur(tl_label, sizeof(tl_label), (double)span * 60.0);
	py_bytes(t1, sizeof(t1), tp);
	py_bytes(t2, sizeof(t2), rp);
	snprintf(c[nc++], sizeof(c[0]), "%sLast %s%s%s  \xe2\x86\x91 %s%s%s %speak %s/s%s", CC(K_WHITE), CC(K_BRIGHT),
		 tl_label, CC(K_RESET), CC(K_GREEN), tsp, CC(K_RESET), CC(K_GREY), t1, CC(K_RESET));
	snprintf(c[nc++], sizeof(c[0]), "%s%*s  \xe2\x86\x93 %s%s%s %speak %s/s%s", CC(K_WHITE),
		 (int)strlen("Last ") + (int)strlen(tl_label), "", CC(K_BLUE), rsp, CC(K_RESET), CC(K_GREY), t2, CC(K_RESET));
	if (r->dropped)
		snprintf(c[nc++], sizeof(c[0]), "%sNOT TRACKED (out of memory): %zu flows%s", CC(K_RED), r->dropped,
			 CC(K_RESET));
	/* Emit: title, then box (top border + rows + bottom border) beside the panel. */
	snprintf(title, sizeof(title), "UNPA NetHound eBPF Hypervisor Traffic Monitor");
	if (want(x)) {
		int pad = (int)(bw - 2 - strlen(title)) / 2;

		sb_printf(b, "%s%s%s %*s%s%*s%s\n", CC(K_BOLD), CC(K_HDR), CC(K_UL), pad > 0 ? pad : 0, "", title,
			  (int)(bw - 2) - (pad > 0 ? pad : 0) - (int)strlen(title), "", CC(K_RESET));
	}
	nrow = nc + 2;
	for (i = 0; i < nrow; i++) {
		if (!want(x))
			continue;
		if (i == 0 || i == nrow - 1) {
			sb_puts(b, CC(K_BOLD K_HDR));
			sb_puts(b, i == 0 ? "\xe2\x94\x8c" : "\xe2\x94\x94");
			for (j = 0; j < bw - 2; j++)
				sb_puts(b, "\xe2\x94\x80");
			sb_puts(b, i == 0 ? "\xe2\x94\x90" : "\xe2\x94\x98");
			sb_puts(b, CC(K_RESET));
		} else {
			add_box_row(b, r, c[i - 1], bw - 2);
		}
		if (panel && i < 6) {
			sb_puts(b, "  ");
			put_fit(b, p[i], 42);
		}
		sb_puts(b, "\n");
	}
	if (want(x))
		sb_puts(b, "\n");
}

static int render_classic(struct report *r)
{
	struct winsize ws;
	struct sb body = { 0 };
	struct clx x = { r, &body, 0, 0, SIZE_MAX };
	struct crow *rows = NULL;
	struct cgrp *grp = NULL;
	size_t *gord = NULL, nrows = 0, ng = 0, ngall, i, j, avail = 0, nconn = 0, nact = 0, shown_cap;
	double tot_b = 0, tot_p = 0;
	int W = 140, H = 40, aw = 20, aw_avail;
	bool tui = r->tui, hist = true, saved_color = r->color, more = false;
	char tmp[256];

	if (tui) {
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
			W = ws.ws_col;
			H = ws.ws_row;
		} else {
			W = 100;
		}
		avail = H > 6 ? (size_t)(H - 3) : 3;
		r->page = avail;
		if (r->scroll + avail > r->cl_lines)
			r->scroll = r->cl_lines > avail ? r->cl_lines - avail : 0;
		x.lo = r->scroll;
		x.hi = x.lo + avail;
	} else {
		r->color = false;
	}
	aw_avail = tui ? W - 4 : 148;
	/* Row layout needs 86 + 2*aw columns (+19 for the history graph). */
	if (86 + 2 * aw + 19 > aw_avail) {
		aw = (aw_avail - 86 - 19) / 2;
		if (aw < 12) {
			hist = false;
			aw = (aw_avail - 86) / 2;
			if (aw > 20)
				aw = 20;
			if (aw < 12)
				aw = 12;
		}
	}

	/* Conversations: merge each flow with its reverse-direction peer. */
	ngall = 0;
	for (i = 0; i < r->nlnk; i++)
		ngall += r->lnk[i].dir == UNPA_GUEST_TX;
	rows = malloc((r->nent + 1) * sizeof(*rows));
	grp = calloc(ngall + 1, sizeof(*grp));
	gord = malloc((ngall + 1) * sizeof(*gord));
	if (!rows || !grp || !gord) {
		free(rows);
		free(grp);
		free(gord);
		r->color = saved_color;
		return -ENOMEM;
	}
	for (i = 0; i < r->nlnk; i++)
		if (r->lnk[i].dir == UNPA_GUEST_TX) {
			grp[ng].dom = r->lnk[i].domain;
			grp[ng++].ifindex = r->lnk[i].ifindex;
		}
	qsort(grp, ng, sizeof(*grp), cmp_cgrp_key);
	grp[ng].dom = -1;
	for (i = 0; i < r->nent; i++) {
		const struct fent *e = r->ents[i], *q = e->peer, *p;
		struct crow *w;
		struct cgrp key, *g;

		if (e->hidden)
			continue;
		if (q && q->hidden)
			q = NULL;
		if (q && q->idx < e->idx)
			continue; /* the peer's row covers this conversation */
		p = e;
		if (q && (q->first_seen < e->first_seen ||
			  (q->first_seen == e->first_seen && q->key.direction == UNPA_GUEST_TX)))
			p = q, q = e;
		w = &rows[nrows++];
		w->p = p;
		w->q = q;
		w->bytes = (double)p->total_bytes + (q ? (double)q->total_bytes : 0.0);
		w->pkts = (double)p->total_pkts + (q ? (double)q->total_pkts : 0.0);
		w->bps = p->bps + (q ? q->bps : 0.0);
		w->last = p->last_seen > (q ? q->last_seen : 0.0) ? p->last_seen : q->last_seen;
		w->key = sort_metric(r, w->bytes, w->pkts, w->bps, w->last);
		key.dom = e->domain;
		key.ifindex = e->key.ifindex;
		g = bsearch(&key, grp, ng, sizeof(*grp), cmp_cgrp_key);
		w->grp = g ? (unsigned)(g - grp) : (unsigned)ng;
		g = &grp[w->grp];
		g->bytes += w->bytes;
		g->pkts += w->pkts;
		g->bps += w->bps;
		if (w->last > g->last)
			g->last = w->last;
		g->n++;
		tot_b += w->bytes;
		tot_p += w->pkts;
		nconn++;
		nact += crow_active(r, w);
	}
	for (i = 0; i <= ng; i++)
		grp[i].key = sort_metric(r, grp[i].bytes, grp[i].pkts, grp[i].bps, grp[i].last);
	if (r->grouped) {
		size_t at = 0;

		qsort(rows, nrows, sizeof(*rows), cmp_row_grp);
		for (i = 0; i <= ng; i++) {
			grp[i].r0 = at;
			at += grp[i].n;
		}
	} else {
		qsort(rows, nrows, sizeof(*rows), cmp_row_flat);
	}
	for (i = 0; i <= ng; i++)
		gord[i] = i;
	qsort_r(gord, ng + 1, sizeof(*gord), cmp_gord, grp);

	if (!tui) {
		time_t tt = time(NULL);
		struct tm tmv;

		localtime_r(&tt, &tmv);
		strftime(tmp, sizeof(tmp), "%H:%M:%S", &tmv);
		sb_printf(&body, "--- report refresh %s ---\n", tmp);
	}
	if (r->help && tui) {
		for (i = 0; i < sizeof(help_lines) / sizeof(*help_lines); i++)
			if (want(&x))
				sb_printf(&body, "%s%s%s\n", CC(i == 0 ? K_BOLD K_MOSS : K_BRIGHT), help_lines[i], CC(K_RESET));
	} else {
		size_t bw = aw_avail >= 80 ? 80 : (aw_avail > 40 ? (size_t)aw_avail : 40);

		build_summary(r, &x, bw, aw_avail >= (int)bw + 2 + 42, tot_b, tot_p, nconn, nact);
		shown_cap = !tui && r->limit == 0 ? 0 : SIZE_MAX;
		if (nrows == 0 && want(&x))
			sb_printf(&body, "  %swaiting for traffic\xe2\x80\xa6%s\n", CC(K_GREY), CC(K_RESET));
		if (r->grouped) {
			for (j = 0; j <= ng && shown_cap; j++) {
				const struct cgrp *g = &grp[gord[j]];
				size_t show = r->expanded ? g->n : (g->n < 5 ? g->n : 5);
				char nm[96], cl[96], b1[32], b2[32], pk[32];

				if (!g->n)
					continue;
				if (gord[j] == ng) {
					snprintf(cl, sizeof(cl), "other");
				} else {
					iflabel(nm, sizeof(nm), r, g->dom, g->ifindex);
					clean(cl, sizeof(cl), nm);
				}
				if (r->ndom > 1 && gord[j] != ng) {
					size_t l = strlen(cl);

					snprintf(cl + l, sizeof(cl) - l, " @%s", r->dom[g->dom].name);
				}
				if (!tui && shown_cap != SIZE_MAX)
					show = 0;
				if (!tui && r->limit && show > r->limit)
					show = r->limit;
				if (want(&x)) {
					commas(pk, sizeof(pk), (unsigned long long)g->pkts);
					py_bytes(b1, sizeof(b1), g->bytes);
					py_bytes(b2, sizeof(b2), g->bps);
					sb_printf(&body,
						  "%s%20s%s[%s%s%s%s] \xe2\x80\xa2 Total Packet Count [ %s%s%s%s ] \xe2\x80\xa2 Total [%s%s%s%s ] \xe2\x80\xa2 %s%s/s%s\n",
						  CC(K_BOLD), "", CC(K_BRIGHT), CC(K_PURPLE), cl, CC(K_BRIGHT), CC(K_BOLD), CC(K_PURPLE), pk,
						  CC(K_BRIGHT), CC(K_BOLD), CC(K_PALE), b1, CC(K_BRIGHT), CC(K_BOLD), CC(vcolor(g->bps * 8 / 1000)),
						  b2, CC(K_RESET));
				}
				for (i = 0; i < show; i++) {
					if (want(&x)) {
						put_row(r, &body, &rows[g->r0 + i], false, aw, hist);
						sb_puts(&body, "\n");
					}
				}
				if (show < g->n && want(&x))
					sb_printf(&body, "  %s\xe2\x80\xa6 %zu more (x expands)%s\n", CC(K_OLIVE), g->n - show, CC(K_RESET));
				if (want(&x))
					sb_puts(&body, "\n");
			}
		} else if (shown_cap) {
			for (i = 0; i < nrows; i++) {
				if (!tui && r->limit && i >= r->limit)
					break;
				if (want(&x)) {
					put_row(r, &body, &rows[i], true, aw, hist);
					sb_puts(&body, "\n");
				}
			}
		}
	}
	if (tui) {
		size_t nl = 0, fw = 64, row = 1, lines_vis = 0;
		const char *p = body.p ? body.p : "";
		const char *ls = p, *end;
		char footer[96], hint[256];
		size_t fvw, pad;
		int k;

		r->cl_lines = x.cur;
		more = x.cur > x.hi;
		for (; ls < p + body.len; ls = end + 1) {
			size_t vw;

			end = memchr(ls, '\n', (size_t)(p + body.len - ls));
			if (!end)
				break;
			{
				char save = *end;

				((char *)end)[0] = 0;
				vw = vwidth(ls);
				((char *)end)[0] = save;
			}
			if (vw > fw)
				fw = vw;
			lines_vis++;
		}
		if (more && lines_vis)
			lines_vis--; /* the last line becomes the "more" notice */
		if (fw > 148)
			fw = 148;
		if ((int)fw > W - 4)
			fw = W > 24 ? (size_t)(W - 4) : 20;
		r->out.len = 0;
		sb_printf(&r->out, "\033[1;1H%s\xe2\x95\xad", CC(K_GREY));
		for (i = 0; i < fw + 2; i++)
			sb_puts(&r->out, "\xe2\x94\x80");
		sb_printf(&r->out, "\xe2\x95\xae%s\033[K", CC(K_RESET));
		row = 2;
		ls = p;
		for (nl = 0; nl < lines_vis; nl++, row++) {
			end = memchr(ls, '\n', (size_t)(p + body.len - ls));
			if (!end)
				break;
			((char *)end)[0] = 0;
			sb_printf(&r->out, "\033[%zu;1H%s\xe2\x94\x82%s ", row, CC(K_GREY), CC(K_RESET));
			put_fit(&r->out, ls, fw);
			sb_printf(&r->out, " %s\xe2\x94\x82%s\033[K", CC(K_GREY), CC(K_RESET));
			ls = end + 1;
		}
		if (more) {
			sb_printf(&r->out, "\033[%zu;1H%s\xe2\x94\x82%s ", row, CC(K_GREY), CC(K_RESET));
			snprintf(tmp, sizeof(tmp), "%s\xe2\x80\xa6 %zu more lines (Up/Down, PgUp/PgDn to scroll)%s", CC(K_OLIVE),
				 x.cur - x.hi + 1, CC(K_RESET));
			put_fit(&r->out, tmp, fw);
			sb_printf(&r->out, " %s\xe2\x94\x82%s\033[K", CC(K_GREY), CC(K_RESET));
			row++;
		}
		snprintf(hint, sizeof(hint), " 1-5 views \xc2\xb7 s sort: %s %s \xc2\xb7 g %s \xc2\xb7 x %s \xc2\xb7 p pause \xc2\xb7 ? help \xc2\xb7 q quit ",
			 sort_names[r->sort], r->reverse ? "\xe2\x96\xb2" : "\xe2\x96\xbc", r->grouped ? "flat" : "group",
			 r->expanded ? "top5" : "expand");
		sb_printf(&r->out, "\033[%zu;1H%s\xe2\x95\xb0", row, CC(K_GREY));
		if (vwidth(hint) + 1 <= fw + 2) {
			sb_puts(&r->out, "\xe2\x94\x80");
			sb_printf(&r->out, "%s%s%s", CC(K_OLIVE), hint, CC(K_GREY));
			for (i = 0; i < fw + 2 - 1 - vwidth(hint); i++)
				sb_puts(&r->out, "\xe2\x94\x80");
		} else {
			for (i = 0; i < fw + 2; i++)
				sb_puts(&r->out, "\xe2\x94\x80");
		}
		sb_printf(&r->out, "\xe2\x95\xaf%s\033[K", CC(K_RESET));
		for (i = row + 1; i < (size_t)H; i++)
			sb_printf(&r->out, "\033[%zu;1H\033[2K", i);
		snprintf(footer, sizeof(footer), " xxx I unpa nethound version %s I xxx ", UNPA_VERSION);
		fvw = strlen(footer);
		if (fvw > (size_t)W)
			footer[W] = 0, fvw = (size_t)W;
		pad = ((size_t)W - fvw) / 2;
		sb_printf(&r->out, "\033[%d;1H\033[2K%*s", H, (int)pad, "");
		for (k = 0; footer[k]; k++) {
			if (r->color)
				sb_printf(&r->out, "\033[38;5;%ldm", lround(22 + 92.0 * k / (fvw > 1 ? (double)(fvw - 1) : 1.0)));
			sb_put(&r->out, &footer[k], 1);
		}
		sb_puts(&r->out, CC(K_RESET));
	} else {
		r->out.len = 0;
		sb_put(&r->out, body.p ? body.p : "", body.len);
		r->cl_lines = x.cur;
	}
	free(body.p);
	free(rows);
	free(grp);
	free(gord);
	r->color = saved_color;
	return flush_out(r);
}
