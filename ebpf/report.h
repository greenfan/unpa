/* SPDX-License-Identifier: MIT */
#ifndef UNPA_REPORT_H
#define UNPA_REPORT_H

#include <stdbool.h>
#include <stddef.h>

/* A "domain" is one loaded BPF object (own flows/links maps) serving exactly
 * one network namespace. ifindex values are unique only within a domain.
 */
struct report;

enum { REPORT_NONE = 0, REPORT_REDRAW = 1, REPORT_QUIT = 2 };

/* limit: max live/history rows shown (0 hides flow rows in JSON/plain mode;
 * the TUI fits rows to the terminal and ignores it except as an upper cap
 * when non-zero). history_limit: 0 keeps every flow for the whole run; N>0 caps the
 * table (evict oldest by last activity). idle_seconds: a flow with no traffic for this long is "inactive"
 * and listed only in history. Returns NULL with errno set on failure.
 */
struct report *report_create(size_t limit, bool json, size_t history_limit,
			     double idle_seconds);
void report_destroy(struct report *); /* also leaves the terminal mode */

/* Interactive TUI (alternate screen, hidden cursor, raw stdin) when both
 * stdin and stdout are TTYs and json is false. No-op otherwise.
 * Returns true if the TUI is active.
 */
bool report_terminal_enter(struct report *);
bool report_tui_active(const struct report *);

/* fds are borrowed; they must stay valid until report_domain_gone() or
 * report_destroy(). Returns a domain id >= 0 or a negative errno.
 */
int report_add_domain(struct report *, const char *nsname, int flows_fd,
		      int links_fd);
/* Registers an attached interface (label may be NULL). */
int report_add_link(struct report *, int domain, const char *ifname,
		    unsigned int ifindex, const char *label);
/* Interface/namespace disappeared: stop reading its maps (fds may be closed
 * afterwards) but keep its totals and flow history on screen, marked gone.
 */
void report_link_gone(struct report *, int domain, unsigned int ifindex);
void report_domain_gone(struct report *, int domain);

/* Accepts a numeric IPv4/IPv6 address or CIDR. Matches either endpoint;
 * exclusions override includes. Returns 0 or a negative errno.
 */
/* Append one JSON line per flow direction when it goes idle and at exit. */
int report_set_log(struct report *, const char *path);
int report_validate_filter(const char *cidr_or_ip);
int report_add_filter(struct report *, const char *cidr_or_ip, bool exclude);

/* seconds: elapsed since the previous tick (or creation). Samples every
 * domain, updates history, renders. Returns 0 or a negative errno
 * (-EPIPE if stdout closed).
 */
int report_tick(struct report *, double seconds);
/* Re-renders the last sample (resize, key press) without sampling. */
int report_render(struct report *);
/* Feed raw bytes read from stdin. Returns REPORT_* (bitmask-free: QUIT wins). */
int report_handle_input(struct report *, const char *buf, size_t n);

#endif /* UNPA_REPORT_H */
