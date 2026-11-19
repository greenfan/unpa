/* SPDX-License-Identifier: MIT */
#ifndef UNPA_NSMGR_H
#define UNPA_NSMGR_H

#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>

#include "report.h"

struct want {
	char name[IF_NAMESIZE];
	const char *label;
};

struct nsmgr_opts {
	const char *object;
	unsigned int priority;
	bool all;		/* every interface in every namespace */
	bool loopback;		/* with all: include lo */
	const struct want *wants; /* host-namespace interfaces (no all) */
	size_t nwants;
};

struct nsmgr;

struct nsmgr *nsmgr_create(const struct nsmgr_opts *, struct report *);
/* Discover, load+attach new, retire vanished. Returns 0 or -errno (fatal). */
int nsmgr_scan(struct nsmgr *, bool quiet);
size_t nsmgr_attached(const struct nsmgr *);
void nsmgr_destroy(struct nsmgr *);

#endif
