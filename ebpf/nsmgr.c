/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nsmgr.h"
#include "unpa.h"

#define MAX_DOMAINS 256
#define UNPA_HANDLE 0x554eU

struct attach {
	struct bpf_tc_hook hook;
	struct bpf_tc_opts opts;
	bool attached, created;
};

struct iface {
	char name[IF_NAMESIZE];
	unsigned int ifindex;
	struct attach at[2];
	bool seen, live;
};

struct domain {
	int id;
	dev_t dev;
	ino_t ino;
	char name[64];
	bool seen, host, gone;
	struct bpf_object *obj;
	int flows_fd, links_fd, prog_fds[2];
	unsigned int prog_ids[2];
	struct iface *ifs;
	size_t nifs, cap;
};

struct cand {
	dev_t dev;
	ino_t ino;
	char path[96], name[64];
};

struct nsmgr {
	struct nsmgr_opts o;
	struct report *report;
	int orig;
	struct domain *doms;
	size_t ndoms, attached;
	struct cand *cands;
	size_t ncands, ccap;
	bool quiet;
};

static void warn(struct nsmgr *m, const char *what, const char *who, int err)
{
	if (!m->quiet)
		fprintf(stderr, "unpa: %s %s: %s\n", what, who, strerror(-err));
}

static int enter(struct nsmgr *m, const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC), err = 0;

	if (fd < 0)
		return -errno;
	if (setns(fd, CLONE_NEWNET))
		err = -errno;
	close(fd);
	(void)m;
	return err;
}

static void leave(struct nsmgr *m)
{
	if (setns(m->orig, CLONE_NEWNET))
		perror("unpa: cannot return to original network namespace");
}

static int add_cand(struct nsmgr *m, const char *path, const char *name)
{
	struct stat st;

	if (stat(path, &st))
		return 0;
	for (size_t i = 0; i < m->ncands; i++)
		if (m->cands[i].dev == st.st_dev && m->cands[i].ino == st.st_ino)
			return 0;
	if (m->ncands == m->ccap) {
		size_t n = m->ccap ? m->ccap * 2 : 64;
		struct cand *c = realloc(m->cands, n * sizeof(*c));

		if (!c)
			return -ENOMEM;
		m->cands = c;
		m->ccap = n;
	}
	struct cand *c = &m->cands[m->ncands++];

	c->dev = st.st_dev;
	c->ino = st.st_ino;
	snprintf(c->path, sizeof(c->path), "%s", path);
	snprintf(c->name, sizeof(c->name), "%s", name);
	return 0;
}

static void named_dir(struct nsmgr *m, const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;

	if (!d)
		return;
	while ((e = readdir(d))) {
		char path[512];

		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%.100s", dir, e->d_name);
		add_cand(m, path, e->d_name);
	}
	closedir(d);
}

static void proc_dir(struct nsmgr *m)
{
	DIR *d = opendir("/proc");
	struct dirent *e;

	if (!d)
		return;
	while ((e = readdir(d))) {
		char path[64], name[64] = "", comm[32] = "";
		FILE *f;

		if (e->d_name[0] < '1' || e->d_name[0] > '9')
			continue;
		snprintf(path, sizeof(path), "/proc/%.20s/ns/net", e->d_name);
		snprintf(name, sizeof(name), "/proc/%.20s/comm", e->d_name);
		f = fopen(name, "r");
		if (f) {
			if (fgets(comm, sizeof(comm), f))
				comm[strcspn(comm, "\n")] = 0;
			fclose(f);
		}
		snprintf(name, sizeof(name), "%.20s:%.30s", e->d_name, comm);
		add_cand(m, path, name);
	}
	closedir(d);
}

static struct domain *find_domain(struct nsmgr *m, const struct cand *c)
{
	for (size_t i = 0; i < m->ndoms; i++)
		if (!m->doms[i].gone && m->doms[i].dev == c->dev &&
		    m->doms[i].ino == c->ino)
			return &m->doms[i];
	return NULL;
}

static int load_domain(struct nsmgr *m, struct domain *d)
{
	static const char *const names[] = {"unpa_ingress", "unpa_egress"};
	int err;

	d->obj = bpf_object__open_file(m->o.object, NULL);
	err = (int)libbpf_get_error(d->obj);
	if (err) {
		d->obj = NULL;
		return err;
	}
	{
		/* Larger flow table: fewer LRU evictions between samples. */
		struct bpf_map *fm = bpf_object__find_map_by_name(d->obj, "flows");

		if (fm)
			bpf_map__set_max_entries(fm, d->host ? 262144 : 32768);
	}
	err = bpf_object__load(d->obj);
	if (err)
		return err;
	d->links_fd = bpf_object__find_map_fd_by_name(d->obj, "links");
	d->flows_fd = bpf_object__find_map_fd_by_name(d->obj, "flows");
	if (d->links_fd < 0 || d->flows_fd < 0)
		return -ENOENT;
	for (int i = 0; i < 2; i++) {
		struct bpf_program *p = bpf_object__find_program_by_name(d->obj, names[i]);
		struct bpf_prog_info info = {0};
		__u32 len = sizeof(info);

		if (!p || (d->prog_fds[i] = bpf_program__fd(p)) < 0)
			return -ENOENT;
		if (bpf_obj_get_info_by_fd(d->prog_fds[i], &info, &len))
			return -errno;
		d->prog_ids[i] = info.id;
	}
	return 0;
}

static void close_domain(struct domain *d)
{
	if (d->obj)
		bpf_object__close(d->obj);
	d->obj = NULL;
	free(d->ifs);
	d->ifs = NULL;
	d->nifs = d->cap = 0;
}

static int attach_iface(struct domain *d, struct iface *f, bool l3, unsigned int prio)
{
	struct link_counters seed = {.l3 = l3};
	int err;

	for (int dir = 0; dir < 2; dir++) {
		struct link_key k = {.ifindex = f->ifindex, .direction = (__u8)dir};

		bpf_map_update_elem(d->links_fd, &k, &seed, BPF_ANY);
		f->at[dir].hook = (struct bpf_tc_hook){
			.sz = sizeof(struct bpf_tc_hook), .ifindex = (int)f->ifindex,
			.attach_point = dir == UNPA_GUEST_TX ? BPF_TC_INGRESS : BPF_TC_EGRESS,
		};
	}
	err = bpf_tc_hook_create(&f->at[0].hook);
	if (err && err != -EEXIST)
		return err;
	f->at[0].created = !err;
	for (int dir = 0; dir < 2; dir++) {
		struct bpf_tc_opts o = {.sz = sizeof(o), .handle = UNPA_HANDLE,
					.priority = prio, .prog_fd = d->prog_fds[dir]};

		err = bpf_tc_attach(&f->at[dir].hook, &o);
		if (err)
			return err;
		f->at[dir].opts = (struct bpf_tc_opts){.sz = sizeof(o), .handle = o.handle,
						       .priority = o.priority,
						       .prog_id = d->prog_ids[dir]};
		f->at[dir].attached = true;
	}
	return 0;
}

static void detach_iface(struct iface *f)
{
	for (int dir = 1; dir >= 0; dir--) {
		struct bpf_tc_opts o = f->at[dir].opts;

		if (!f->at[dir].attached)
			continue;
		o.prog_id = 0;
		bpf_tc_detach(&f->at[dir].hook, &o);
		f->at[dir].attached = false;
	}
	if (f->at[0].created)
		bpf_tc_hook_destroy(&f->at[0].hook);
}

static const struct want *wanted(const struct nsmgr *m, const char *name)
{
	for (size_t i = 0; i < m->o.nwants; i++)
		if (!strcmp(m->o.wants[i].name, name))
			return &m->o.wants[i];
	return NULL;
}

/* Runs inside the target namespace. */
static void scan_ifaces(struct nsmgr *m, struct domain *d)
{
	struct if_nameindex *list = if_nameindex();
	int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	for (size_t i = 0; i < d->nifs; i++)
		d->ifs[i].seen = false;
	for (struct if_nameindex *p = list; p && p->if_index; p++) {
		const struct want *w = d->host && !m->o.all ? wanted(m, p->if_name) : NULL;
		struct ifreq req = {0};
		struct iface *f = NULL;
		bool l3 = false;
		int err;

		if (!m->o.all && !w)
			continue;
		if (!m->o.loopback && !w && !strcmp(p->if_name, "lo"))
			continue;
		for (size_t i = 0; i < d->nifs; i++)
			if (d->ifs[i].live && d->ifs[i].ifindex == p->if_index &&
			    !strcmp(d->ifs[i].name, p->if_name))
				f = &d->ifs[i];
		if (f) {
			f->seen = true;
			continue;
		}
		if (d->nifs == d->cap) {
			size_t n = d->cap ? d->cap * 2 : 8;
			struct iface *v = realloc(d->ifs, n * sizeof(*v));

			if (!v)
				continue;
			d->ifs = v;
			d->cap = n;
		}
		f = &d->ifs[d->nifs];
		memset(f, 0, sizeof(*f));
		snprintf(f->name, sizeof(f->name), "%s", p->if_name);
		f->ifindex = p->if_index;
		snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", p->if_name);
		if (sock >= 0 && !ioctl(sock, SIOCGIFHWADDR, &req)) {
			int t = req.ifr_hwaddr.sa_family;

			l3 = !(t == ARPHRD_ETHER || t == ARPHRD_LOOPBACK || t == ARPHRD_IEEE802);
		}
		err = attach_iface(d, f, l3, m->o.priority);
		if (err) {
			detach_iface(f);
			warn(m, "attach", p->if_name, err);
			continue;
		}
		f->live = f->seen = true;
		d->nifs++;
		m->attached++;
		report_add_link(m->report, d->id, f->name, f->ifindex, w ? w->label : NULL);
	}
	if (sock >= 0)
		close(sock);
	if (list)
		if_freenameindex(list);
	for (size_t i = 0; i < d->nifs; i++) {
		struct iface *f = &d->ifs[i];

		if (f->live && !f->seen) {
			f->live = false;
			m->attached--;
			report_link_gone(m->report, d->id, f->ifindex);
		}
	}
}

int nsmgr_scan(struct nsmgr *m, bool quiet)
{
	m->quiet = quiet;
	m->ncands = 0;
	if (m->o.all) {
		named_dir(m, "/run/netns");
		named_dir(m, "/run/docker/netns");
		add_cand(m, "/proc/1/ns/net", "host");
		proc_dir(m);
	}
	add_cand(m, "/proc/self/ns/net", "host");
	for (size_t i = 0; i < m->ndoms; i++)
		m->doms[i].seen = false;
	for (size_t i = 0; i < m->ncands; i++) {
		struct cand *c = &m->cands[i];
		struct domain *d = find_domain(m, c);
		struct stat self;
		bool host = !stat("/proc/self/ns/net", &self) &&
			    self.st_dev == c->dev && self.st_ino == c->ino;
		int err;

		if (!m->o.all && !host)
			continue;
		if (!d) {
			if (m->ndoms == MAX_DOMAINS)
				continue;
			d = &m->doms[m->ndoms];
			memset(d, 0, sizeof(*d));
			d->dev = c->dev;
			d->ino = c->ino;
			d->host = host;
			snprintf(d->name, sizeof(d->name), "%s", host ? "host" : c->name);
			err = load_domain(m, d);
			if (err) {
				warn(m, "load BPF for namespace", d->name, err);
				close_domain(d);
				if (host)
					return err;
				continue;
			}
			d->id = report_add_domain(m->report, d->name, d->flows_fd, d->links_fd);
			if (d->id < 0) {
				err = d->id;
				close_domain(d);
				return err;
			}
			m->ndoms++;
		}
		d->seen = true;
		err = host ? 0 : enter(m, c->path);
		if (err) {
			warn(m, "enter namespace", d->name, err);
			continue;
		}
		scan_ifaces(m, d);
		if (!host)
			leave(m);
	}
	for (size_t i = 0; i < m->ndoms; i++) {
		struct domain *d = &m->doms[i];

		if (!d->gone && !d->seen) {
			for (size_t j = 0; j < d->nifs; j++)
				if (d->ifs[j].live)
					m->attached--;
			d->gone = true;
			report_domain_gone(m->report, d->id);
			close_domain(d);
		}
	}
	return 0;
}

size_t nsmgr_attached(const struct nsmgr *m)
{
	return m->attached;
}

struct nsmgr *nsmgr_create(const struct nsmgr_opts *o, struct report *r)
{
	struct nsmgr *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	m->o = *o;
	m->report = r;
	m->doms = calloc(MAX_DOMAINS, sizeof(*m->doms));
	m->orig = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (!m->doms || m->orig < 0) {
		int e = errno ? errno : ENOMEM;

		free(m->doms);
		free(m);
		errno = e;
		return NULL;
	}
	return m;
}

void nsmgr_destroy(struct nsmgr *m)
{
	if (!m)
		return;
	for (size_t i = 0; i < m->ndoms; i++) {
		struct domain *d = &m->doms[i];

		if (d->gone || !d->obj)
			continue;
		if (!d->host) {
			bool found = false;

			m->ncands = 0;
			add_cand(m, "/proc/self/ns/net", "host");
			named_dir(m, "/run/netns");
			named_dir(m, "/run/docker/netns");
			proc_dir(m);
			for (size_t c = 0; c < m->ncands && !found; c++) {
				if (m->cands[c].dev != d->dev || m->cands[c].ino != d->ino)
					continue;
				found = !enter(m, m->cands[c].path);
			}
			if (!found)
				continue;
		}
		for (size_t j = 0; j < d->nifs; j++)
			if (d->ifs[j].live)
				detach_iface(&d->ifs[j]);
		if (!d->host)
			leave(m);
	}
	for (size_t i = 0; i < m->ndoms; i++)
		close_domain(&m->doms[i]);
	free(m->cands);
	free(m->doms);
	close(m->orig);
	free(m);
}
