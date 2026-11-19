/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "nsmgr.h"
#include "report.h"

#define MAX_WANTS 1024
#define MAX_FILTERS 1024
#define RESCAN_SECONDS 2.0

struct filter_arg {
	const char *text;
	bool exclude;
};

static volatile sig_atomic_t stop, winch;

static void on_signal(int sig)
{
	if (sig == SIGWINCH)
		winch = 1;
	else
		stop = 1;
}

static void usage(FILE *out)
{
	fputs("Usage: unpa [-a | -i IFACE[=VM] ...] [options]   (run as root)\n"
	      "  -a, --all                  Every interface in every network namespace\n"
	      "  -i, --interface IFACE[=VM] Host interface to watch; optional VM label\n"
	      "      --loopback             With -a: include lo\n"
	      "  -t, --interval SECONDS     Sample interval (default 1; 0.1-3600)\n"
	      "  -c, --count N              Max flow rows for plain/JSON output (default 20)\n"
	      "  -ii CIDR, --include CIDR   Include flows matching either endpoint\n"
	      "  -ee CIDR, --exclude CIDR   Exclude flows matching either endpoint\n"
	      "      --idle SECONDS         Flow is inactive after this idle time (default 5)\n"
	      "      --history N            Cap remembered flows (default: keep all)\n"
	      "      --log FILE             Append idle/final flow records as JSON lines\n"
	      "      --json                 One JSON object per sample\n"
	      "      --once                 Exit after one sample\n"
	      "      --priority N           TC filter priority (default 1)\n"
	      "      --object FILE          Override the BPF ELF beside this binary\n"
	      "      --version              Print the version\n"
	      "  -h, --help                 Show this help\n"
	      "TUI keys: 1-5/Tab views, s sort, g group, x expand, r reverse, p pause, c clear, ? help, q quit\n", out);
}

static bool uint_arg(const char *s, unsigned long max, unsigned long *out)
{
	char *end;

	if (!s[0] || s[strspn(s, "0123456789")])
		return false;
	errno = 0;
	*out = strtoul(s, &end, 10);
	return !errno && !*end && *out <= max;
}

static bool double_arg(const char *s, double lo, double hi, double *out)
{
	char *end;

	*out = strtod(s, &end);
	return *s && !*end && isfinite(*out) && *out >= lo && *out <= hi;
}

static int object_path(char *buf, size_t size)
{
	const char name[] = "unpa.bpf.o";
	ssize_t len = readlink("/proc/self/exe", buf, size - 1);
	char *base;

	if (len < 0)
		return -errno;
	if ((size_t)len == size - 1)
		return -ENAMETOOLONG;
	buf[len] = 0;
	base = strrchr(buf, '/');
	if (!base || size - (size_t)(base + 1 - buf) < sizeof(name))
		return -ENAMETOOLONG;
	memcpy(base + 1, name, sizeof(name));
	return 0;
}

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int run(int argc, char **argv)
{
	static const struct option opts[] = {
		{"all", no_argument, NULL, 'a'},
		{"interface", required_argument, NULL, 'i'},
		{"interval", required_argument, NULL, 't'},
		{"count", required_argument, NULL, 'c'},
		{"include", required_argument, NULL, 256}, {"ii", required_argument, NULL, 256},
		{"exclude", required_argument, NULL, 257}, {"ee", required_argument, NULL, 257},
		{"json", no_argument, NULL, 258}, {"once", no_argument, NULL, 259},
		{"priority", required_argument, NULL, 260}, {"object", required_argument, NULL, 261},
		{"version", no_argument, NULL, 262}, {"loopback", no_argument, NULL, 263},
		{"idle", required_argument, NULL, 264}, {"history", required_argument, NULL, 265}, {"log", required_argument, NULL, 266},
		{"help", no_argument, NULL, 'h'}, {0},
	};
	static struct want wants[MAX_WANTS];
	static struct filter_arg filters[MAX_FILTERS];
	struct nsmgr_opts mo = {.priority = 1};
	struct nsmgr *mgr = NULL;
	struct report *report = NULL;
	struct sigaction sig = {.sa_handler = on_signal};
	const char *file = NULL, *where = "initialize";
	char sibling[PATH_MAX];
	size_t nwants = 0, nfilters = 0;
	unsigned long limit = 20, priority = 1, history = 0;
	const char *logfile = NULL;
	double interval = 1, idle = 5, last, next_scan, now;
	bool once = false, json = false, all = false, loopback = false, tui;
	int opt, err = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--"))
			break;
		if (!strcmp(argv[i], "-ii"))
			argv[i] = "--include";
		else if (!strcmp(argv[i], "-ee"))
			argv[i] = "--exclude";
	}
	while ((opt = getopt_long(argc, argv, "ai:t:c:h", opts, NULL)) != -1) {
		switch (opt) {
		case 'a': all = true; break;
		case 'i': {
			const char *eq = strchr(optarg, '=');
			size_t len = eq ? (size_t)(eq - optarg) : strlen(optarg);

			if (nwants == MAX_WANTS || !len || len >= IF_NAMESIZE || (eq && !eq[1]))
				goto bad_arg;
			memcpy(wants[nwants].name, optarg, len);
			wants[nwants++].label = eq ? eq + 1 : NULL;
			break;
		}
		case 't': if (!double_arg(optarg, 0.1, 3600, &interval)) goto bad_arg; break;
		case 264: if (!double_arg(optarg, 0.1, 86400, &idle)) goto bad_arg; break;
		case 'c': if (!uint_arg(optarg, 16384, &limit)) goto bad_arg; break;
		case 265: if (!uint_arg(optarg, 100000000, &history) || !history) goto bad_arg; break;
		case 266: logfile = optarg; break;
		case 256: case 257:
			if (nfilters == MAX_FILTERS || report_validate_filter(optarg))
				goto bad_arg;
			filters[nfilters++] = (struct filter_arg){optarg, opt == 257};
			break;
		case 258: json = true; break;
		case 259: once = true; break;
		case 260: if (!uint_arg(optarg, 65535, &priority) || !priority) goto bad_arg; break;
		case 261: file = optarg; break;
		case 262: puts("unpa " UNPA_VERSION); return 0;
		case 263: loopback = true; break;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 2;
		}
	}
	if ((!all && !nwants) || optind != argc) {
		usage(stderr);
		return 2;
	}
	if (geteuid() != 0)
		fprintf(stderr, "unpa: warning: not root; BPF and namespace access will likely fail\n");
	if (!file) {
		err = object_path(sibling, sizeof(sibling));
		if (err) {
			where = "locate BPF object";
			goto out;
		}
		file = sibling;
	}
	sigemptyset(&sig.sa_mask);
	if (sigaction(SIGINT, &sig, NULL) || sigaction(SIGTERM, &sig, NULL) ||
	    sigaction(SIGHUP, &sig, NULL) || sigaction(SIGWINCH, &sig, NULL)) {
		err = -errno;
		where = "set signal handlers";
		goto out;
	}
	signal(SIGPIPE, SIG_IGN);

	report = report_create(limit, json, history, idle);
	if (!report) {
		err = -errno;
		where = "initialize report";
		goto out;
	}
	if (logfile && (err = report_set_log(report, logfile))) {
		where = "open flow log";
		goto out;
	}
	for (size_t i = 0; i < nfilters; i++) {
		err = report_add_filter(report, filters[i].text, filters[i].exclude);
		if (err) {
			where = "add flow filter";
			goto out;
		}
	}
	mo.object = file;
	mo.priority = (unsigned int)priority;
	mo.all = all;
	mo.loopback = loopback;
	mo.wants = wants;
	mo.nwants = nwants;
	mgr = nsmgr_create(&mo, report);
	if (!mgr) {
		err = -errno;
		where = "initialize namespace manager";
		goto out;
	}
	where = "attach (requires root, BPF and CAP_NET_ADMIN)";
	err = nsmgr_scan(mgr, false);
	if (err)
		goto out;
	tui = report_terminal_enter(report);
	last = now_s();
	next_scan = last + RESCAN_SECONDS;
	while (!stop) {
		double next = last + interval, wait = next - now_s();
		int rc = REPORT_NONE;

		while (wait > 0 && !stop) {
			struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
			int n = poll(&pfd, tui ? 1 : 0, (int)(wait * 1000) + 1);

			if (n > 0 && (pfd.revents & POLLIN)) {
				char buf[64];
				ssize_t got = read(STDIN_FILENO, buf, sizeof(buf));

				if (got > 0)
					rc |= report_handle_input(report, buf, (size_t)got);
				else if (got == 0)
					tui = false;
			}
			if (rc & REPORT_QUIT) {
				stop = 1;
				break;
			}
			if (winch || (rc & REPORT_REDRAW)) {
				winch = 0;
				rc = REPORT_NONE;
				report_render(report);
			}
			wait = next - now_s();
		}
		if (stop)
			break;
		now = now_s();
		if (now >= next_scan) {
			err = nsmgr_scan(mgr, tui);
			if (err) {
				where = "rescan namespaces";
				break;
			}
			next_scan = now + RESCAN_SECONDS;
		}
		where = "report sample";
		err = report_tick(report, now - last);
		last = now;
		if (err == -EPIPE && stop)
			err = 0;
		if (err || once)
			break;
	}
out:
	nsmgr_destroy(mgr);
	report_destroy(report);
	if (err)
		fprintf(stderr, "unpa: %s: %s\n", where, strerror(-err));
	return err ? 1 : 0;
bad_arg:
	fprintf(stderr, "unpa: invalid argument: %s\n", optarg);
	return 2;
}

int main(int argc, char **argv)
{
	return run(argc, argv);
}
