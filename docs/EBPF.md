# UNPA eBPF (0.6.2.1)

A native rewrite of UNPA for Linux hypervisor hosts (KVM/QEMU, containers, network namespaces). A small passive eBPF program counts packets in the kernel. A C reporter turns the counts into a TUI, a JSON stream and a long-term flow log. It is built for runs that last hours or days, where you come back to read the table.

## How it works

- **Sensor** (`ebpf/unpa.bpf.c`): a TC classifier on `clsact` that always returns `TC_ACT_UNSPEC`. It never drops, redirects or edits a packet. It parses Ethernet, IPv4 and IPv6 (and L3-only links such as tun/wireguard) and counts packets and bytes per flow and per link. Bytes are `skb->len`, not wire bytes.
- **Direction** is from the guest's side. Ingress on a host TAP is guest **TX**. Egress is guest **RX**.
- **Namespaces** (`ebpf/nsmgr.c`): with `-a`, UNPA finds every network namespace, enters each with `setns()`, and loads and attaches one BPF object per namespace. It rescans every couple of seconds, so new interfaces, VMs and containers are picked up live.
- **Reporter** (`ebpf/report.c`, `ebpf/classic.inc`): copies flows out of the kernel's LRU map into an unbounded user-space table, so flows survive kernel eviction. Flows that go idle move from *Live* to *History* and keep their first-seen, last-seen and totals.

## Build

Needs Linux 5.x or later with BTF, `clang`, `libbpf-dev`, `pkg-config` and a C compiler.

```bash
sudo apt install clang libbpf-dev pkg-config
make          # builds build/unpa and build/unpa.bpf.o (both needed at runtime)
make check    # CLI sanity checks
```

Builds use `-Wall -Wextra -Werror`.

## Run

Run as root. Keep `build/unpa.bpf.o` beside the binary, or pass `--object`.

```bash
sudo build/unpa -a                           # all interfaces, all namespaces
sudo build/unpa -a --log ~/unpa-history.log  # also keep a flow log for later analysis
sudo build/unpa -i tapfff2331e=myvm          # one interface, with a label
sudo build/unpa -a --json -t 5               # one JSON object per sample
```

| Option | Description |
|---|---|
| `-a`, `--all` | Every interface in every namespace; rescans periodically |
| `-i IFACE[=VM]` | Watch one interface, with an optional label (repeatable) |
| `--loopback` | With `-a`, include `lo` |
| `-t SEC` | Sample interval (default 1) |
| `-c N` | Max flow rows in plain/JSON output (default 20) |
| `-ii CIDR`, `-ee CIDR` | Include or exclude flows by either endpoint (IPv4/IPv6). Exclusions win and do not change link totals |
| `--idle SEC` | A flow is inactive after this long (default 5) |
| `--history N` | Cap remembered flows. **Default: keep everything** |
| `--log FILE` | Append idle/final flow records as JSON lines |
| `--json`, `--once` | Machine output; exit after one sample |
| `--priority N`, `--object FILE` | TC filter priority; path to the BPF object |

## TUI

Views: `1` Classic (Python-style, grouped by interface, default), `2` Live flows, `3` History, `4` Interfaces, `5` Namespaces. `Tab` cycles.

| Key | Action |
|---|---|
| `s` | Cycle sort: rate, **total bytes**, packets, last seen |
| `r` | Reverse sort |
| `g` / `x` | Flat or grouped list / expand rows |
| `p` | Pause |
| `c` | Clear history |
| `?` | Help |
| `q` | Quit |

`NO_COLOR` turns colour off.

## Long-term use

History is never evicted unless you set `--history N`. Anything dropped by that cap is counted and shown in the UI. For a record that outlives the process, use `--log FILE`. Each line is one flow:

```json
{"first":1.0,"last":9.2,"ns":"host","iface":"tap0","dir":"TX","family":4,"proto":6,"src":"10.0.0.2","sport":443,"dst":"10.0.0.9","dport":5000,"packets":120,"bytes":98000}
```

## Limits

- Veth pairs and bridges are counted once per interface, so the totals strip counts that traffic twice.
- The kernel flow map holds 32,768 entries. A burst larger than that between two scans can lose flows before they are copied.
- TC sees `skb->len`, not wire bytes. There is no per-process or DNS view.
- It targets standard Linux KVM/QEMU hosts using public kernel interfaces. It does not claim to match any cloud provider's production stack.
- The TUI has had little interactive testing. Reports are welcome.
