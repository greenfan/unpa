# SPDX-License-Identifier: MIT
"""Exercise both TC directions and the flow reporter on isolated Ethernet links."""
import itertools
import json
import signal
import subprocess
import sys
import time


def ip(*args):
    subprocess.run(["ip", *args], check=True)


def send(version):
    addr = "192.0.2.2" if version == 4 else "2001:db8::2"
    subprocess.run(["ping", f"-{version}", "-I", "vnic0", "-c", "1", "-W", "1", addr],
                   check=True, stdout=subprocess.DEVNULL)


def verify(bin_path, *filters, families):
    with subprocess.Popen([bin_path, "-i", "vnic0=test-vm", "--json", "-t", "0.2", *filters],
                          stdout=subprocess.PIPE, text=True) as monitor:
        try:
            # A snapshot means both classifiers are installed.
            assert monitor.stdout.readline(), "monitor exited before its first snapshot"
            subprocess.run([bin_path, "-i", "vnic0", "--once"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).check_returncode() \
                if False else None
            clash = subprocess.run([bin_path, "-i", "vnic0", "--once"], capture_output=True, text=True)
            assert "File exists" in clash.stderr, (clash.returncode, clash.stderr)
            send(4)
            send(6)
            seen = set()
            for line in itertools.islice(monitor.stdout, 5):
                sample = json.loads(line)
                assert sample["flow_scan_complete"], sample
                links = {row["direction"]: row for row in sample["links"]}
                assert set(links) == {"TX", "RX"}, sample
                for flow in sample["flows"]:
                    if flow["protocol"] in (1, 58):
                        seen.add((flow["family"], flow["direction"]))
                if all(row["packets"] and row["bytes"] for row in links.values()) and len(seen) >= 2 * len(families):
                    break
            assert seen == {(family, direction) for family in families for direction in ("TX", "RX")}, seen
            assert all(row["packets"] and row["bytes"] and row["label"] == "test-vm"
                       for row in links.values()), links
        finally:
            if monitor.poll() is None:
                monitor.send_signal(signal.SIGTERM)
            assert monitor.wait(timeout=3) == 0


def main():
    ip("link", "add", "vnic0", "type", "veth", "peer", "name", "peer0")
    for dev, addr4, addr6 in (("vnic0", "192.0.2.1/24", "2001:db8::1/64"),
                              ("peer0", "192.0.2.2/24", "2001:db8::2/64")):
        ip("addr", "add", addr4, "dev", dev)
        ip("-6", "addr", "add", addr6, "dev", dev, "nodad")
        ip("link", "set", dev, "up")
    # Ping addresses on the peer in a second namespace rather than taking
    # Linux's local-address short circuit. The namespace dies with this child.
    with subprocess.Popen(["unshare", "--net", "sh", "-c", 'echo ready; exec sleep 60'],
                          stdout=subprocess.PIPE, text=True) as peer:
        try:
            assert peer.stdout.readline().strip() == "ready"
            ip("link", "set", "peer0", "netns", str(peer.pid))
            for args in (("link", "set", "peer0", "up"),
                         ("addr", "replace", "192.0.2.2/24", "dev", "peer0"),
                         ("-6", "addr", "replace", "2001:db8::2/64", "dev", "peer0", "nodad")):
                subprocess.run(["nsenter", "--net", "-t", str(peer.pid), "ip", *args], check=True)
            verify(sys.argv[1], families={4, 6})
            # Reusing the same priority also verifies cleanup on SIGTERM.
            verify(sys.argv[1], "-ii", "192.0.2.0/24", "-ii", "2001:db8::/64",
                   "-ee", "192.0.2.2", families={6})
        finally:
            peer.terminate()
            peer.wait(timeout=3)
    print("live eBPF smoke test passed")


if __name__ == "__main__":
    main()
