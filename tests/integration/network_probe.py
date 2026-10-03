"""Run a command inside an isolated network namespace and report every connection it attempts.

Not a test module: `test_offline_guarantee.py` launches it under
`unshare --user --map-root-user --net`. Standard library only, because it
runs as a bare `python3` inside the namespace.

The namespace has no real interface. A `local` default route makes every
outgoing packet, to any address, loop back through `lo`, where an
`AF_PACKET` socket records it: TCP SYNs and UDP datagrams, any destination,
any port. This observes a tool that ignores proxy variables or dials an IP
literal, which a proxy-based listener would miss; DNS queries are recorded
too (a lookup is already a network attempt, even when the resolver is a
loopback stub). Connections to `127.0.0.0/8` / `::1` other than DNS are not
attempts to leave the machine and are ignored.

Usage: network_probe.py <json: {"argv": [...], "env": {...}, "cwd": "..."}>
Prints one JSON object: exit_code, stdout, stderr, attempts.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading

_ETH_P_ALL = 0x0003
_ETH_P_IP = 0x0800
_ETH_P_IPV6 = 0x86DD
_DNS_PORT = 53
_TCP, _UDP = 6, 17
_SYN, _ACK = 0x02, 0x10


def _setup_routes() -> None:
    for argv in (
        ["ip", "link", "set", "lo", "up"],
        ["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo"],
        ["ip", "-6", "route", "add", "local", "::/0", "dev", "lo"],
    ):
        subprocess.run(argv, check=argv[1] != "-6", capture_output=True)  # noqa: S603


def _record(attempts: set[str], proto: int, dst: str, dport: int, flags: int) -> None:
    is_syn = proto == _TCP and flags & _SYN and not flags & _ACK
    if not (is_syn or proto == _UDP):
        return
    if ipaddress.ip_address(dst).is_loopback and dport != _DNS_PORT:
        return
    attempts.add(f"{'tcp' if proto == _TCP else 'udp'} {dst}:{dport}")


def _sniff(attempts: set[str], stop: threading.Event, ready: threading.Event) -> None:
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
    sniffer.bind(("lo", 0))
    sniffer.settimeout(0.1)
    ready.set()
    while not stop.is_set():
        try:
            frame = sniffer.recv(65535)
        except TimeoutError:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        packet = frame[14:]
        if ethertype == _ETH_P_IP and len(packet) >= 20:
            header_len = (packet[0] & 0x0F) * 4
            proto, dst = packet[9], socket.inet_ntop(socket.AF_INET, packet[16:20])
            segment = packet[header_len:]
        elif ethertype == _ETH_P_IPV6 and len(packet) >= 40:
            proto, dst = packet[6], socket.inet_ntop(socket.AF_INET6, packet[24:40])
            segment = packet[40:]
        else:
            continue
        if proto == _TCP and len(segment) >= 14:
            _record(attempts, proto, dst, struct.unpack("!H", segment[2:4])[0], segment[13])
        elif proto == _UDP and len(segment) >= 8:
            _record(attempts, proto, dst, struct.unpack("!H", segment[2:4])[0], 0)


def main() -> None:
    spec = json.loads(sys.argv[1])
    _setup_routes()
    attempts: set[str] = set()
    stop, ready = threading.Event(), threading.Event()
    thread = threading.Thread(target=_sniff, args=(attempts, stop, ready), daemon=True)
    thread.start()
    ready.wait()
    env = {**os.environ, **spec["env"]}
    try:
        done = subprocess.run(  # noqa: S603
            spec["argv"], env=env, cwd=spec["cwd"], capture_output=True, text=True, check=False
        )
        outcome = (done.returncode, done.stdout, done.stderr)
    except FileNotFoundError as exc:
        outcome = (127, "", f"binary not found: {exc}")
    stop.set()
    thread.join()
    print(
        json.dumps(
            {
                "exit_code": outcome[0],
                "stdout": outcome[1],
                "stderr": outcome[2],
                "attempts": sorted(attempts),
            }
        )
    )


if __name__ == "__main__":
    main()
