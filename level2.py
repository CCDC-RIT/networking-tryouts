#!/usr/bin/env python3
"""
usage: python thisfile.py
Tested on ubuntu and windows. Contact the CCDC team if it's not working




STOP STOP STOP STOP STOP
STOP STOP STOP STOP STOP
STOP STOP STOP STOP STOP

Do not view this file until you have completed CCDC Tryouts 2025 Networking Level 2 or unless a CCDC team member tells you too!

Ask us for help if you cannot identify the malicious traffic!

Note: this is 100% vibe coded and I do not apologize



"""































"""
lab_traffic_gen_quiet_systemdns.py

Quiet lab traffic generator:
- Sends UDP packets to IP targets in TARGETS.
- For EXTERNAL_HOSTNAMES: if ALLOW_EXTERNAL=True and the name resolves,
  sends UDP packets to the resolved IP. If it does not resolve (or
  ALLOW_EXTERNAL=False), repeatedly performs system DNS lookups
  (socket.getaddrinfo) for that hostname so lookups show in system/DNS logs.
- Prints only "Started" at launch and "Finished" on graceful shutdown.
"""

import socket
import threading
import time
import random
import signal
from concurrent.futures import ThreadPoolExecutor

# --------------------- CONFIG (edit if needed) ---------------------
ALLOW_EXTERNAL = False   # False by default, do not contact external hostnames directly

TARGETS = [
    ("203.0.113.99", 80),   # TEST-NET-3 (safe for lab documentation)
    ("203.0.113.25", 31337),
    ("67.67.67.67", 821),
    ("1.2.3.4", 1337)
]

EXTERNAL_HOSTNAMES = [
    ("c2callback.net", 443),
    ("badguy.xyz", 22),
    ("stackoverflow.net", 1582),
    ("gumper.lol", 9999)
]

WORKER_COUNT = 8
DELAY_MIN = 0.1
DELAY_MAX = 0.6
PORTS = [53, 80, 443, 12345]
PAYLOAD = b"LAB-Traffic-Test\n"
# ------------------------------------------------------------------

_stop_event = threading.Event()

def _signal_handler(sig, frame):
    _stop_event.set()

signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

def resolve_targets():
    """
    Resolve static TARGETS (IPs assumed) and attempt to resolve EXTERNAL_HOSTNAMES
    if ALLOW_EXTERNAL True. Return:
      - send_targets: list of (ip, port) to send UDP packets to
      - unresolved_hostnames: list of hostnames that should receive repeated system DNS lookups
    """
    send_targets = []
    unresolved = []

    for host_or_ip, port in TARGETS:
        try:
            # If dotted IPv4 address, accept it directly
            socket.inet_pton(socket.AF_INET, host_or_ip)
            send_targets.append((host_or_ip, port))
        except Exception:
            try:
                infos = socket.getaddrinfo(host_or_ip, port, proto=socket.IPPROTO_UDP)
                ip = infos[0][4][0]
                send_targets.append((ip, port))
            except Exception:
                # treat as unresolved silently
                unresolved.append((host_or_ip, port))

    for host, port in EXTERNAL_HOSTNAMES:
        if ALLOW_EXTERNAL:
            try:
                infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_UDP)
                ip = infos[0][4][0]
                send_targets.append((ip, port))
            except Exception:
                unresolved.append((host, port))
        else:
            # Do not contact external hosts directly; cause system DNS lookups instead
            unresolved.append((host, port))

    # deduplicate send targets
    seen = set()
    unique = []
    for ip, port in send_targets:
        if (ip, port) not in seen:
            seen.add((ip, port))
            unique.append((ip, port))
    return unique, unresolved

def worker_send_loop(worker_id, targets):
    """
    UDP sender worker: repeatedly sends small UDP payloads to targets.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
    except Exception:
        return
    rng = random.Random(worker_id + int(time.time()))
    if not targets:
        try:
            sock.close()
        except Exception:
            pass
        return
    while not _stop_event.is_set():
        try:
            ip, base_port = rng.choice(targets)
            port = rng.choice(PORTS) if base_port == 0 else base_port
            pkt = PAYLOAD + f"worker={worker_id} t={time.time():.3f} rand={rng.randint(0,99999)}\n".encode()
            sock.sendto(pkt, (ip, port))
        except Exception:
            pass
        time.sleep(rng.uniform(DELAY_MIN, DELAY_MAX))
    try:
        sock.close()
    except Exception:
        pass

def dns_system_query_loop(hostname, worker_id=0):
    """
    Repeatedly perform system resolver lookups (socket.getaddrinfo) for hostname.
    This relies on the system's configured DNS resolver.
    """
    rng = random.Random(worker_id + int(time.time()))
    while not _stop_event.is_set():
        try:
            # perform a lookup that is likely to hit the system resolver
            # the port argument is None so only name resolution occurs
            socket.getaddrinfo(hostname, None)
        except Exception:
            pass
        time.sleep(rng.uniform(DELAY_MIN, DELAY_MAX))

def run():
    send_targets, unresolved = resolve_targets()

    max_workers = max(WORKER_COUNT, len(unresolved) + 1)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        if send_targets:
            for i in range(WORKER_COUNT):
                futures.append(ex.submit(worker_send_loop, i, send_targets))

        dns_worker_id = 1000
        for host, _ in unresolved:
            futures.append(ex.submit(dns_system_query_loop, host, dns_worker_id))
            dns_worker_id += 1

        try:
            while not _stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            _stop_event.set()

        # allow threads a short time to finish
        for f in futures:
            try:
                f.result(timeout=2)
            except Exception:
                pass

if __name__ == "__main__":
    # Only allowed console output per user instruction:
    print("Started")
    run()
    print("Finished")
