#!/usr/bin/env python3

import argparse
import csv
import os
import subprocess
import sys
from collections import defaultdict

DNS_PORT, HTTP_PORT, DOH_PORT = 5300, 8053, 8443
MARKER = "anonimitate"
VARIANTS = ["dns_udp", "http_plain", "doh", "doh_pad"]
TLS_OVERHEAD = 17         


def run_tshark(tshark, pcap, display_filter, fields):
    cmd = [tshark, "-r", pcap,
           "-d", f"udp.port=={DNS_PORT},dns", "-d", f"tcp.port=={HTTP_PORT},http",
           "-d", f"tcp.port=={DOH_PORT},tls",
           "-Y", display_filter, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"tshark error: {res.stderr.strip()}")
    return [line.split("|") for line in res.stdout.splitlines() if line.strip()]


def ints(text):
    return [int(x) for x in text.split(",") if x != ""]


def marker_ports(tshark, pcap, proto, server_port):
    """Client ports of conversations in which the marker string appears in ANY packet."""
    rows = run_tshark(tshark, pcap, f'{proto}.port=={server_port} && frame contains "{MARKER}"',
                      [f"{proto}.srcport", f"{proto}.dstport"])
    ports = set()
    for src, dst in rows:
        ports.add(int(dst) if int(src) == server_port else int(src))
    return ports


def linfit(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0:
        return None
    slope = sxy / sxx
    return slope, my - slope * mx, (sxy * sxy / (sxx * syy) if syy > 0 else None)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("queries")
    ap.add_argument("--tshark", default="tshark")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    # ---- observed sizes, keyed by client port
    udp = {int(p): int(l) - 8 for p, l in run_tshark(args.tshark, args.pcap, f"udp.dstport=={DNS_PORT}",
                                                     ["udp.srcport", "udp.length"])}
    http = defaultdict(int)
    for p, l in run_tshark(args.tshark, args.pcap, f"tcp.dstport=={HTTP_PORT} && tcp.len>0",
                           ["tcp.srcport", "tcp.len"]):
        http[int(p)] += int(l)
    tls_records, client_hello = defaultdict(list), {}
    for p, ctype, lens in run_tshark(args.tshark, args.pcap, f"tcp.dstport=={DOH_PORT} && tls.record.length",
                                     ["tcp.srcport", "tls.record.content_type", "tls.record.length"]):
        if "22" in ctype.split(","):
            client_hello[int(p)] = ints(lens)[0]
        else:
            tls_records[int(p)] += ints(lens)
    sni = {int(p): s for p, s in run_tshark(args.tshark, args.pcap, "tls.handshake.type==1",
                                            ["tcp.srcport", "tls.handshake.extensions_server_name"]) if s}

    visible = {"dns_udp": marker_ports(args.tshark, args.pcap, "udp", DNS_PORT),
               "http_plain": marker_ports(args.tshark, args.pcap, "tcp", HTTP_PORT)}
    visible["doh"] = visible["doh_pad"] = marker_ports(args.tshark, args.pcap, "tcp", DOH_PORT)

    # ---- join with the query log
    with open(args.queries, newline="") as f:
        queries = list(csv.DictReader(f))
    obs = []
    for q in queries:
        v, port = q["variant"], int(q["client_port"])
        L, dns_len, http_len = int(q["name_len"]), int(q["dns_len"]), int(q["http_len"])
        if v == "dns_udp":
            size, expected = udp.get(port), dns_len
        elif v == "http_plain":
            size, expected = http.get(port), http_len
        else:
            size = max(tls_records[port]) if tls_records.get(port) else None
            expected = http_len + TLS_OVERHEAD
        obs.append({"variant": v, "rep": q["rep"], "name_len": L, "client_port": port,
                    "observed": size, "expected": expected,
                    "marker_visible": int(port in visible[v]),
                    "sni": sni.get(port, ""), "client_hello": client_hello.get(port, "")})

    with open(os.path.join(args.out, "observations.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(obs[0].keys()))
        w.writeheader()
        w.writerows(obs)


    lines = []
    out = lambda s="": (print(s), lines.append(s))
    out("## Summary per variant")
    out("| variant | queries | captured | marker visible | observed == model | slope (B/char) | intercept | R^2 |")
    out("|---|---|---|---|---|---|---|---|")
    fits = {}
    for v in VARIANTS:
        rows = [o for o in obs if o["variant"] == v]
        cap = [o for o in rows if o["observed"] is not None]
        match = sum(o["observed"] == o["expected"] for o in cap)
        vis = sum(o["marker_visible"] for o in rows)
        fit = linfit([o["name_len"] for o in cap], [o["observed"] for o in cap]) if cap else None
        fits[v] = fit
        s = "n/a" if fit is None else f"{fit[0]:.3f}"
        b = "n/a" if fit is None else f"{fit[1]:.1f}"
        r2 = "n/a" if fit is None else ("constant" if fit[2] is None else f"{fit[2]:.4f}")
        out(f"| {v} | {len(rows)} | {len(cap)} | {vis}/{len(rows)} | {match}/{len(cap)} | {s} | {b} | {r2} |")

    out()
    out("## TLS metadata visible to the observer (doh, doh_pad)")
    hello = [o["client_hello"] for o in obs if o["variant"] in ("doh", "doh_pad") and o["client_hello"] != ""]
    snis = sorted({o["sni"] for o in obs if o["variant"] in ("doh", "doh_pad")})
    out(f"- SNI values seen in ClientHello: {snis}")
    out(f"- ClientHello record length: min {min(hello)} B, max {max(hello)} B" if hello else "- no ClientHello found")

    lens = sorted({o["name_len"] for o in obs})
    out()
    out("## Mean observed size (bytes) by domain-name length")
    out("| name length L | " + " | ".join(VARIANTS) + " |")
    out("|---|" + "---|" * len(VARIANTS))
    for L in lens:
        cells = []
        for v in VARIANTS:
            vals = [o["observed"] for o in obs if o["variant"] == v and o["name_len"] == L and o["observed"] is not None]
            cells.append(f"{sum(vals) / len(vals):.1f}" if vals else "n/a")
        out(f"| {L} | " + " | ".join(cells) + " |")

    with open(os.path.join(args.out, "results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        plt.figure(figsize=(7, 4.5))
        marks = {"dns_udp": "o", "http_plain": "s", "doh": "^", "doh_pad": "x"}
        for v in VARIANTS:
            pts = [(o["name_len"], o["observed"]) for o in obs if o["variant"] == v and o["observed"] is not None]
            if pts:
                plt.scatter(*zip(*pts), marker=marks[v], label=v, alpha=0.7)
        plt.xlabel("domain name length L (characters)")
        plt.ylabel("size seen by the observer (bytes)")
        plt.grid(alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(args.out, "plot.png"), dpi=200)
        print(f"\nPlot: {os.path.join(args.out, 'plot.png')}")
    except ImportError:
        print("\n(matplotlib not installed - plot skipped: pip install matplotlib)")


if __name__ == "__main__":
    main()