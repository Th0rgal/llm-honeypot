#!/usr/bin/env python3
"""Incremental honeypot report: summarise log lines written since the last run.

Reads /var/log/llm-honeypot/requests.jsonl from a saved byte offset, prints a
compact per-IP summary of the new requests, and advances the offset. Safe across
log rotation (resets the offset when the file shrinks).
"""
import collections
import json
import os

LOG = os.environ.get("HONEYPOT_LOG", "/var/log/llm-honeypot/requests.jsonl")
CUR = os.environ.get("HONEYPOT_CURSOR", "/var/lib/llm-honeypot/report.offset")


def read_offset():
    try:
        return int(open(CUR).read().strip())
    except Exception:
        return 0


def main():
    off = read_offset()
    size = os.path.getsize(LOG) if os.path.exists(LOG) else 0
    if off > size:
        off = 0
    new = []
    if os.path.exists(LOG):
        with open(LOG, "r", errors="replace") as f:
            f.seek(off)
            for line in f:
                line = line.strip()
                if line:
                    try:
                        new.append(json.loads(line))
                    except Exception:
                        pass
            os.makedirs(os.path.dirname(CUR), exist_ok=True)
            open(CUR, "w").write(str(f.tell()))

    if not new:
        print("NEW=0")
        return

    ips = collections.defaultdict(lambda: {
        "n": 0, "ua": set(), "models": set(), "keys": set(),
        "paths": collections.Counter(),
    })
    chat = 0
    for d in new:
        e = ips[d.get("ip", "?")]
        e["n"] += 1
        ua = d.get("ua")
        if ua and ua != "-":
            e["ua"].add(ua[:50])
        if d.get("model"):
            e["models"].add(str(d["model"])[:40])
        if d.get("api_key"):
            e["keys"].add(str(d["api_key"])[:24])
        path = (d.get("path") or "?").split("?")[0]
        e["paths"][path] += 1
        if "chat" in path or "generate" in path or "completions" in path:
            chat += 1

    print("NEW=%d chat_requests=%d unique_ips=%d" % (len(new), chat, len(ips)))
    for ip, e in sorted(ips.items(), key=lambda kv: -kv[1]["n"]):
        print("- %s n=%d ua=%s models=%s keys=%s paths=%s" % (
            ip, e["n"], sorted(e["ua"]) or ["-"], sorted(e["models"]),
            sorted(e["keys"]), dict(e["paths"]),
        ))


if __name__ == "__main__":
    main()
