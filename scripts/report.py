#!/usr/bin/env python3
"""Incremental honeypot report: summarise log lines written since the last run.

Reads /var/log/llm-honeypot/requests.jsonl from a saved byte offset, prints a
per-IP summary of the new requests (reverse DNS, ASN/network owner, TLS
fingerprint, user-agents, models, keys, prompt excerpts) and advances the
offset. Safe across log rotation (resets the offset when the file shrinks).

Enrichment is passive: a PTR lookup and a Team Cymru DNS TXT query per new IP.
Nothing is ever sent to the visitor. Results are cached, and every IP ever seen
is kept in a small history file (first/last seen, request count).
"""
import collections
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import time

LOG = os.environ.get("HONEYPOT_LOG", "/var/log/llm-honeypot/requests.jsonl")
STATE = os.environ.get("HONEYPOT_STATE", "/var/lib/llm-honeypot")
CUR = os.path.join(STATE, "report.offset")
INTEL = os.path.join(STATE, "intel.json")
HIST = os.path.join(STATE, "history.json")
IGNORE = [p for p in os.environ.get("HONEYPOT_IGNORE", "").split(",") if p]


def load(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default


def save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    json.dump(obj, open(tmp, "w"))
    os.replace(tmp, path)


def txt(name):
    try:
        out = subprocess.run(["host", "-W", "3", "-t", "TXT", name],
                             capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if "descriptive text" in line:
            return line.split("descriptive text", 1)[1].strip().strip('"')
    return None


def cymru_name(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nib = a.exploded.replace(":", "")
    return ".".join(reversed(nib)) + ".origin6.asn.cymru.com"


def enrich(ip):
    info = {}
    socket.setdefaulttimeout(4)
    try:
        info["rdns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        info["rdns"] = None
    try:
        origin = txt(cymru_name(ip))  # "ASN | prefix | CC | registry | date"
        if origin:
            asn, prefix, cc = [x.strip() for x in origin.split("|")[:3]]
            asn = asn.split()[0]
            info.update(asn=asn, prefix=prefix, cc=cc)
            desc = txt("AS%s.asn.cymru.com" % asn)
            if desc:
                info["as_name"] = desc.split("|")[-1].strip()
    except Exception:
        pass
    return info


def last_user_prompt(body):
    try:
        d = json.loads(body)
    except Exception:
        return body[:200] if body else None
    if isinstance(d, dict):
        msgs = d.get("messages")
        if isinstance(msgs, list) and msgs:
            for m in reversed(msgs):
                if isinstance(m, dict) and m.get("role") == "user":
                    c = m.get("content")
                    return (c if isinstance(c, str) else json.dumps(c))[:300]
        for k in ("prompt", "input"):
            if d.get(k):
                return str(d[k])[:300]
    return None


def tls_fp(d):
    h = {k.lower(): v for k, v in d.get("headers") or []}
    parts = [h.get("x-honeypot-tls-proto", ""), h.get("x-honeypot-tls-ciphers", ""),
             h.get("x-honeypot-tls-curves", "")]
    if not any(parts):
        return None
    return h.get("x-honeypot-tls-proto", "?") + ":" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def main():
    off = load(CUR, 0)
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
            save(CUR, f.tell())

    new = [d for d in new if "ip" in d and not any(d["ip"].startswith(p) for p in IGNORE)]
    if not new:
        print("NEW=0")
        return

    intel, hist = load(INTEL, {}), load(HIST, {})
    ips = collections.defaultdict(lambda: {
        "n": 0, "ua": set(), "models": set(), "keys": set(), "tls": set(),
        "paths": collections.Counter(), "prompts": [],
    })
    chat = 0
    for d in new:
        ip = d["ip"]
        e = ips[ip]
        e["n"] += 1
        h = hist.setdefault(ip, {"first": d.get("ts"), "n": 0})
        h["last"], h["n"] = d.get("ts"), h["n"] + 1
        ua = d.get("ua")
        if ua and ua != "-":
            e["ua"].add(ua[:80])
        if d.get("model"):
            e["models"].add(str(d["model"])[:40])
        if d.get("api_key"):
            e["keys"].add(str(d["api_key"])[:24])
        fp = tls_fp(d)
        if fp:
            e["tls"].add(fp)
        path = (d.get("path") or "?").split("?")[0]
        e["paths"]["%s %s" % (d.get("method"), path)] += 1
        if d.get("method") == "POST":
            chat += 1
            p = last_user_prompt(d.get("body") or "")
            if p and p not in e["prompts"] and len(e["prompts"]) < 3:
                e["prompts"].append(p)

    for ip in ips:
        if ip not in intel:
            intel[ip] = enrich(ip)
            intel[ip]["at"] = int(time.time())
    save(INTEL, intel)
    save(HIST, hist)

    print("NEW=%d posts=%d unique_ips=%d known_ips_total=%d" % (len(new), chat, len(ips), len(hist)))
    for ip, e in sorted(ips.items(), key=lambda kv: -kv[1]["n"]):
        i, h = intel.get(ip, {}), hist[ip]
        print("- %s n=%d (total %d, first %s) rdns=%s AS%s %s [%s] %s" % (
            ip, e["n"], h["n"], time.strftime("%m-%d %H:%M", time.gmtime(h["first"] or 0)),
            i.get("rdns"), i.get("asn", "?"), i.get("as_name", "?"), i.get("cc", "?"), i.get("prefix", ""),
        ))
        print("    ua=%s tls=%s" % (sorted(e["ua"]) or ["-"], sorted(e["tls"])))
        print("    paths=%s" % dict(e["paths"]))
        if e["models"] or e["keys"]:
            print("    models=%s keys=%s" % (sorted(e["models"]), sorted(e["keys"])))
        for p in e["prompts"]:
            print("    prompt: %r" % p)


if __name__ == "__main__":
    main()
