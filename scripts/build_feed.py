#!/usr/bin/env python3
"""Daily Threat Watch: build a static page from public data.

Sources (all public, no key needed):
  CISA KEV    bugs that attackers are already using
  NVD         newly published critical CVEs (an optional NVD_API_KEY is faster)
  FIRST EPSS  estimated chance a bug is attacked in the next 30 days

Writes:
  <out>/index.html      latest edition
  <out>/archive/        older editions, rebuilt from <data>/*.json
  <out>/analysis.html   copied from the repo root when that file exists
Saves:
  <data>/YYYY-MM-DD.json   one snapshot per edition (the workflow commits it)

Standard library only. Python 3.9 or newer.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except Exception:  # very old Python: skip the Sydney time
    ZoneInfo = None

REPO_URL = "https://github.com/rpkjS1-hash/threat-brief"
UA = "daily-threat-watch/1.0 (+" + REPO_URL + ")"

KEV_URLS = [
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

WINDOW_DAYS = 7        # how far back to look
KEV_MIN_ITEMS = 5      # if the window is quiet, still show this many
KEV_MAX_ITEMS = 40
NVD_TOP = 15           # critical CVEs to show, ranked by exploit likelihood
EPSS_CHUNK = 4         # FIRST ignores the filter with more IDs per call
EPSS_MAX_IDS = 200
KEEP_SNAPSHOTS = 120

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------

def get_json(url, params=None, headers=None, retries=3, wait=8, timeout=60):
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    hdr = {"User-Agent": UA, "Accept": "application/json"}
    hdr.update(headers or {})
    err = None
    for n in range(retries):
        try:
            req = urllib.request.Request(url, headers=hdr)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - we retry and then report
            err = exc
            if n < retries - 1:
                time.sleep(wait * (n + 1))
    raise RuntimeError("request failed (%s): %s" % (url.split("?")[0], err))


def fetch_kev(fix):
    if fix:
        return json.loads((fix / "kev.json").read_text("utf-8"))
    last = None
    for url in KEV_URLS:
        try:
            data = get_json(url, retries=2, wait=5, timeout=90)
            if isinstance(data.get("vulnerabilities"), list) and data["vulnerabilities"]:
                return data
        except Exception as exc:  # noqa: BLE001
            last = exc
    raise RuntimeError("could not download the KEV catalog: %s" % last)


def iso_ms(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_nvd(rec):
    cve = (rec or {}).get("cve") or {}
    cid = cve.get("id", "")
    if not CVE_RE.match(cid):
        return None
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    best = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)) and (best is None or score > best[0]):
                who = "NVD" if m.get("source") == "nvd@nist.gov" else "CNA"
                best = (float(score), str(data.get("version", "")), who)
    cwes = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    return {
        "id": cid,
        "published": (cve.get("published") or "")[:10],
        "desc": desc,
        "score": best[0] if best else None,
        "cvss_version": best[1] if best else "",
        "scored_by": best[2] if best else "",
        "cwes": cwes,
    }


def fetch_nvd(start, end, api_key, fix):
    """Return (records by CVE id, error text or None)."""
    out = {}
    if fix:
        if (fix / "nvd.fail").exists():
            return {}, "NVD did not answer."
        for name in ("nvd_v3.json", "nvd_v4.json"):
            p = fix / name
            if p.exists():
                for rec in json.loads(p.read_text("utf-8")).get("vulnerabilities", []):
                    r = parse_nvd(rec)
                    if r:
                        out.setdefault(r["id"], r)
        return out, None
    errors, ok = [], 0
    for sev in ("cvssV3Severity", "cvssV4Severity"):
        params = {
            "pubStartDate": iso_ms(start),
            "pubEndDate": iso_ms(end),
            sev: "CRITICAL",
            "resultsPerPage": 2000,
        }
        try:
            data = get_json(NVD_URL, params, {"apiKey": api_key} if api_key else None,
                            retries=4, wait=15, timeout=90)
            for rec in data.get("vulnerabilities", []):
                r = parse_nvd(rec)
                if r:
                    out.setdefault(r["id"], r)
            ok += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
        time.sleep(1 if api_key else 7)  # NVD allows 5 calls per 30 s without a key
    if ok == 0:
        return {}, "NVD did not answer."
    return out, ("Partial NVD data: one of two queries failed." if errors else None)


def fetch_epss(ids, fix):
    """Return ({cve: (epss, percentile)}, date string). Quietly returns less on failure."""
    ids = sorted({i for i in ids if CVE_RE.match(i)})[:EPSS_MAX_IDS]
    scores, dates = {}, set()
    if fix:
        p = fix / "epss.json"
        if p.exists():
            table = json.loads(p.read_text("utf-8"))
            for i in ids:
                if i in table:
                    scores[i] = (float(table[i][0]), float(table[i][1]))
            dates.add("2026-10-30")
        return scores, (max(dates) if dates else "")

    def ask(batch):
        data = get_json(EPSS_URL, {"cve": ",".join(batch)}, retries=2, wait=4, timeout=30)
        rows = data.get("data") or []
        honoured = data.get("total") == len(rows) and all(r.get("cve") in batch for r in rows)
        return rows, honoured

    for i in range(0, len(ids), EPSS_CHUNK):
        batch = ids[i:i + EPSS_CHUNK]
        try:
            rows, honoured = ask(batch)
            if not honoured:  # the filter was ignored: ask one by one
                rows = []
                for one in batch:
                    r, ok = ask([one])
                    if ok:
                        rows += r
            for r in rows:
                try:
                    scores[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
                    if r.get("date"):
                        dates.add(str(r["date"]))
                except (KeyError, TypeError, ValueError):
                    continue
        except Exception:  # noqa: BLE001
            continue
        time.sleep(0.3)
    return scores, (max(dates) if dates else "")


# --------------------------------------------------------------------------
# Plain-English helper (simple rules, not AI)
# --------------------------------------------------------------------------

IMPACT = [
    (r"remote code execution|arbitrary code|execute (?:arbitrary )?(?:code|commands?)|"
     r"run (?:arbitrary )?(?:code|commands?)|command injection|code injection|os command|remote command",
     "An attacker could run their own commands on the affected system."),
    (r"authentication bypass|bypass(?:es|ing)? (?:the )?(?:authentication|authorization|login|access control)|"
     r"improper authentication|missing authentication|missing authorization|"
     r"forge[sd]? (?:a )?(?:valid )?(?:login |session |auth\w* )?tokens?",
     "An attacker could get in without a valid login."),
    (r"privilege escalation|escalat\w+ (?:of )?privileges?|elevat\w+ (?:of )?privileges?|"
     r"gain(?:s|ing)? (?:root|admin\w*|system) ",
     "A low-level user could gain admin or root rights."),
    (r"sql injection",
     "An attacker could read or change database records by sending crafted input."),
    (r"path traversal|directory traversal|arbitrary file (?:read|download)|local file inclusion|"
     r"read arbitrary files?",
     "An attacker could read files they should not be able to see."),
    (r"arbitrary file (?:write|upload|overwrite|creation)|unrestricted (?:file )?upload|"
     r"upload (?:a )?(?:malicious|arbitrary)",
     "An attacker could plant files on the system. That can lead to a full takeover."),
    (r"server-side request forgery|\bssrf\b",
     "An attacker could make the server send requests for them, for example into an internal network."),
    (r"deserializ",
     "The app trusts data it should not. Crafted data can make it do what the attacker chooses."),
    (r"cross-site scripting|\bxss\b",
     "An attacker could run script in a victim's browser while they use the site."),
    (r"cross-site request forgery|\bcsrf\b",
     "An attacker could trick a signed-in user into actions they did not intend."),
    (r"buffer overflow|out-of-bounds|use-after-free|heap overflow|stack overflow|memory corruption|"
     r"type confusion",
     "A memory bug. At worst it lets an attacker run code. Often it only crashes the program."),
    (r"hard-?coded (?:credentials?|passwords?|keys?)",
     "A fixed password or key is built in. Anyone who finds it can use it."),
    (r"information disclosure|disclos\w+ (?:of )?sensitive|expos\w+ sensitive|memory (?:disclosure|leak)|"
     r"leak\w* (?:sensitive|credentials|secrets|tokens)",
     "An attacker could see data that should stay private."),
    (r"denial[- ]of[- ]service|\bdos\b|crash|infinite loop|resource exhaustion",
     "An attacker could crash the service or make it unusable."),
]
IMPACT = [(re.compile(p, re.I), s) for p, s in IMPACT]
NEGATION = re.compile(r"\b(?:not|no|cannot|can't|never|unable)\b", re.I)
UNAUTH = re.compile(
    r"unauthenticated|without (?:any )?authentication|without logging in|no authentication|"
    r"does not require authentication|not require (?:any )?authentication|pre-?auth", re.I)
USERINT = re.compile(
    r"requires? user interaction|user interaction is required|victim (?:must|needs? to)|"
    r"(?:tricks?|tricking|convince\w*|lure\w*) (?:a |the )?user|if (?:a |the )?user (?:opens|clicks|visits|views)",
    re.I)


def explain(text):
    """One plain-English line built from keywords in the official description."""
    text = text or ""
    line = ""
    for rx, sentence in IMPACT:
        m = rx.search(text)
        if not m:
            continue
        before = text[max(0, m.start() - 25):m.start()]
        if NEGATION.search(before):
            continue
        line = sentence
        break
    if not line:
        return ""
    if UNAUTH.search(text) and "without a valid login" not in line:
        line += " No login is needed."
    if USERINT.search(text):
        line += " It needs a user to do something first, like click a link or open a file."
    return line


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

def cve_num(cve):
    """CVE-2026-76418 -> (2026, 76418), so IDs sort by number, not by text."""
    try:
        _, year, num = cve.split("-")
        return int(year), int(num)
    except ValueError:
        return 0, 0


def select_kev(now, kev):
    """Return (all valid entries newest first, entries to show, padded flag)."""
    since = (now - dt.timedelta(days=WINDOW_DAYS)).date().isoformat()
    vulns = [v for v in kev.get("vulnerabilities", []) if CVE_RE.match(str(v.get("cveID", "")))]
    vulns.sort(key=lambda v: (str(v.get("dateAdded", "")), cve_num(v["cveID"])), reverse=True)
    recent = [v for v in vulns if str(v.get("dateAdded", "")) > since]
    padded = False
    if len(recent) < KEV_MIN_ITEMS:
        recent, padded = vulns[:KEV_MIN_ITEMS], True
    return vulns, recent[:KEV_MAX_ITEMS], padded


def build_model(now, kev, nvd, nvd_err, epss, epss_date):
    today = now.date()
    soon = (today + dt.timedelta(days=3)).isoformat()
    vulns, recent, padded = select_kev(now, kev)
    due_soon = sum(1 for v in vulns if today.isoformat() <= str(v.get("dueDate", "")) <= soon)
    kev_ids = {v["cveID"] for v in vulns}

    kev_items = []
    for v in recent:
        e = epss.get(v["cveID"])
        kev_items.append({
            "cveID": v["cveID"],
            "vendorProject": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerabilityName": v.get("vulnerabilityName", ""),
            "dateAdded": v.get("dateAdded", ""),
            "dueDate": v.get("dueDate", ""),
            "shortDescription": v.get("shortDescription", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", ""),
            "epss": e[0] if e else None,
            "pct": e[1] if e else None,
        })

    ranked = []
    for r in nvd.values():
        e = epss.get(r["id"])
        item = dict(r)
        item["in_kev"] = r["id"] in kev_ids
        item["epss"], item["pct"] = (e[0], e[1]) if e else (None, None)
        ranked.append(item)
    ranked.sort(key=lambda r: (r["in_kev"],
                               r["epss"] if r["epss"] is not None else -1.0,
                               r["score"] or 0.0,
                               r["published"]), reverse=True)

    edition = (now + dt.timedelta(hours=8)).date().isoformat()  # Singapore date
    return {
        "schema": 1,
        "edition": edition,
        "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": WINDOW_DAYS,
        "epss_date": epss_date,
        "kev": {
            "catalogVersion": kev.get("catalogVersion", ""),
            "dateReleased": kev.get("dateReleased", ""),
            "count": kev.get("count", len(vulns)),
            "padded": padded,
            "due_soon": due_soon,
            "items": kev_items,
        },
        "nvd": {
            "error": nvd_err,
            "total": len(ranked),
            "shown": ranked[:NVD_TOP],
        },
    }


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

def esc(s):
    return html.escape(str(s if s is not None else ""), quote=True)


def clip(s, n):
    s = " ".join(str(s or "").split())
    if len(s) <= n:
        return s
    return s[:n].rsplit(" ", 1)[0].rstrip(",;:. ") + "…"


def d_short(iso):
    try:
        d = dt.date.fromisoformat(iso[:10])
    except Exception:  # noqa: BLE001
        return iso or ""
    return "%d %s %d" % (d.day, d.strftime("%b"), d.year)


def parse_utc(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def clock_lines(gen):
    """('Sun 1 Nov 2026, 22:41 UTC', 'Mon 06:41 SGT · Mon 09:41 AEDT')"""
    utc = "%s %d %s %d, %s UTC" % (gen.strftime("%a"), gen.day, gen.strftime("%b"), gen.year,
                                   gen.strftime("%H:%M"))
    sgt = gen + dt.timedelta(hours=8)
    parts = ["%s %s SGT" % (sgt.strftime("%a"), sgt.strftime("%H:%M"))]
    if ZoneInfo is not None:
        try:
            syd = gen.astimezone(ZoneInfo("Australia/Sydney"))
            parts.append("%s %s %s" % (syd.strftime("%a"), syd.strftime("%H:%M"), syd.strftime("%Z")))
        except Exception:  # noqa: BLE001
            pass
    return utc, " · ".join(parts)


def badge(text, cls="mute"):
    return '<span class="b b-%s">%s</span>' % (cls, esc(text))


def epss_badge(e, pct):
    if e is None:
        return ""
    cls = "bad" if e >= 0.5 else ("warn" if e >= 0.1 else "mute")
    label = "EPSS %s" % (("%.1f%%" % (e * 100)) if e < 0.1 else ("%.0f%%" % (e * 100)))
    return badge(label, cls)


def nvd_link(cve):
    return '<a href="https://nvd.nist.gov/vuln/detail/%s">%s</a>' % (esc(cve), esc(cve))


def kev_card(it):
    b = [badge("KEV added " + d_short(it["dateAdded"]), "bad")]
    if str(it.get("ransomware", "")).lower() == "known":
        b.append(badge("Ransomware use: known", "bad"))
    if it.get("dueDate"):
        b.append(badge("CISA due " + d_short(it["dueDate"]), "warn"))
    b.append(epss_badge(it.get("epss"), it.get("pct")))
    who = " · ".join(x for x in (it.get("vendorProject"), it.get("product")) if x)
    plain = explain(it.get("shortDescription", ""))
    out = ['<article class="item">', '<div class="badges">%s</div>' % "".join(b),
           "<h3>%s</h3>" % esc(it.get("vulnerabilityName") or it["cveID"]),
           '<p class="ids">%s%s</p>' % (nvd_link(it["cveID"]), (" · " + esc(who)) if who else ""),
           "<p>%s</p>" % esc(clip(it.get("shortDescription"), 280))]
    if plain:
        out.append('<p class="plain"><strong>In plain English:</strong> %s</p>' % esc(plain))
    out.append("</article>")
    return "".join(out)


def nvd_card(r):
    b = []
    if r.get("score") is not None:
        v = ("v" + r["cvss_version"]) if r.get("cvss_version") else ""
        b.append(badge(("CVSS %.1f %s" % (r["score"], v)).strip(), "bad" if r["score"] >= 9 else "warn"))
    if r.get("in_kev"):
        b.append(badge("In CISA KEV", "bad"))
    b.append(epss_badge(r.get("epss"), r.get("pct")))
    b.append(badge("Published " + d_short(r.get("published", "")), "mute"))
    meta = []
    if r.get("scored_by"):
        meta.append("scored by " + r["scored_by"])
    if r.get("cwes"):
        meta.append(", ".join(r["cwes"][:3]))
    plain = explain(r.get("desc", ""))
    out = ['<article class="item">', '<div class="badges">%s</div>' % "".join(b),
           '<h3 class="mono">%s</h3>' % nvd_link(r["id"]),
           '<p class="ids">%s</p>' % esc(" · ".join(meta)) if meta else "",
           "<p>%s</p>" % esc(clip(r.get("desc"), 300))]
    if plain:
        out.append('<p class="plain"><strong>In plain English:</strong> %s</p>' % esc(plain))
    out.append("</article>")
    return "".join(out)


CSS = """
:root{
  --bg:#F5F5FA;--surface:#FFFFFF;--surface-2:#EEEEF7;--fg:#1A1B2E;--muted:#55576F;--line:#DCDDEA;
  --accent:#6B0AEA;--accent-soft:#EFE7FD;--good:#12765A;--good-soft:#E0F3EB;--bad:#BE2638;--bad-soft:#FCE6E9;
  --warn:#8F5200;--warn-soft:#FFEFD3;--code:#EEEEF7;--hero-bg:#0B0C1B;--hero-fg:#F1F1F9;--hero-muted:#AEB0C9;
  --hero-line:#2C2E4A;--hero-accent:#B38CFF;
  --shadow:0 1px 2px rgba(26,27,46,.06),0 6px 20px rgba(26,27,46,.05);
  --sans:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#0B0C1B;--surface:#14152A;--surface-2:#1C1D36;--fg:#E9EAF5;--muted:#A3A5BE;--line:#2B2D49;
    --accent:#B38CFF;--accent-soft:#2A1C52;--good:#46D3A6;--good-soft:#0F2F28;--bad:#FF8A95;--bad-soft:#3A1B24;
    --warn:#F2B866;--warn-soft:#352A12;--code:#1C1D36;--hero-bg:#05050F;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 6px 20px rgba(0,0,0,.25);color-scheme:dark;
  }
}
:root[data-theme="dark"]{
  --bg:#0B0C1B;--surface:#14152A;--surface-2:#1C1D36;--fg:#E9EAF5;--muted:#A3A5BE;--line:#2B2D49;
  --accent:#B38CFF;--accent-soft:#2A1C52;--good:#46D3A6;--good-soft:#0F2F28;--bad:#FF8A95;--bad-soft:#3A1B24;
  --warn:#F2B866;--warn-soft:#352A12;--code:#1C1D36;--hero-bg:#05050F;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 6px 20px rgba(0,0,0,.25);color-scheme:dark;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:16px;line-height:1.6}
a{color:var(--accent);text-underline-offset:2px}
p{margin:0 0 .8em}
.wrap{max-width:900px;margin:0 auto;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
.sitenav{background:var(--hero-bg)}
.sitenav .wrap{display:flex;flex-wrap:wrap;gap:6px 18px;padding-block:10px;font-size:.84rem}
.sitenav a{color:var(--hero-muted);text-decoration:none}
.sitenav a:hover{color:var(--hero-accent)}
.hero{background:var(--hero-bg);color:var(--hero-fg);border-bottom:1px solid var(--hero-line)}
.hero .wrap{padding-block:14px 22px}
.eyebrow{font-family:var(--mono);font-size:.78rem;letter-spacing:.12em;text-transform:uppercase;color:var(--hero-accent);margin:0 0 8px}
h1{font-size:clamp(1.7rem,4.4vw,2.5rem);line-height:1.15;margin:0 0 10px;font-weight:700;letter-spacing:-.01em;text-wrap:balance}
.hero-meta{margin:2px 0;color:var(--hero-muted);font-size:.9rem}
.jump{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.jump a{color:var(--hero-fg);text-decoration:none;border:1px solid var(--hero-line);padding:6px 12px;border-radius:999px;font-size:.84rem}
.jump a:hover{border-color:var(--hero-accent);color:var(--hero-accent)}
main .wrap{padding-block:4px 48px}
.sec{margin-top:36px;scroll-margin-top:12px}
h2{font-size:1.35rem;line-height:1.25;margin:0 0 8px;font-weight:700;text-wrap:balance}
.note{color:var(--muted);font-size:.92rem;max-width:70ch;margin:0 0 14px}
.notice{background:var(--warn-soft);color:var(--warn);border-radius:10px;padding:10px 14px;font-size:.9rem;margin:0 0 14px}
.feature{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:12px;padding:16px 20px;box-shadow:var(--shadow);margin-top:24px}
.feature p{margin:0 0 4px;max-width:72ch}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px 16px;min-width:0}
.stat b{display:block;font-family:var(--mono);font-size:1.9rem;line-height:1.1;color:var(--accent);font-weight:500}
.stat span{display:block;font-size:.9rem;margin-top:6px}
.stat small{display:block;color:var(--muted);font-size:.78rem;margin-top:4px}
.items{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,400px),1fr));gap:14px}
.item{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 18px;min-width:0;box-shadow:var(--shadow)}
.item h3{margin:0 0 4px;font-size:1.05rem;line-height:1.3;text-wrap:balance}
.item h3.mono{font-family:var(--mono);font-weight:500}
.item p{max-width:72ch}
.ids{font-family:var(--mono);font-size:.78rem;color:var(--muted);margin:0 0 8px;overflow-wrap:anywhere}
.plain{background:var(--accent-soft);border-radius:8px;padding:8px 12px;margin:10px 0 0}
.badges{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 8px}
.b{display:inline-flex;align-items:center;font-size:.7rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;padding:3px 9px;border-radius:999px;white-space:nowrap}
.b-bad{background:var(--bad-soft);color:var(--bad)}
.b-warn{background:var(--warn-soft);color:var(--warn)}
.b-good{background:var(--good-soft);color:var(--good)}
.b-mute{background:var(--surface-2);color:var(--muted)}
.legend{display:grid;gap:8px;margin:0;max-width:72ch}
.legend p{margin:0}
.end{margin-top:36px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:.86rem}
.end p{max-width:72ch}
"""

FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E"
           "%3Cpath fill='%236B0AEA' d='M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z'/%3E%3C/svg%3E")


def stat(num, label, small):
    return '<div class="stat"><b>%s</b><span>%s</span><small>%s</small></div>' % (esc(num), esc(label), esc(small))


SITE_DESC = ("Newly exploited vulnerabilities from CISA KEV and new critical CVEs from NVD, "
             "ranked by how likely they are to be attacked. Updated every weekday.")
PAGE_CLOSE = "</div>\n</main>\n</body>\n</html>\n"


def page_open(title, eyebrow, h1, meta_lines, jump, base, analysis):
    """Everything from <!doctype> to the opening of <main>."""
    nav = ['<a href="%s">Latest</a>' % (base or "./")]
    if analysis:
        nav.append('<a href="%sanalysis.html">Featured analysis</a>' % base)
    nav.append('<a href="%sarchive/">Archive</a>' % base)
    nav.append('<a href="%s">Source code</a>' % esc(REPO_URL))
    jumps = ""
    if jump:
        jumps = ('<nav class="jump" aria-label="Jump to a section">%s</nav>\n'
                 % "".join('<a href="#%s">%s</a>' % (esc(a), esc(t)) for a, t in jump))
    meta = "".join('<p class="hero-meta">%s</p>\n' % esc(x) for x in meta_lines)
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
        '<meta name="color-scheme" content="light dark">\n'
        '<title>%s</title>\n'
        '<meta name="description" content="%s">\n'
        '<meta property="og:type" content="website">\n'
        '<meta property="og:title" content="%s">\n'
        '<meta property="og:description" content="%s">\n'
        '<link rel="icon" href="%s">\n'
        '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500'
        '&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">\n'
        '<style>%s</style>\n</head>\n<body>\n'
        '<nav class="sitenav" aria-label="Site"><div class="wrap">%s</div></nav>\n'
        '<header class="hero"><div class="wrap">\n'
        '<p class="eyebrow">%s</p>\n<h1>%s</h1>\n%s%s</div></header>\n'
        '<main>\n<div class="wrap">\n'
    ) % (esc(title), esc(SITE_DESC), esc(title), esc(SITE_DESC), FAVICON, CSS, "".join(nav),
         esc(eyebrow), esc(h1), meta, jumps)


def render_page(m, index, analysis, newest):
    """m = one snapshot. index=True for the home page, False for an archive page."""
    base = "" if index else "../"
    utc_line, local_line = clock_lines(parse_utc(m["generated_utc"]))
    kev, nvd = m["kev"], m["nvd"]
    n_new = len(kev["items"])
    n_rans = sum(1 for i in kev["items"] if str(i.get("ransomware", "")).lower() == "known")
    nvd_total = "—" if nvd.get("error") and not nvd["total"] else str(nvd["total"])
    name = "Daily Threat Watch"

    p = [page_open(
        name if index else "%s · %s" % (name, d_short(m["edition"])),
        "Auto-updated every weekday" if index else "Edition · " + d_short(m["edition"]),
        name,
        ["Updated " + utc_line, local_line,
         "Window: last %d days · Sources: CISA KEV, NVD, FIRST EPSS" % m["window_days"]],
        [("kev", "Exploited now"), ("critical", "Critical and new"), ("how", "How to read this"),
         ("sources", "Sources")],
        base, analysis)]

    if m["edition"] != newest:
        p.append('<p class="notice" style="margin-top:20px">This is an older edition. '
                 '<a href="../">Open the latest edition.</a></p>\n')
    if analysis:
        when = (" (%s)" % esc(d_short(analysis["date"]))) if analysis.get("date") else ""
        p.append('<section class="feature"><p><strong>Featured analysis%s</strong></p>'
                 '<p>Plain-English and technical write-ups of the biggest threats, with an honest note on '
                 'where a security product helps and where it does not. Updated by hand, not every day.</p>'
                 '<p><a href="%sanalysis.html">Read the analysis →</a></p></section>\n' % (when, base))

    p.append('<section class="sec" id="glance"><h2>At a glance</h2><div class="stats">')
    p.append(stat(str(n_new), "New in CISA KEV",
                  ("last %d days" % m["window_days"]) if not kev["padded"] else "quiet week: latest %d shown" % n_new))
    p.append(stat(str(n_rans), "Linked to ransomware", "among the new KEV entries"))
    p.append(stat(str(kev["due_soon"]), "CISA deadlines in 3 days", "binds US federal agencies; a priority signal for all"))
    p.append(stat(nvd_total, "New critical CVEs", "NVD, CVSS 9.0 or higher, last %d days" % m["window_days"]))
    p.append("</div></section>\n")

    p.append('<section class="sec" id="kev"><h2>Exploited now: new in CISA KEV</h2>')
    p.append('<p class="note">KEV is CISA\'s list of bugs that attackers are already using. '
             'If a bug is on it, patch it first.</p>')
    if kev["padded"]:
        p.append('<p class="notice">Fewer than %d additions in the last %d days. Showing the %d most recent.</p>'
                 % (KEV_MIN_ITEMS, m["window_days"], n_new))
    p.append('<div class="items">%s</div></section>\n' % "".join(kev_card(i) for i in kev["items"]))

    p.append('<section class="sec" id="critical"><h2>Critical and brand new</h2>')
    p.append('<p class="note">New bugs that NVD or the vendor scored 9.0 or higher. '
             'Sorted by EPSS, the estimated chance of an attack in the next 30 days. '
             'Bugs already in KEV come first.</p>')
    if nvd.get("error"):
        p.append('<p class="notice">%s The next run will try again.</p>' % esc(nvd["error"]))
    if nvd["shown"]:
        more = nvd["total"] - len(nvd["shown"])
        p.append('<div class="items">%s</div>' % "".join(nvd_card(r) for r in nvd["shown"]))
        if more > 0:
            p.append('<p class="note" style="margin-top:14px">%d more critical CVEs were published '
                     'in this window. They are not shown because an attack on them is less likely. '
                     'Search them in <a href="https://nvd.nist.gov/vuln/search">NVD</a>.</p>' % more)
    elif not nvd.get("error"):
        p.append('<p class="note">No critical CVEs found in this window.</p>')
    p.append("</section>\n")

    p.append('<section class="sec" id="how"><h2>How to read this page</h2><div class="legend">'
             '<p><strong>CVE</strong> is the ID of one bug, like CVE-2026-12345.</p>'
             '<p><strong>KEV</strong> means CISA has proof that attackers use the bug in real attacks.</p>'
             '<p><strong>CVSS</strong> is a score from 0 to 10. It shows how bad a bug could be. '
             'It does not show how likely an attack is.</p>'
             '<p><strong>EPSS</strong> is a score from 0 to 100%. It estimates how likely a bug is to be '
             'attacked in the next 30 days. A new bug can start low and climb.</p>'
             '<p><strong>In plain English</strong> lines are written by simple rules from the official '
             'description. They can be wrong. Read the source before you act.</p>'
             '</div></section>\n')

    ep = (" EPSS scores are from %s." % esc(m["epss_date"])) if m.get("epss_date") else \
        " EPSS scores were not available in this run."
    p.append('<footer class="end" id="sources"><p><strong>Sources.</strong> '
             'KEV: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA Known Exploited '
             'Vulnerabilities Catalog</a>, version %s. Critical CVEs: the NVD API. EPSS: '
             '<a href="https://www.first.org/epss/">FIRST</a>.%s</p>'
             '<p>This product uses data from the NVD API but is not endorsed or certified by the NVD.</p>'
             '<p>Built automatically by GitHub Actions each weekday from public data. '
             '<a href="%s">Source code</a>.</p>'
             '<p>Personal project. Not an official SentinelOne publication. An automated summary, not advice. '
             'Check the original sources before you act on anything here.</p></footer>\n'
             % (esc(kev.get("catalogVersion") or "unknown"), ep, esc(REPO_URL)))
    p.append(PAGE_CLOSE)
    return "".join(p)


def render_archive_index(snaps, analysis):
    rows = []
    for s in snaps:
        k, n = s["kev"], s["nvd"]
        crit = "?" if n.get("error") and not n["total"] else str(n["total"])
        rows.append('<li><a href="%s.html">%s</a> · %d new in KEV · %s critical CVEs</li>'
                    % (esc(s["edition"]), esc(d_short(s["edition"])), len(k["items"]), crit))
    head = page_open("Daily Threat Watch archive", "Archive", "Past editions",
                     ["One page for each weekday run, newest first."], [], "../", analysis)
    return head + '<section class="sec"><ul class="legend">%s</ul></section>\n' % "".join(rows) + PAGE_CLOSE


# --------------------------------------------------------------------------
# Site
# --------------------------------------------------------------------------

def read_analysis(root):
    p = root / "analysis.html"
    if not p.exists():
        return None
    txt = p.read_text("utf-8", errors="replace")
    m = re.search(r'<meta\s+name="edition-date"\s+content="(\d{4}-\d{2}-\d{2})"', txt)
    return {"date": m.group(1) if m else ""}


def load_snapshots(data_dir):
    snaps = []
    for p in sorted(Path(data_dir).glob("20??-??-??.json"), reverse=True):
        try:
            s = json.loads(p.read_text("utf-8"))
            if s.get("schema") == 1 and s.get("edition"):
                snaps.append(s)
        except Exception:  # noqa: BLE001
            continue
    return snaps


def prune(data_dir):
    files = sorted(Path(data_dir).glob("20??-??-??.json"), reverse=True)
    for p in files[KEEP_SNAPSHOTS:]:
        p.unlink()


def write_site(out, data_dir, root):
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "archive").mkdir(parents=True)
    snaps = load_snapshots(data_dir)
    if not snaps:
        raise RuntimeError("no snapshots to render")
    analysis = read_analysis(root)
    (out / "index.html").write_text(render_page(snaps[0], True, analysis, snaps[0]["edition"]), "utf-8")
    for s in snaps:
        (out / "archive" / ("%s.html" % s["edition"])).write_text(
            render_page(s, False, analysis, snaps[0]["edition"]), "utf-8")
    (out / "archive" / "index.html").write_text(render_archive_index(snaps, analysis), "utf-8")
    if analysis:
        shutil.copyfile(root / "analysis.html", out / "analysis.html")
    return snaps


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default="_site")
    ap.add_argument("--data", default="data")
    ap.add_argument("--root", default=".", help="repo root (where analysis.html lives)")
    ap.add_argument("--fixtures", help="read test data from this folder instead of the network")
    args = ap.parse_args()
    fix = Path(args.fixtures) if args.fixtures else None

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    if os.environ.get("THREAT_NOW"):  # for tests
        now = parse_utc(os.environ["THREAT_NOW"])
    api_key = (os.environ.get("NVD_API_KEY") or "").strip() or None

    try:
        kev = fetch_kev(fix)
    except Exception as exc:  # noqa: BLE001
        print("ERROR:", exc, file=sys.stderr)
        return 1
    n_kev = len(kev.get("vulnerabilities", []))
    print("KEV: %d entries, catalog %s" % (n_kev, kev.get("catalogVersion", "?")))

    nvd, nvd_err = fetch_nvd(now - dt.timedelta(days=WINDOW_DAYS), now, api_key, fix)
    print("NVD: %d critical CVEs%s" % (len(nvd), (" (" + nvd_err + ")") if nvd_err else ""))

    _, shown_kev, _ = select_kev(now, kev)
    ids = [v["cveID"] for v in shown_kev]
    ids += list(nvd.keys())
    epss, epss_date = fetch_epss(ids, fix)
    print("EPSS: %d scores%s" % (len(epss), (" as of " + epss_date) if epss_date else ""))

    model = build_model(now, kev, nvd, nvd_err, epss, epss_date)
    data_dir = Path(args.data)
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / ("%s.json" % model["edition"])).write_text(
        json.dumps(model, indent=1, ensure_ascii=False, sort_keys=True) + "\n", "utf-8")
    prune(data_dir)

    snaps = write_site(args.out, data_dir, Path(args.root))
    print("Site: %d page(s) in %s (latest edition %s)" % (len(snaps) + 1, args.out, snaps[0]["edition"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
