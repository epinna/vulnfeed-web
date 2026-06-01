#!/usr/bin/env python3
"""
web.py — VulnFeed public site + authenticated internal research dashboard.

Replaces import_feed.py. One pure-stdlib tool, three modes:

  web.py --export [--research P] [--out P] [--metrics-out P]
      Regenerate feed.json + metrics.json (the PUBLIC, redacted artifacts the
      static pages consume). Byte-for-byte the old import_feed.py behaviour.
      This is also the default when no mode flag is given.

  web.py --serve-public [--host H] [--port N] [--research P]
      Serve the PUBLIC site. The HTML/assets (index.html / feed.html /
      metrics.html, etc.) are served from this directory exactly as-is — so the
      current, or a future redesigned, page renders unchanged. Only feed.json /
      metrics.json are built live from the research tree, so the page always
      loads its entries without a separate --export step. No dynamic HTML
      rendering, no internals (no .py / dotfiles either).

  web.py --local [--port N] [--research P]
      Serve the INTERNAL dashboard. Reads the FULL research tree from disk —
      every file, all internals (root_cause, vulnerable_paths + snippets, full
      trigger plan incl. payloads/runtime_config, qualification rationale,
      signals, outcome.md, sandbox harness). Access control is TWO layers:
        1. bound to 127.0.0.1 ONLY (never a routable interface), and
        2. HTTP Basic Auth (VULNFEED_USER / VULNFEED_PASS, or a generated pw).
      The "Download PoC zip" button is an inert placeholder — nothing is ever
      zipped or served (honours the pipeline's no-publication invariant).
"""

import argparse
import base64
import hmac
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ── Default paths ────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent
RESEARCH_DIR = SCRIPT_DIR.parent / "vulnfeed" / "research"
OUT_FILE     = SCRIPT_DIR / "feed.json"
METRICS_FILE = SCRIPT_DIR / "metrics.json"

# Content types for the public static file server.
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg", ".gif": "image/gif", ".ico": "image/x-icon",
    ".webp": "image/webp", ".woff2": "font/woff2", ".woff": "font/woff",
    ".txt": "text/plain; charset=utf-8", ".xml": "application/xml; charset=utf-8",
    ".map": "application/json; charset=utf-8", ".webmanifest": "application/manifest+json",
}


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DATA LAYER — ported verbatim from import_feed.py (the redacted public     ║
# ║  projection + the exact export). Shared by --export and --serve-public.    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def sev_from_hint(hint: float) -> str:
    if hint >= 0.9:  return "CRITICAL"
    if hint >= 0.55: return "HIGH"
    if hint >= 0.25: return "MEDIUM"
    return "LOW"


ECO_ALIASES = {
    "pypi": "PyPI", "npm": "npm", "go": "Go", "maven": "Maven", "nuget": "NuGet",
    "cargo": "Rust", "rubygems": "RubyGems", "packagist": "PHP", "hex": "Elixir",
    "pub": "Dart", "cran": "R",
}
PLATFORM_ECO = {
    "alpine-secfixes": "Alpine", "redhat-tracker": "RPM",
    "ubuntu-tracker": "Debian", "oss-security": "Linux",
}


def normalise_eco(raw: str) -> str:
    return ECO_ALIASES.get(raw.lower(), raw)


def ecosystem_from(data: dict) -> str:
    for sig in data.get("signals", []):
        eco = sig.get("extra", {}).get("ecosystem", "")
        if eco:
            return normalise_eco(eco)
    return PLATFORM_ECO.get(data.get("platform", ""), "Unknown")


# Maps canonical status (lib/status.py) → public display tier. Inlined to avoid
# a cross-repo import (vulnfeed/ and vulnfeed-web/ are siblings).
_STATUS_TO_TIER = {
    "confirmed":       "CONFIRMED",
    "sandbox-aborted": "ANALYZED",
    "not-triggered":   "ANALYZED",
    "analyzed":        "ANALYZED",
    "approved":        "ANALYZED",
    "qualified":       "QUALIFYING",
}


def _parse_outcome_status(entry_dir: Path) -> str:
    """Return the lowercase status string from outcome.md, or ''."""
    path = entry_dir / "outcome.md"
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return ""
    fm = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    if fm:
        for line in fm.group(1).splitlines():
            m = re.match(r"^status:\s*(.+)", line.strip(), re.IGNORECASE)
            if m:
                return m.group(1).strip().lower()
    for line in text.splitlines():
        ll = line.lower()
        bm = re.search(r"\*\*status[^*]*:?\*\*:?\s*([^\n|*`]+)", ll)
        if bm:
            return bm.group(1).strip()
        tm = re.match(r"\|\s*status\s*\|\s*([^|]+)", ll)
        if tm:
            return tm.group(1).strip()
    return ""


def pipeline_tier(entry_dir: Path) -> str | None:
    """Display tier (CONFIRMED/ANALYZED/QUALIFYING) or None to skip from feed."""
    status_path = entry_dir / "status.json"
    if status_path.exists():
        try:
            s = json.loads(status_path.read_text())
            status = s.get("status", "")
            if status in _STATUS_TO_TIER:
                return _STATUS_TO_TIER[status]
            if status in ("rejected", "deferred", "stub", "analysis-aborted"):
                return None
        except Exception:
            pass

    out_status = _parse_outcome_status(entry_dir)
    sandbox = entry_dir / "sandbox"
    if (sandbox / "Dockerfile").exists():
        if (sandbox / "run_poc.sh").exists() and (sandbox / "README.md").exists():
            return "CONFIRMED"

    if (entry_dir / "analysis.json").exists() and (entry_dir / "analysis.md").exists():
        if "aborted" in out_status:
            return "QUALIFYING"
        return "ANALYZED"

    disc = entry_dir / "discovery.json"
    if disc.exists():
        d = json.loads(disc.read_text())
        if d.get("qualification", {}).get("result") == "passed":
            return "QUALIFYING"
    return None


def _osv_ids_raw(data: dict) -> list[str]:
    seen, out = set(), []
    for sig in data.get("signals", []):
        oid = sig.get("extra", {}).get("osv_id", "")
        if oid and oid not in seen:
            seen.add(oid); out.append(oid)
    return out


def ghsa_ids_from(data: dict) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for ghsa in (data.get("ghsa_ids") or []):
        if ghsa and ghsa not in seen:
            seen.add(ghsa); out.append(ghsa)
    for oid in _osv_ids_raw(data):
        if oid.startswith("GHSA-") and oid not in seen:
            seen.add(oid); out.append(oid)
    return out


def osv_ids_from(data: dict) -> list[str]:
    return [oid for oid in _osv_ids_raw(data) if not oid.startswith("GHSA-")]


def fixed_versions_from(data: dict) -> list[str]:
    seen, out = set(), []
    for sig in data.get("signals", []):
        for v in sig.get("extra", {}).get("all_fixed_versions", []):
            if v not in seen:
                seen.add(v); out.append(v)
    return out


def build_refs(data: dict, disc: dict | None) -> list[dict]:
    seen_urls: set[str] = set()
    refs: list[dict] = []

    def add(kind: str, url: str, label: str) -> None:
        if not url or url in seen_urls:
            return
        seen_urls.add(url)
        refs.append({"kind": kind, "url": url, "label": label})

    if disc:
        for url in disc.get("qualification", {}).get("evidence_urls", []):
            if "osv.dev" in url:
                add("osv", url, url.rsplit("/", 1)[-1])
            elif "github.com/advisories" in url:
                add("advisory", url, url.rsplit("/", 1)[-1])
            elif "github.com" in url and "/commit/" in url:
                add("commit", url, "Fix commit · " + url.rsplit("/", 1)[-1][:10])
            else:
                add("advisory", url, url.rsplit("/", 1)[-1][:40])

    if disc:
        repo = disc.get("repo_url", data.get("repo_url", ""))
        for sha in disc.get("fix_commit_shas", []):
            if repo:
                url = f"{repo.rstrip('/')}/commit/{sha}"
                add("commit", url, f"Fix commit · {sha[:10]}")

    for ghsa in data.get("ghsa_ids", []):
        add("advisory", f"https://github.com/advisories/{ghsa}", ghsa)

    for sig in data.get("signals", []):
        url = sig.get("url", "")
        title = sig.get("title", url.rsplit("/", 1)[-1])[:50]
        if "osv.dev" in url:
            add("osv", url, sig.get("extra", {}).get("osv_id", title))
        elif url:
            add("advisory", url, title)

    return refs


TAG_KEYWORDS: list[tuple[str, list[str]]] = [
    ("supply-chain",    ["malicious", "malware", "backdoor", "typosquat", "postinstall"]),
    ("rce",             ["remote code execution", "rce", "arbitrary code"]),
    ("dos",             ["denial of service", "panic", "dos", "memory exhaustion", "oom"]),
    ("auth-bypass",     ["authentication bypass", "authorization bypass", "auth bypass",
                         "unauthenticated", "bypass the intended", "opt-in", "session-key",
                         "session key", "routing opt"]),
    ("idor",            ["insecure direct object", "idor", "bola", "object-level access"]),
    ("sqli",            ["sql injection", "sqli"]),
    ("xss",             ["cross-site scripting", "xss", "stored xss", "reflected xss"]),
    ("ssrf",            ["server-side request forgery", "ssrf"]),
    ("path-traversal",  ["path traversal", "directory traversal", "zip slip"]),
    ("deserialization", ["deserialization", "pickle", "unsafe deserialization"]),
    ("cryptography",    ["cryptograph", "jwe", "jwt", "tls", "ssl", "cipher", "key wrap"]),
    ("credential-theft",["credential", "token harvest", "api key", "secret scan"]),
    ("privilege-escalation", ["privilege escalation", "privesc", "escalate privilege"]),
    ("injection",       ["template injection", "ssti", "command injection", "shell injection",
                         "template render", "templated"]),
    ("multi-tenant",    ["cross-workspace", "cross-tenant", "workspace isolation", "tenant"]),
    ("webhook",         ["webhook", "hook mapping", "hook session"]),
]


def infer_tags(data: dict) -> list[str]:
    corpus = " ".join([
        data.get("project_name", ""),
        *(sig.get("verbatim_excerpt", "")[:800] for sig in data.get("signals", [])),
    ]).lower()
    return [tag for tag, kws in TAG_KEYWORDS if any(kw in corpus for kw in kws)][:6]


def _is_prose_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or len(stripped) < 35:
        return False
    if stripped.startswith(("#", "-", "*", "|", ">")):
        return False
    if stripped.startswith(("Package:", "Affected", "Patched", "Version", "Fixed", "Workaround")):
        return False
    if stripped.startswith(("http://", "https://", "```", "~~~")):
        return False
    return True


def extract_teaser(data: dict, title: str) -> str:
    title_norm = title.lower().rstrip(".")
    for sig in data.get("signals", []):
        excerpt = sig.get("verbatim_excerpt", "")
        if not excerpt:
            continue
        paragraphs = [p.strip() for p in excerpt.split("\n\n") if p.strip()]
        for para in paragraphs:
            flat = " ".join(l.strip() for l in para.splitlines() if l.strip())
            if flat.lower().rstrip(".") == title_norm:
                continue
            if _is_prose_line(flat):
                flat = re.sub(r"<[^>]+>", "", flat)
                flat = re.sub(r"<[^>]*$", "", flat).strip()
                flat = re.sub(r"`([^`]+)`", r"\1", flat)
                flat = re.sub(r"\*\*([^*]+)\*\*", r"\1", flat)
                flat = re.sub(r"\*([^*]+)\*", r"\1", flat)
                flat = flat.strip()
                if len(flat) < 35:
                    continue
                return flat[:240]
    return f"Security vulnerability in {data.get('project_name', 'unknown package')}."


def process_entry(entry_dir: Path) -> dict | None:
    """The REDACTED public projection (feed.json entry) — unchanged."""
    stub_path = entry_dir / "stub.json"
    disc_path = entry_dir / "discovery.json"

    if not stub_path.exists() and not disc_path.exists():
        return None

    primary_path = disc_path if disc_path.exists() else stub_path
    data = json.loads(primary_path.read_text())
    disc = json.loads(disc_path.read_text()) if disc_path.exists() else None

    status = pipeline_tier(entry_dir)
    if status is None:
        return None

    cve_ids = data.get("cve_ids") or []
    ghsa_ids = ghsa_ids_from(data)
    osv_ids = osv_ids_from(data)

    if not cve_ids and not ghsa_ids and not osv_ids:
        return None

    signals = data.get("signals", [])
    title = signals[0]["title"] if signals else data.get("project_name", entry_dir.name)
    priority = data.get("priority_components", {})
    severity = sev_from_hint(priority.get("severity_hint", 0.3))

    analysis_path = entry_dir / "analysis.json"
    impact = ""
    if analysis_path.exists():
        try:
            analysis = json.loads(analysis_path.read_text())
            analysis_desc = analysis.get("description", "")
            impact = (analysis.get("attacker_model") or {}).get("impact", "")
        except Exception:
            analysis_desc = ""
    else:
        analysis_desc = ""
    teaser = analysis_desc if analysis_desc else extract_teaser(data, title)

    stub_data = json.loads(stub_path.read_text()) if stub_path.exists() else {}
    clone_of = stub_data.get("clone_of") or data.get("clone_of") or None
    clone_source_url = stub_data.get("clone_source_url") or data.get("clone_source_url") or None

    raw_stars = (disc.get("repo_stars") if disc else None) or data.get("repo_stars")
    repo_stars = int(raw_stars) if isinstance(raw_stars, (int, float)) and raw_stars > 0 else None

    entry: dict = {
        "id":            entry_dir.name,
        "title":         title,
        "teaser":        teaser,
        "impact":        impact,
        "package":       data.get("project_name", entry_dir.name),
        "ecosystem":     ecosystem_from(data),
        "severity":      severity,
        "cve_ids":       cve_ids,
        "ghsa_ids":      ghsa_ids,
        "osv_ids":       osv_ids,
        "fixed_in":      fixed_versions_from(data),
        "action":        None,
        "discovered_at": data.get("discovered_at", ""),
        "poc_status":    status,
        "priority_score": data.get("priority_score", 0.0),
        "repo_stars":    repo_stars,
        "tags":          infer_tags(data),
        "references":    build_refs(data, disc),
    }
    if clone_of:
        entry["clone_of"] = clone_of
        entry["clone_source_url"] = clone_source_url
    return entry


def build_feed_and_metrics(research: Path) -> tuple[dict, dict, dict]:
    """Build the feed.json + metrics.json dicts. Returns (feed, metrics, stats).

    Logic is identical to the old import_feed.py main() so output is preserved.
    """
    all_entries: list[dict] = []
    rejection_reasons: dict[str, int] = {}
    total_dirs = 0
    total_qualified = 0

    for entry_dir in sorted(research.iterdir()):
        if not entry_dir.is_dir():
            continue
        total_dirs += 1

        disc_path = entry_dir / "discovery.json"
        if disc_path.exists():
            disc = json.loads(disc_path.read_text())
            q = disc.get("qualification", {})
            if q:
                total_qualified += 1
                if q.get("result") == "rejected":
                    reason = q.get("reject_reason", "unknown")
                    rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1

        result = process_entry(entry_dir)
        if result is None:
            continue
        all_entries.append(result)

    tier_order = {"CONFIRMED": 0, "ANALYZED": 1, "QUALIFYING": 2}
    all_entries.sort(key=lambda e: (tier_order[e["poc_status"]], -e["priority_score"]))

    totals = {t: sum(1 for e in all_entries if e["poc_status"] == t)
              for t in ("CONFIRMED", "ANALYZED", "QUALIFYING")}
    clone_totals = {t: sum(1 for e in all_entries if e["poc_status"] == t and e.get("clone_of"))
                    for t in ("CONFIRMED", "ANALYZED", "QUALIFYING")}
    total_clone_stubs = sum(
        1 for d in research.iterdir()
        if d.is_dir() and (d / "stub.json").exists()
        and json.loads((d / "stub.json").read_text()).get("clone_of")
    )

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    confirmed = [
        {k: v for k, v in e.items() if k != "priority_score"}
        for e in all_entries if e["poc_status"] == "CONFIRMED"
    ]
    feed = {
        "generated_at":              now,
        "pipeline":                  "vulnfeed/0.1",
        "total_candidates_analyzed": total_dirs,
        "confirmed_pocs":            totals["CONFIRMED"],
        "entries":                   confirmed,
    }

    metrics_entries = [
        {k: v for k, v in e.items() if k != "priority_score"}
        for e in all_entries
    ]
    for e in metrics_entries:
        disc_path = research / e["id"] / "discovery.json"
        if disc_path.exists():
            disc = json.loads(disc_path.read_text())
            q = disc.get("qualification", {})
            e["qualification_rationale"] = q.get("rationale", "")
            e["fix_commit_shas"] = disc.get("fix_commit_shas", [])

    metrics = {
        "generated_at": now,
        "pipeline":     "vulnfeed/0.1",
        "funnel": {
            "discovered":  total_dirs,
            "qualified":   total_qualified,
            "passed":      totals["CONFIRMED"] + totals["ANALYZED"] + totals["QUALIFYING"],
            "analyzed":    totals["CONFIRMED"] + totals["ANALYZED"],
            "confirmed":   totals["CONFIRMED"],
            "clone_qualify": {
                "discovered": total_clone_stubs,
                "passed":     sum(clone_totals.values()),
                "analyzed":   clone_totals["CONFIRMED"] + clone_totals["ANALYZED"],
                "confirmed":  clone_totals["CONFIRMED"],
            },
        },
        "rejection_reasons": dict(sorted(rejection_reasons.items(), key=lambda x: -x[1])),
        "entries": metrics_entries,
    }

    stats = {
        "totals": totals, "clone_totals": clone_totals,
        "total_dirs": total_dirs, "total_qualified": total_qualified,
        "total_clone_stubs": total_clone_stubs, "total_entries": len(all_entries),
    }
    return feed, metrics, stats


def run_export(args) -> None:
    """Write feed.json + metrics.json. Replaces import_feed.py's main()."""
    research: Path = args.research
    if not research.is_dir():
        print(f"error: research dir not found: {research}", file=sys.stderr)
        sys.exit(1)

    feed, metrics, stats = build_feed_and_metrics(research)
    args.out.write_text(json.dumps(feed, indent=2, ensure_ascii=False))
    args.metrics_out.write_text(json.dumps(metrics, indent=2, ensure_ascii=False))

    totals, clone_totals = stats["totals"], stats["clone_totals"]
    clone_passed = sum(clone_totals.values())
    clone_analyzed = clone_totals["CONFIRMED"] + clone_totals["ANALYZED"]
    print(f"feed.json    → {args.out}  ({totals['CONFIRMED']} CONFIRMED entries)")
    print(f"metrics.json → {args.metrics_out}  ({stats['total_entries']} total entries)")
    print(f"  CONFIRMED  {totals['CONFIRMED']}  (clone: {clone_totals['CONFIRMED']})")
    print(f"  ANALYZED   {totals['ANALYZED']}  (clone: {clone_totals['ANALYZED']})")
    print(f"  QUALIFYING {totals['QUALIFYING']}  (clone: {clone_totals['QUALIFYING']})")
    print(f"  funnel: {stats['total_dirs']} discovered → {stats['total_qualified']} qualified → "
          f"{totals['CONFIRMED']+totals['ANALYZED']+totals['QUALIFYING']} passed → "
          f"{totals['CONFIRMED']} confirmed")
    print(f"  clone-qualify: {stats['total_clone_stubs']} discovered → {clone_passed} passed → "
          f"{clone_analyzed} analyzed → {clone_totals['CONFIRMED']} confirmed")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  INTERNAL DATA LAYER — full, unredacted (loopback dashboard only)          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# Full 9-status taxonomy → display tier (superset of the public _STATUS_TO_TIER).
STATUS_TIER = {
    "confirmed": "CONFIRMED",
    "analyzed": "ANALYZED", "approved": "ANALYZED", "not-triggered": "ANALYZED", "sandbox-aborted": "ANALYZED",
    "qualified": "QUALIFYING", "analysis-aborted": "QUALIFYING",
    "rejected": "REJECTED", "deferred": "DEFERRED", "stub": "STUB", "unknown": "OTHER",
}
TIER_RANK = {"CONFIRMED": 0, "ANALYZED": 1, "QUALIFYING": 2,
             "DEFERRED": 3, "REJECTED": 4, "STUB": 5, "OTHER": 6}
# Pipeline order for the "entries by state" chart.
STATUS_ORDER = ["confirmed", "not-triggered", "sandbox-aborted", "analyzed",
                "analysis-aborted", "qualified", "deferred", "rejected", "stub", "unknown"]

SAFE_SLUG = re.compile(r"^[A-Za-z0-9._-]+$")


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_text(path: Path):
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def iter_entry_dirs(research: Path):
    for d in sorted(research.iterdir()):
        if d.is_dir() and not d.name.startswith("."):
            yield d


def _pkg_from_slug(slug: str) -> str:
    s = re.sub(r"-cve-\d{4}-\d+$", "", slug, flags=re.I)
    s = re.sub(r"-ghsa-[0-9a-z-]+$", "", s, flags=re.I)
    s = re.sub(r"-[0-9a-f]{8}$", "", s)
    return s


def _cves_from_slug(slug: str) -> list[str]:
    return [m.upper() for m in re.findall(r"cve-\d{4}-\d+", slug, flags=re.I)]


def _infer_status(entry_dir: Path) -> str:
    """Best-effort status when status.json is missing (rare)."""
    sb = entry_dir / "sandbox"
    if (sb / "Dockerfile").exists() and (sb / "run_poc.sh").exists() and (sb / "README.md").exists():
        return "confirmed"
    if (entry_dir / "analysis.json").exists():
        return "analyzed"
    if (entry_dir / "discovery.json").exists():
        return "qualified"
    if (entry_dir / "stub.json").exists():
        return "stub"
    return "unknown"


def scan_index(research: Path) -> list[dict]:
    """Cheap one row per entry for the index. Avoids parsing the (often huge)
    rejected discovery.json files — those rows are slug-derived only."""
    rows: list[dict] = []
    for d in iter_entry_dirs(research):
        slug = d.name
        st = read_json(d / "status.json") or {}
        status = st.get("status") or _infer_status(d)
        row = {
            "id": slug, "status": status, "tier": STATUS_TIER.get(status, "OTHER"),
            "package": _pkg_from_slug(slug), "severity": "", "ecosystem": "",
            "cve_ids": _cves_from_slug(slug), "ghsa_ids": [], "osv_ids": [],
            "stars": None, "tags": [], "discovered_at": "",
        }
        if status != "rejected":  # don't open the big rejected discovery.json files
            stub = read_json(d / "stub.json")
            disc = read_json(d / "discovery.json")
            data = disc or stub
            if data:
                row["package"] = data.get("project_name") or row["package"]
                row["cve_ids"] = data.get("cve_ids") or row["cve_ids"]
                row["ghsa_ids"] = ghsa_ids_from(data)
                row["osv_ids"] = osv_ids_from(data)
                row["ecosystem"] = ecosystem_from(data)
                row["severity"] = sev_from_hint((data.get("priority_components") or {}).get("severity_hint", 0.3))
                row["tags"] = infer_tags(data)
                rs = (disc.get("repo_stars") if disc else None) or data.get("repo_stars")
                row["stars"] = int(rs) if isinstance(rs, (int, float)) and rs > 0 else None
                row["discovered_at"] = data.get("discovered_at", "")
        rows.append(row)
    rows.sort(key=lambda r: (TIER_RANK.get(r["tier"], 9), r["id"]))
    return rows


# 30s TTL cache of the index scan (keyed by research path).
_INDEX_CACHE: dict[str, tuple[float, list[dict]]] = {}


def get_index_rows(research: Path) -> list[dict]:
    key = str(research)
    now = time.monotonic()
    cached = _INDEX_CACHE.get(key)
    if cached and now - cached[0] < 30:
        return cached[1]
    rows = scan_index(research)
    _INDEX_CACHE[key] = (now, rows)
    return rows


def load_full_entry(entry_dir: Path) -> dict:
    """Every file + all internals for a single entry (lazy, per detail view)."""
    slug = entry_dir.name
    st = read_json(entry_dir / "status.json") or {}
    status = st.get("status") or _infer_status(entry_dir)
    try:
        public = process_entry(entry_dir)
    except Exception:
        public = None
    full = {
        "slug": slug, "status": status, "tier": STATUS_TIER.get(status, "OTHER"),
        "status_json": st, "public": public,
        "stub": read_json(entry_dir / "stub.json"),
        "discovery": read_json(entry_dir / "discovery.json"),
        "analysis": read_json(entry_dir / "analysis.json"),
        "analysis_md": read_text(entry_dir / "analysis.md"),
        "outcome_md": read_text(entry_dir / "outcome.md"),
        "sandbox": None,
    }
    sb = entry_dir / "sandbox"
    if sb.is_dir():
        files = []
        for f in sorted(sb.rglob("*")):
            if f.is_file():
                try:
                    size = f.stat().st_size
                except Exception:
                    size = 0
                files.append({"name": f.relative_to(entry_dir).as_posix(), "size": size})
        full["sandbox"] = {
            "files": files,
            "dockerfile": read_text(sb / "Dockerfile"),
            "run_poc_sh": read_text(sb / "run_poc.sh"),
            "readme_md": read_text(sb / "README.md"),
            "prep": read_json(sb / ".sandbox-prep.json"),
        }
    return full


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  RENDERING — markdown + HTML helpers                                       ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def esc(s) -> str:
    return html.escape("" if s is None else str(s))


def pretty_json(obj) -> str:
    return f'<pre class="code"><code>{esc(json.dumps(obj, indent=2, ensure_ascii=False))}</code></pre>'


def code_block(text: str) -> str:
    return f'<pre class="code"><code>{esc(text)}</code></pre>'


def _md_inline(s: str) -> str:
    s = esc(s)  # escape FIRST so content can never inject tags
    s = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<!\*)\*([^*\s][^*]*?)\*(?!\*)", r"<em>\1</em>", s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
               r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>', s)
    return s


def _md(md: str) -> str:
    lines = md.split("\n")
    out: list[str] = []
    i, n = 0, len(lines)
    in_ul = False

    def close_ul():
        nonlocal in_ul
        if in_ul:
            out.append("</ul>"); in_ul = False

    while i < n:
        line = lines[i]
        if line.lstrip().startswith("```"):
            close_ul()
            i += 1
            buf: list[str] = []
            while i < n and not lines[i].lstrip().startswith("```"):
                buf.append(lines[i]); i += 1
            i += 1
            code = "\n".join(buf)
            out.append(f'<pre class="code"><code>{esc(code)}</code></pre>')
            continue
        stripped = line.strip()
        if not stripped:
            close_ul(); i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            close_ul()
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_md_inline(m.group(2))}</h{lvl}>")
            i += 1; continue
        if re.match(r"^(---+|\*\*\*+|___+)$", stripped):
            close_ul(); out.append("<hr>"); i += 1; continue
        if "|" in line and i + 1 < n and re.match(
                r"^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$", lines[i + 1]):
            close_ul()
            header = [c.strip() for c in stripped.strip("|").split("|")]
            i += 2
            body_rows: list[list[str]] = []
            while i < n and "|" in lines[i] and lines[i].strip():
                body_rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            th = "".join(f"<th>{_md_inline(c)}</th>" for c in header)
            trs = ""
            for r in body_rows:
                trs += "<tr>" + "".join(f"<td>{_md_inline(c)}</td>" for c in r) + "</tr>"
            out.append(f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>")
            continue
        if stripped.startswith(">"):
            close_ul()
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(re.sub(r"^\s*>\s?", "", lines[i])); i += 1
            out.append(f"<blockquote>{_md_inline(' '.join(buf))}</blockquote>")
            continue
        bm = re.match(r"^[-*+]\s+(.*)$", stripped) or re.match(r"^\d+\.\s+(.*)$", stripped)
        if bm:
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{_md_inline(bm.group(1))}</li>")
            i += 1; continue
        close_ul()
        buf = [stripped]; i += 1
        while i < n and lines[i].strip() and not re.match(
                r"^(#{1,6}\s|[-*+]\s|\d+\.\s|>|```|---+$|\|)", lines[i].strip()):
            buf.append(lines[i].strip()); i += 1
        out.append(f"<p>{_md_inline(' '.join(buf))}</p>")
    close_ul()
    return "\n".join(out)


def render_markdown(md) -> str:
    if not md:
        return ""
    try:
        return f'<div class="md-body">{_md(md)}</div>'
    except Exception:
        return f'<pre class="code">{esc(md)}</pre>'


def html_page(title: str, inner: str, *, scripts: str = "") -> str:
    """Render an internal-dashboard page. (The public site is served as static
    files by PublicHandler, never through this function.)"""
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        f"<title>{esc(title)}</title>" + FONTS_LINK +
        "<style>" + BASE_CSS + "</style></head><body>" +
        ORBS + NAV_INTERNAL + INT_BANNER + inner + FOOTER + MODAL_HTML + scripts +
        "</body></html>"
    )


# ── Index (list) view ─────────────────────────────────────────────────────────

def render_index(rows: list[dict]) -> str:
    tier_counts: dict[str, int] = {}
    for r in rows:
        tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1
    chips = " · ".join(f'<span class="stat-inline">{tier_counts.get(t, 0)}</span> {t.lower()}'
                       for t in ("CONFIRMED", "ANALYZED", "QUALIFYING", "REJECTED", "STUB")
                       if tier_counts.get(t))

    # Bar chart: how many entries in each pipeline state.
    status_counts: dict[str, int] = {}
    for r in rows:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    ordered = [(s, status_counts[s]) for s in STATUS_ORDER if status_counts.get(s)]
    ordered += [(s, c) for s, c in sorted(status_counts.items()) if s not in STATUS_ORDER]
    mx = max((c for _, c in ordered), default=1)
    bars = "".join(
        f'<div class="bar-row"><span class="bar-label">{esc(s)}</span>'
        f'<div class="bar-track"><div class="bar-fill" data-tier="{STATUS_TIER.get(s, "OTHER")}" '
        f'style="width:{max(c / mx * 100, 1.2):.1f}%"></div></div>'
        f'<span class="bar-count">{c:,}</span></div>'
        for s, c in ordered)
    chart = f'<section class="section chart"><h2>Entries by state</h2>{bars}</section>'

    inner = f"""
  <main><div class="wrapper">
    <div class="page-header">
      <h1 class="page-title">Research dashboard — all entries</h1>
      <p class="page-sub"><span class="stat-inline">{len(rows)}</span> entries · {chips}</p>
    </div>
    {chart}
    <div class="toolbar">
      <div class="filter-group">
        <span class="filter-label">Tier</span>
        <button class="filter-btn active-all" data-filter="all">All</button>
        <button class="filter-btn" data-tier="CONFIRMED">Confirmed</button>
        <button class="filter-btn" data-tier="ANALYZED">Analyzed</button>
        <button class="filter-btn" data-tier="QUALIFYING">Qualifying</button>
        <button class="filter-btn" data-tier="REJECTED">Rejected</button>
        <button class="filter-btn" data-tier="STUB">Stub</button>
      </div>
      <div class="filter-group">
        <span class="filter-label">Severity</span>
        <button class="filter-btn" data-sev="CRITICAL">● Critical</button>
        <button class="filter-btn" data-sev="HIGH">● High</button>
        <button class="filter-btn" data-sev="MEDIUM">● Medium</button>
      </div>
      <div class="toolbar-spacer"></div>
      <div class="search-wrap">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="6.5" cy="6.5" r="5"/><path d="M10 10l3.5 3.5" stroke-linecap="round"/>
        </svg>
        <input class="search-input" id="searchInput" type="text" placeholder="Search slug, package, CVE…" autocomplete="off" spellcheck="false">
        <span class="kbd-hint">/</span>
      </div>
    </div>
    <div class="results-meta" id="resultsMeta"></div>
    <div class="cards-grid" id="cardsGrid"></div>
  </div></main>
"""
    return html_page("VulnFeed — Research dashboard", inner,
                     scripts=f"<script>{INDEX_JS}</script>")


# ── Detail view ────────────────────────────────────────────────────────────────

def _chips(ids: list[str]) -> str:
    return "".join(f'<span class="id-chip">{esc(i)}</span>' for i in (ids or []))


def _kv(pairs: list[tuple[str, str]]) -> str:
    rows = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in pairs if v not in (None, "", []))
    return f'<dl class="kv">{rows}</dl>' if rows else ""


def _section(title: str, body: str) -> str:
    if not body:
        return ""
    return f'<section class="section"><h2>{esc(title)}</h2>{body}</section>'


def _refs_html(refs: list[dict]) -> str:
    if not refs:
        return ""
    links = "".join(
        f'<a class="ref-link kind-{esc(r.get("kind",""))}" href="{esc(r.get("url",""))}" '
        f'target="_blank" rel="noopener noreferrer">{esc(r.get("label",""))}</a>'
        for r in refs)
    return f'<div class="card-refs" style="border:none;padding:0">{links}</div>'


def render_detail(full: dict) -> str:
    slug = full["slug"]
    pub = full["public"] or {}
    disc = full["discovery"] or {}
    an = full["analysis"] or {}
    sev = pub.get("severity", "")

    title = pub.get("title") or _pkg_from_slug(slug)
    ids = (pub.get("cve_ids") or disc.get("cve_ids") or _cves_from_slug(slug)) \
        + (pub.get("ghsa_ids") or []) + (pub.get("osv_ids") or [])
    repo_url = disc.get("repo_url") or an.get("repo_url") or ""
    stars = pub.get("repo_stars")

    head = f"""
  <main><div class="wrapper">
    <a class="back-link" href="/">← all entries</a>
    <div class="detail-head">
      <div class="card-top" style="margin-bottom:10px">
        <span class="tier-badge" data-tier="{esc(full['tier'])}">{esc(full['tier'])}</span>
        <span class="status-chip">{esc(full['status'])}</span>
        {f'<span class="badge sev-badge" data-severity="{esc(sev)}">{esc(sev)}</span>' if sev else ''}
        {f'<span class="badge eco-badge" data-eco="{esc(pub.get("ecosystem",""))}">{esc(pub.get("ecosystem",""))}</span>' if pub.get('ecosystem') else ''}
        {f'<span class="star-chip star-mid">★ {stars:,}</span>' if stars else ''}
      </div>
      <h1 class="detail-title">{esc(pub.get('package') or _pkg_from_slug(slug))}</h1>
      <p class="page-sub" style="font-family:var(--font-mono)">{esc(slug)}</p>
      <div class="card-ids" style="margin-top:10px">{_chips(ids)}</div>
    </div>
"""

    # Overview
    overview = ""
    if pub.get("teaser") or pub.get("impact"):
        overview += (f'<p style="font-size:14px;line-height:1.7;color:var(--text-primary)">{esc(pub.get("teaser",""))}</p>')
    overview += _kv([
        ("Impact", esc(pub.get("impact", ""))),
        ("Ecosystem", esc(pub.get("ecosystem", ""))),
        ("Fixed in", ", ".join(esc(v) for v in pub.get("fixed_in", []))),
        ("Repository", f'<a href="{esc(repo_url)}" target="_blank" rel="noopener noreferrer">{esc(repo_url)}</a>' if repo_url else ""),
        ("Tags", " ".join(f'<span class="tag">{esc(t)}</span>' for t in pub.get("tags", []))),
        ("Discovered", esc(pub.get("discovered_at", ""))),
    ])
    if pub.get("references"):
        overview += _refs_html(pub["references"])
    sec_overview = _section("Overview", overview)

    # Internals (analysis.json)
    internals = ""
    if an:
        am = an.get("attacker_model") or {}
        bc = an.get("bug_class") or {}
        internals += _kv([
            ("Description", esc(an.get("description", ""))),
            ("CWE", esc(bc.get("cwe", ""))),
            ("Bug class", esc(bc.get("category", ""))),
            ("Requirements", esc(am.get("requirements", ""))),
            ("Impact", esc(am.get("impact", ""))),
            ("Notes", esc(am.get("notes", ""))),
            ("Affected", ", ".join(esc(v) for v in an.get("affected_versions", []))),
            ("Last affected", esc(an.get("last_affected_version", ""))),
            ("Latest unaffected", esc(an.get("latest_unaffected_version", ""))),
        ])
        if an.get("root_cause"):
            internals += f'<h3 class="sub-h">Root cause</h3>{render_markdown(an["root_cause"])}'
    sec_internals = _section("Analysis — internals", internals)

    # Vulnerable paths
    vp = ""
    for p in (an.get("vulnerable_paths") or []):
        lr = p.get("line_range") or []
        loc = f'{esc(p.get("file",""))}' + (f' : {esc(p.get("function",""))}' if p.get("function") else "") \
            + (f' ({lr[0]}–{lr[1]})' if len(lr) == 2 else "")
        vp += f'<div class="vp"><div class="vp-loc">{loc}</div>{code_block(p.get("snippet","")) if p.get("snippet") else ""}</div>'
    sec_vp = _section("Vulnerable code paths", vp)

    # Trigger plan
    trig = an.get("trigger") or {}
    tparts = ""
    if trig:
        ep = trig.get("entry_point") or {}
        ishape = trig.get("input_shape") or {}
        rc = trig.get("runtime_config") or {}
        ss = trig.get("success_signal") or {}
        tparts += _kv([
            ("Entry point", esc(f'{ep.get("kind","")} — {ep.get("detail","")}'.strip(" —"))),
            ("Input shape", esc(ishape.get("description", ""))),
            ("Payload encoding", esc(ishape.get("payload_encoding", ""))),
            ("Success signal", esc(f'{ss.get("kind","")} — {ss.get("detail","")}'.strip(" —"))),
        ])
        if ishape.get("example_payload"):
            tparts += f'<h3 class="sub-h">Example payload</h3>{code_block(ishape["example_payload"])}'
        if rc:
            tparts += f'<h3 class="sub-h">Runtime config</h3>{pretty_json(rc)}'
    sec_trigger = _section("Trigger plan", tparts)

    # Qualification (discovery.json)
    qual = disc.get("qualification") or {}
    qparts = ""
    if disc:
        qparts += _kv([
            ("Result", esc(qual.get("result", ""))),
            ("Reject reason", esc(qual.get("reject_reason", ""))),
            ("Decided at", esc(qual.get("decided_at", ""))),
            ("Deployment type", esc(disc.get("deployment_type", ""))),
            ("Needs social-eng", "yes" if disc.get("requires_social_engineering") else ""),
            ("Priority score", esc(disc.get("priority_score", ""))),
            ("Seen count", esc(disc.get("seen_count", ""))),
        ])
        if qual.get("rationale"):
            qparts += f'<h3 class="sub-h">Rationale</h3>{render_markdown(qual["rationale"])}'
        ev = qual.get("evidence_urls") or []
        if ev:
            qparts += '<h3 class="sub-h">Evidence</h3><div class="card-refs" style="border:none;padding:0">' + \
                "".join(f'<a class="ref-link" href="{esc(u)}" target="_blank" rel="noopener noreferrer">{esc(u.rsplit("/",1)[-1][:48] or u)}</a>' for u in ev) + "</div>"
        sigs = disc.get("signals") or []
        if sigs:
            qparts += f'<details class="raw"><summary>{len(sigs)} signal(s)</summary>{pretty_json(sigs)}</details>'
        if disc.get("priority_components"):
            qparts += f'<details class="raw"><summary>priority components</summary>{pretty_json(disc["priority_components"])}</details>'
    sec_qual = _section("Qualification", qparts)

    # Markdown writeups
    sec_an_md = _section("analysis.md", render_markdown(full.get("analysis_md")))
    sec_outcome = _section("outcome.md", render_markdown(full.get("outcome_md")))

    # Sandbox / PoC
    sb = full.get("sandbox")
    sandbox_html = ""
    if sb:
        sandbox_html += (
            '<div class="warn-note">Internal — do not distribute. These artifacts are '
            'shown only on the loopback dashboard and are never published or downloadable.</div>')
        sandbox_html += (
            '<a class="get-access-btn poc-dl" href="javascript:void(0)" '
            f'onclick="pocDemo()">⬇ Download PoC zip</a>')
        if sb.get("readme_md"):
            sandbox_html += f'<h3 class="sub-h">README.md</h3>{render_markdown(sb["readme_md"])}'
        if sb.get("dockerfile"):
            sandbox_html += f'<h3 class="sub-h">Dockerfile</h3>{code_block(sb["dockerfile"])}'
        if sb.get("run_poc_sh"):
            sandbox_html += f'<h3 class="sub-h">run_poc.sh</h3>{code_block(sb["run_poc_sh"])}'
        if sb.get("prep"):
            sandbox_html += f'<details class="raw"><summary>.sandbox-prep.json</summary>{pretty_json(sb["prep"])}</details>'
        if sb.get("files"):
            rows = "".join(
                f'<div class="file-row"><a href="/raw/{esc(slug)}/{esc(f["name"])}">{esc(f["name"])}</a>'
                f'<span>{f["size"]:,} B</span></div>' for f in sb["files"])
            sandbox_html += f'<h3 class="sub-h">All sandbox files</h3><div class="file-list">{rows}</div>'
    sec_sandbox = _section("Sandbox / PoC", sandbox_html)

    # Raw blobs (everything, collapsible)
    raw = ""
    for label, obj in (("status.json", full.get("status_json")), ("stub.json", full.get("stub")),
                       ("discovery.json", full.get("discovery")), ("analysis.json", full.get("analysis"))):
        if obj:
            raw += f'<details class="raw"><summary>{esc(label)}</summary>{pretty_json(obj)}</details>'
    sec_raw = _section("Raw artifacts", raw)

    body = head + "".join([
        sec_overview, sec_internals, sec_vp, sec_trigger, sec_qual,
        sec_an_md, sec_outcome, sec_sandbox, sec_raw,
    ]) + "</div></main>"
    return html_page(f"{slug} — VulnFeed internal", body, scripts=f"<script>{DETAIL_JS}</script>")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  HTTP — internal (loopback + Basic Auth) and public handlers               ║
# ╚══════════════════════════════════════════════════════════════════════════╝

class _Base(BaseHTTPRequestHandler):
    server_version = "vulnfeed-web/1.0"

    def log_message(self, fmt, *args):  # quieter logs
        sys.stderr.write("[web] %s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body, ctype="text/html; charset=utf-8", extra_headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _not_found(self):
        self._send(404, html_page("404", '<main><div class="wrapper"><div class="empty-state">Not found.</div></div></main>'))


class DashboardHandler(_Base):
    """INTERNAL dashboard. Loopback-only + Basic Auth. Serves all internals."""
    RESEARCH: Path = RESEARCH_DIR
    KNOWN_SLUGS: frozenset = frozenset()
    AUTH_USER: str = "vulnfeed"
    AUTH_PASS: str = ""

    # ── access control ────────────────────────────────────────────────────
    def _loopback_ok(self) -> bool:
        host = self.client_address[0] if self.client_address else ""
        return host in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _authed(self) -> bool:
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            user, _, pw = base64.b64decode(hdr[6:]).decode("utf-8", "replace").partition(":")
        except Exception:
            return False
        return (hmac.compare_digest(user, self.AUTH_USER)
                and hmac.compare_digest(pw, self.AUTH_PASS))

    def _gate(self) -> bool:
        """Return True if the request may proceed; otherwise send 403/401."""
        if not self._loopback_ok():
            self._send(403, "forbidden: loopback only\n", "text/plain; charset=utf-8")
            return False
        if not self._authed():
            self._send(401, "authentication required\n", "text/plain; charset=utf-8",
                       {"WWW-Authenticate": 'Basic realm="vulnfeed-internal"'})
            return False
        return True

    def _entry_dir(self, slug: str):
        """Validated entry dir for a slug, or None (path-traversal safe)."""
        if not SAFE_SLUG.match(slug) or slug not in self.KNOWN_SLUGS:
            return None
        d = (self.RESEARCH / slug).resolve()
        if d.parent != self.RESEARCH.resolve() or not d.is_dir():
            return None
        return d

    # ── dispatch ──────────────────────────────────────────────────────────
    def do_GET(self):
        if not self._gate():
            return
        try:
            self._route_get()
        except Exception as e:  # never leak a stack trace to the client
            sys.stderr.write(f"[web] error: {e!r}\n")
            self._send(500, html_page("500", '<main><div class="wrapper"><div class="empty-state">Internal error.</div></div></main>'))

    def do_POST(self):
        if not self._gate():
            return
        path = self.path.split("?", 1)[0]
        if re.fullmatch(r"/poc/[^/]+", path):
            self._send(200, "Demo only — PoC artifacts are not distributed from this dashboard.\n",
                       "text/plain; charset=utf-8")
            return
        self._not_found()

    def _route_get(self):
        path = self.path.split("?", 1)[0]

        if path == "/" or path == "/index.html":
            self._send(200, render_index(get_index_rows(self.RESEARCH)))
            return
        if path == "/healthz":
            self._send(200, f"ok 127.0.0.1 entries={len(self.KNOWN_SLUGS)}\n", "text/plain; charset=utf-8")
            return
        if path == "/api/entries.json":
            self._send(200, json.dumps(get_index_rows(self.RESEARCH), ensure_ascii=False),
                       "application/json; charset=utf-8")
            return

        m = re.fullmatch(r"/api/entry/([^/]+)\.json", path)
        if m:
            d = self._entry_dir(m.group(1))
            if not d:
                self._not_found(); return
            self._send(200, json.dumps(load_full_entry(d), ensure_ascii=False),
                       "application/json; charset=utf-8")
            return

        m = re.fullmatch(r"/entry/([^/]+)", path)
        if m:
            d = self._entry_dir(m.group(1))
            if not d:
                self._not_found(); return
            self._send(200, render_detail(load_full_entry(d)))
            return

        if re.fullmatch(r"/poc/[^/]+", path):
            self._send(200, "Demo only — PoC artifacts are not distributed from this dashboard.\n",
                       "text/plain; charset=utf-8")
            return

        m = re.fullmatch(r"/raw/([^/]+)/(.+)", path)
        if m:
            self._serve_raw(m.group(1), m.group(2))
            return

        self._not_found()

    def _serve_raw(self, slug: str, relpath: str):
        d = self._entry_dir(slug)
        if not d:
            self._not_found(); return
        # Resolve and confirm the target stays strictly inside the entry dir.
        try:
            target = (d / relpath).resolve()
        except Exception:
            self._not_found(); return
        base = d.resolve()
        if base != target and base not in target.parents:
            self._not_found(); return
        if not target.is_file():
            self._not_found(); return

        name = target.name
        rel = target.relative_to(base).as_posix()
        text = read_text(target)
        if text is None:
            inner = '<div class="warn-note">Binary or unreadable file — not rendered.</div>'
        elif name.endswith((".md",)):
            inner = render_markdown(text)
        elif name.endswith((".json",)):
            obj = read_json(target)
            inner = pretty_json(obj) if obj is not None else code_block(text)
        else:
            inner = code_block(text)
        body = (f'<main><div class="wrapper"><a class="back-link" href="/entry/{esc(slug)}">← {esc(slug)}</a>'
                f'<div class="detail-head"><h1 class="detail-title" style="font-size:18px">{esc(rel)}</h1></div>'
                f'<div class="warn-note">Internal artifact — do not distribute.</div>'
                f'<section class="section">{inner}</section></div></main>')
        self._send(200, html_page(f"{rel} — {slug}", body))


class PublicHandler(_Base):
    """PUBLIC site — a plain static file server for this directory, serving the
    page exactly as deployed. No dynamic rendering, no internals; .py files and
    dotfiles are never served. Faithful to the current (or a future) page.

    feed.json / metrics.json are the one exception: served from a live in-memory
    build (set by serve_public) so the page always has data."""
    ROOT: Path = SCRIPT_DIR
    FEED_BYTES: bytes | None = None
    METRICS_BYTES: bytes | None = None

    def do_GET(self):
        try:
            self._serve()
        except Exception as e:
            sys.stderr.write(f"[web] error: {e!r}\n")
            self._send(500, "error\n", "text/plain; charset=utf-8")

    def _serve(self):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        # The page's data feed: serve the live-built JSON so entries always load.
        if path == "/feed.json" and self.FEED_BYTES is not None:
            self._send(200, self.FEED_BYTES, "application/json; charset=utf-8"); return
        if path == "/metrics.json" and self.METRICS_BYTES is not None:
            self._send(200, self.METRICS_BYTES, "application/json; charset=utf-8"); return
        rel = path.lstrip("/") or "index.html"
        if rel.endswith("/"):
            rel += "index.html"
        try:
            target = (self.ROOT / rel).resolve()
        except Exception:
            self._send(404, "not found\n", "text/plain; charset=utf-8"); return
        root = self.ROOT.resolve()
        # Confine to ROOT (no traversal).
        if (root != target and root not in target.parents) or not target.is_file():
            self._send(404, "not found\n", "text/plain; charset=utf-8"); return
        # Refuse dotfiles/dotdirs anywhere in the path (.git, .env, .claude, …)
        # and source files.
        if any(p.startswith(".") for p in target.relative_to(root).parts) or target.suffix == ".py":
            self._send(404, "not found\n", "text/plain; charset=utf-8"); return
        try:
            data = target.read_bytes()
        except Exception:
            self._send(404, "not found\n", "text/plain; charset=utf-8"); return
        self._send(200, data, CONTENT_TYPES.get(target.suffix.lower(), "application/octet-stream"))


# ── servers ─────────────────────────────────────────────────────────────────

def serve_local(research: Path, port: int) -> None:
    if not research.is_dir():
        print(f"error: research dir not found: {research}", file=sys.stderr)
        sys.exit(1)

    DashboardHandler.RESEARCH = research
    DashboardHandler.KNOWN_SLUGS = frozenset(d.name for d in iter_entry_dirs(research))

    user = os.environ.get("VULNFEED_USER") or "vulnfeed"
    pw = os.environ.get("VULNFEED_PASS") or "vulnfeed"
    DashboardHandler.AUTH_USER = user
    DashboardHandler.AUTH_PASS = pw
    if not os.environ.get("VULNFEED_PASS"):
        print(f"[web] Basic Auth: default credentials {user} / {pw} "
              f"(set VULNFEED_USER / VULNFEED_PASS to override)", file=sys.stderr)

    # Loopback ONLY. This literal is the access-control boundary — do not make
    # it configurable; the internal view must never bind a routable interface.
    httpd = ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"[web] INTERNAL dashboard → http://127.0.0.1:{port}  (loopback only · Basic Auth · "
          f"{len(DashboardHandler.KNOWN_SLUGS)} entries)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[web] stopped.", file=sys.stderr)


def serve_public(research: Path, host: str, port: int) -> None:
    PublicHandler.ROOT = SCRIPT_DIR
    # Build the page's data feed live so it always loads entries, even without a
    # prior --export. HTML/assets are still served from disk exactly as-is.
    if research.is_dir():
        feed, metrics, _ = build_feed_and_metrics(research)
        PublicHandler.FEED_BYTES = json.dumps(feed, ensure_ascii=False).encode("utf-8")
        PublicHandler.METRICS_BYTES = json.dumps(metrics, ensure_ascii=False).encode("utf-8")
        note = f"{feed['confirmed_pocs']} confirmed PoCs · feed built live from {research}"
    else:
        note = f"research dir not found ({research}) — serving on-disk feed.json/metrics.json if present"
    httpd = ThreadingHTTPServer((host, port), PublicHandler)
    print(f"[web] PUBLIC site → http://{host}:{port}  ({note}; no internals)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[web] stopped.", file=sys.stderr)


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  STATIC ASSETS — CSS (ported from feed.html) + client JS + chrome          ║
# ╚══════════════════════════════════════════════════════════════════════════╝

FONTS_LINK = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700'
    '&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">'
)

ORBS = (
    '<div class="bg-orbs" aria-hidden="true"><div class="bg-orb bg-orb-1"></div>'
    '<div class="bg-orb bg-orb-2"></div><div class="bg-orb bg-orb-3"></div></div>'
)

_LOGO = (
    '<a class="logo" href="/"><div class="logo-icon">'
    '<svg viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<path d="M9 1.5L2 4.5V9c0 3.87 3.03 7.5 7 8.5 3.97-1 7-4.63 7-8.5V4.5L9 1.5z" stroke="#38bdf8" stroke-width="1.3" stroke-linejoin="round"/>'
    '<path d="M6 9l2 2 4-4" stroke="#a8ff3e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>'
    '</svg></div><span class="logo-name">Vuln<span>Feed</span></span></a>'
)

NAV_INTERNAL = (
    '<nav><div class="nav-inner">' + _LOGO +
    '<ul class="nav-links"><li><a class="nav-link active" href="/">Dashboard</a></li></ul>'
    '<span class="nav-cta" style="background:rgba(255,62,94,.15);color:#ff8ba0;cursor:default">INTERNAL</span>'
    '</div></nav>'
)
INT_BANNER = (
    '<div class="int-banner"><div class="int-banner-inner">'
    '<span class="int-banner-text">⚠ Internal research view — full unredacted data. '
    'Loopback-only + authenticated. Do not expose or distribute.</span></div></div>'
)
FOOTER = (
    '<footer><div class="footer-inner"><div class="footer-brand">'
    'Powered by&nbsp;<strong>vulnfeed</strong>&nbsp;research engine</div>'
    '<div class="footer-note">Details withheld pending responsible disclosure</div></div></footer>'
)

MODAL_HTML = (
    '<div class="modal-back" id="modal" onclick="if(event.target===this)this.classList.remove(\'open\')">'
    '<div class="modal"><p>Demo only — PoC artifacts are not distributed from this dashboard.</p>'
    '<button onclick="document.getElementById(\'modal\').classList.remove(\'open\')">Close</button>'
    '</div></div>'
)

# CSS: ported verbatim from feed.html <style>, plus internal/detail/md-body classes.
BASE_CSS = r"""
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg:#060b16; --surface:#0d1525; --card-bg:rgba(13,21,42,0.7);
      --card-border:rgba(148,163,184,0.08); --card-hover-border:rgba(148,163,184,0.18);
      --text-primary:#e2e8f0; --text-secondary:#64748b; --text-muted:#334155;
      --accent:#a8ff3e; --accent-dim:rgba(168,255,62,0.15);
      --c-critical:#ff3e5e; --c-high:#ff8c3e; --c-medium:#ffd93e; --c-low:#3eb8ff;
      --eco-npm:#cb3837; --eco-go:#00acd7; --eco-maven:#f89820; --eco-pypi:#3572a5;
      --font-ui:'Inter',system-ui,-apple-system,sans-serif;
      --font-mono:'JetBrains Mono','Fira Code',monospace;
      --radius:12px; --radius-sm:6px;
    }
    html { scroll-behavior: smooth; }
    body { font-family:var(--font-ui); background:var(--bg); color:var(--text-primary); min-height:100vh; overflow-x:hidden; -webkit-font-smoothing:antialiased; }
    .bg-orbs { position:fixed; inset:0; pointer-events:none; z-index:0; overflow:hidden; }
    .bg-orb { position:absolute; border-radius:50%; filter:blur(90px); opacity:0.10; }
    .bg-orb-1 { width:700px; height:700px; background:radial-gradient(circle,#3b82f6,transparent 70%); top:-250px; left:-200px; animation:orbFloat1 22s ease-in-out infinite; }
    .bg-orb-2 { width:500px; height:500px; background:radial-gradient(circle,#7c3aed,transparent 70%); bottom:-150px; right:-100px; animation:orbFloat2 28s ease-in-out infinite; }
    .bg-orb-3 { width:350px; height:350px; background:radial-gradient(circle,#0ea5e9,transparent 70%); top:40%; left:55%; animation:orbFloat3 18s ease-in-out infinite; }
    @keyframes orbFloat1 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(60px,40px)} }
    @keyframes orbFloat2 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(-50px,-60px)} }
    @keyframes orbFloat3 { 0%,100%{transform:translate(0,0)} 33%{transform:translate(30px,-40px)} 66%{transform:translate(-20px,30px)} }
    body::before { content:''; position:fixed; inset:0; z-index:0; pointer-events:none; background-image:linear-gradient(rgba(148,163,184,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(148,163,184,0.018) 1px,transparent 1px); background-size:40px 40px; }
    @keyframes livePulse { 0%,100%{opacity:1;box-shadow:0 0 6px var(--accent)} 50%{opacity:0.5;box-shadow:0 0 2px var(--accent)} }
    nav { position:sticky; top:0; z-index:100; background:rgba(6,11,22,0.88); border-bottom:1px solid rgba(148,163,184,0.07); backdrop-filter:blur(20px) saturate(180%); -webkit-backdrop-filter:blur(20px) saturate(180%); }
    .nav-inner { position:relative; z-index:1; max-width:1200px; margin:0 auto; padding:0 24px; height:64px; display:flex; align-items:center; gap:16px; }
    .logo { display:flex; align-items:center; gap:10px; text-decoration:none; flex-shrink:0; }
    .logo-icon { width:32px; height:32px; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg,#1e3a5f,#0f2340); border:1px solid rgba(59,130,246,0.3); border-radius:8px; box-shadow:0 0 12px rgba(59,130,246,0.2); }
    .logo-icon svg { width:18px; height:18px; }
    .logo-name { font-size:17px; font-weight:700; letter-spacing:-0.3px; color:var(--text-primary); }
    .logo-name span { color:var(--accent); }
    .nav-links { flex:1; display:flex; justify-content:center; gap:36px; list-style:none; }
    .nav-link { font-size:13px; color:var(--text-secondary); text-decoration:none; transition:color 0.15s; }
    .nav-link:hover { color:var(--text-primary); }
    .nav-link.active { color:var(--text-primary); }
    .nav-cta { font-size:13px; font-weight:600; padding:7px 16px; border-radius:8px; border:none; background:var(--accent); color:#060b16; text-decoration:none; white-space:nowrap; flex-shrink:0; transition:opacity 0.15s,transform 0.15s; }
    .nav-cta:hover { opacity:0.88; transform:translateY(-1px); }
    .wrapper { position:relative; z-index:1; max-width:1200px; margin:0 auto; padding:0 24px; }
    .sub-banner { position:relative; z-index:1; background:rgba(168,255,62,0.04); border-bottom:1px solid rgba(168,255,62,0.1); }
    .sub-banner-inner { max-width:1200px; margin:0 auto; padding:11px 24px; display:flex; align-items:center; justify-content:center; gap:12px; flex-wrap:wrap; }
    .sub-banner-text { font-size:12px; color:var(--text-secondary); }
    .sub-banner-link { font-size:12px; font-weight:600; color:var(--accent); text-decoration:none; white-space:nowrap; transition:opacity 0.15s; }
    .sub-banner-link:hover { opacity:0.8; }
    .int-banner { position:relative; z-index:1; background:rgba(255,62,94,0.06); border-bottom:1px solid rgba(255,62,94,0.18); }
    .int-banner-inner { max-width:1200px; margin:0 auto; padding:11px 24px; display:flex; align-items:center; justify-content:center; gap:12px; flex-wrap:wrap; }
    .int-banner-text { font-size:12px; color:#ff9aa9; }
    .page-header { padding:40px 0 16px; }
    .page-title { font-size:22px; font-weight:700; letter-spacing:-0.5px; color:var(--text-primary); margin-bottom:4px; }
    .page-sub { font-size:13px; color:var(--text-muted); }
    .page-sub .stat-inline { font-family:var(--font-mono); color:var(--text-secondary); }
    .toolbar { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:32px; }
    .filter-group { display:flex; align-items:center; gap:6px; }
    .filter-label { font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:var(--text-muted); font-weight:500; margin-right:2px; }
    .filter-btn { font-family:var(--font-ui); font-size:12px; font-weight:500; padding:5px 12px; border-radius:100px; border:1px solid var(--card-border); background:transparent; color:var(--text-secondary); cursor:pointer; transition:all 0.15s ease; white-space:nowrap; }
    .filter-btn:hover { border-color:rgba(148,163,184,0.25); color:var(--text-primary); background:rgba(148,163,184,0.05); }
    .filter-btn.active-all { background:rgba(148,163,184,0.1); border-color:rgba(148,163,184,0.25); color:var(--text-primary); }
    .filter-btn[data-sev="CRITICAL"].active { background:rgba(255,62,94,0.15); border-color:rgba(255,62,94,0.4); color:var(--c-critical); }
    .filter-btn[data-sev="HIGH"].active { background:rgba(255,140,62,0.15); border-color:rgba(255,140,62,0.4); color:var(--c-high); }
    .filter-btn[data-sev="MEDIUM"].active { background:rgba(255,217,62,0.15); border-color:rgba(255,217,62,0.4); color:var(--c-medium); }
    .filter-btn[data-tier].active { background:rgba(148,163,184,0.12); border-color:rgba(148,163,184,0.35); color:var(--text-primary); }
    .toolbar-spacer { flex:1; }
    .search-wrap { position:relative; display:flex; align-items:center; }
    .search-wrap svg { position:absolute; left:10px; width:14px; height:14px; color:var(--text-muted); pointer-events:none; }
    .search-input { font-family:var(--font-ui); font-size:13px; background:rgba(13,21,42,0.6); border:1px solid var(--card-border); border-radius:8px; color:var(--text-primary); padding:7px 12px 7px 32px; width:240px; outline:none; transition:border-color 0.2s,box-shadow 0.2s; }
    .search-input::placeholder { color:var(--text-muted); }
    .search-input:focus { border-color:rgba(148,163,184,0.25); box-shadow:0 0 0 3px rgba(168,255,62,0.06); }
    .kbd-hint { position:absolute; right:8px; font-family:var(--font-mono); font-size:10px; color:var(--text-muted); pointer-events:none; transition:opacity 0.2s; }
    .search-input:focus + .kbd-hint { opacity:0; }
    .results-meta { font-size:12px; color:var(--text-muted); margin-bottom:20px; min-height:18px; }
    .results-meta strong { color:var(--text-secondary); }
    .cards-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:20px; margin-bottom:80px; }
    .card { background:var(--card-bg); border:1px solid var(--card-border); border-radius:var(--radius); padding:20px; display:flex; flex-direction:column; gap:14px; backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px); position:relative; overflow:hidden; transition:border-color 0.2s,box-shadow 0.2s,transform 0.2s; border-left:3px solid transparent; text-decoration:none; color:inherit; }
    .card:hover { border-color:var(--card-hover-border); transform:translateY(-3px); }
    .card[data-severity="CRITICAL"] { border-left-color:var(--c-critical); }
    .card[data-severity="HIGH"] { border-left-color:var(--c-high); }
    .card[data-severity="MEDIUM"] { border-left-color:var(--c-medium); }
    .card[data-severity="LOW"] { border-left-color:var(--c-low); }
    .card-top { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .badge { display:inline-flex; align-items:center; gap:5px; font-size:10px; font-weight:600; letter-spacing:0.07em; text-transform:uppercase; border-radius:var(--radius-sm); padding:3px 8px; }
    .sev-badge { border:1px solid transparent; }
    .sev-badge[data-severity="CRITICAL"] { background:rgba(255,62,94,0.15); color:var(--c-critical); border-color:rgba(255,62,94,0.3); }
    .sev-badge[data-severity="HIGH"] { background:rgba(255,140,62,0.15); color:var(--c-high); border-color:rgba(255,140,62,0.3); }
    .sev-badge[data-severity="MEDIUM"] { background:rgba(255,217,62,0.12); color:var(--c-medium); border-color:rgba(255,217,62,0.3); }
    .sev-badge[data-severity="LOW"] { background:rgba(62,184,255,0.12); color:var(--c-low); border-color:rgba(62,184,255,0.3); }
    .eco-badge { border:1px solid transparent; }
    .eco-badge[data-eco="npm"] { background:rgba(203,56,55,0.12); color:var(--eco-npm); border-color:rgba(203,56,55,0.3); }
    .eco-badge[data-eco="Go"] { background:rgba(0,172,215,0.12); color:var(--eco-go); border-color:rgba(0,172,215,0.3); }
    .eco-badge[data-eco="Maven"] { background:rgba(248,152,32,0.12); color:var(--eco-maven); border-color:rgba(248,152,32,0.3); }
    .eco-badge[data-eco="PyPI"] { background:rgba(53,114,165,0.15); color:var(--eco-pypi); border-color:rgba(53,114,165,0.35); }
    .badge-spacer { flex:1; }
    .date-label { font-family:var(--font-mono); font-size:11px; color:var(--text-muted); white-space:nowrap; }
    .star-chip { display:inline-flex; align-items:center; gap:3px; font-family:var(--font-mono); font-size:11px; font-weight:500; padding:2px 7px; border-radius:4px; border:1px solid transparent; white-space:nowrap; flex-shrink:0; }
    .star-chip.star-mega { color:#fbbf24; background:rgba(251,191,36,0.07); border-color:rgba(251,191,36,0.22); }
    .star-chip.star-high { color:#d97706; background:rgba(217,119,6,0.07); border-color:rgba(217,119,6,0.18); }
    .star-chip.star-mid { color:var(--text-muted); background:rgba(148,163,184,0.05); border-color:rgba(148,163,184,0.08); }
    .tier-badge { font-size:10px; font-weight:600; letter-spacing:0.06em; text-transform:uppercase; padding:3px 8px; border-radius:var(--radius-sm); border:1px solid transparent; }
    .tier-badge[data-tier="CONFIRMED"] { background:rgba(168,255,62,0.1); color:var(--accent); border-color:rgba(168,255,62,0.3); }
    .tier-badge[data-tier="ANALYZED"] { background:rgba(62,184,255,0.12); color:var(--c-low); border-color:rgba(62,184,255,0.3); }
    .tier-badge[data-tier="QUALIFYING"] { background:rgba(255,217,62,0.12); color:var(--c-medium); border-color:rgba(255,217,62,0.3); }
    .tier-badge[data-tier="REJECTED"] { background:rgba(255,62,94,0.1); color:var(--c-critical); border-color:rgba(255,62,94,0.25); }
    .tier-badge[data-tier="DEFERRED"] { background:rgba(168,99,255,0.12); color:#c8a0ff; border-color:rgba(168,99,255,0.3); }
    .tier-badge[data-tier="STUB"] { background:rgba(148,163,184,0.08); color:var(--text-secondary); border-color:rgba(148,163,184,0.18); }
    .tier-badge[data-tier="OTHER"] { background:rgba(148,163,184,0.08); color:var(--text-muted); border-color:rgba(148,163,184,0.15); }
    .status-chip { font-family:var(--font-mono); font-size:10px; color:var(--text-muted); }
    .poc-badge { display:inline-flex; align-items:center; gap:5px; font-size:10px; font-weight:600; letter-spacing:0.05em; padding:3px 8px; border-radius:var(--radius-sm); background:rgba(168,255,62,0.08); color:var(--accent); border:1px solid rgba(168,255,62,0.2); }
    .card-pkg { font-family:var(--font-mono); font-size:15px; font-weight:500; color:var(--text-primary); letter-spacing:-0.3px; line-height:1.3; word-break:break-word; }
    .card-teaser { font-size:13px; color:var(--text-secondary); line-height:1.6; display:-webkit-box; -webkit-line-clamp:3; -webkit-box-orient:vertical; overflow:hidden; }
    .card-ids { display:flex; align-items:center; flex-wrap:wrap; gap:6px; }
    .id-chip { font-family:var(--font-mono); font-size:11px; font-weight:500; color:var(--text-muted); background:rgba(148,163,184,0.05); border:1px solid rgba(148,163,184,0.08); border-radius:4px; padding:2px 7px; }
    .card-tags { display:flex; flex-wrap:wrap; gap:5px; }
    .tag { font-size:10px; font-weight:500; letter-spacing:0.04em; text-transform:lowercase; padding:2px 8px; border-radius:4px; background:rgba(148,163,184,0.06); color:var(--text-muted); border:1px solid rgba(148,163,184,0.07); }
    .card-refs { display:flex; flex-wrap:wrap; gap:8px; padding-top:4px; border-top:1px solid rgba(148,163,184,0.06); }
    .ref-link { display:inline-flex; align-items:center; gap:4px; font-size:11px; font-weight:500; color:var(--text-muted); text-decoration:none; padding:4px 10px; border-radius:var(--radius-sm); border:1px solid rgba(148,163,184,0.08); background:rgba(148,163,184,0.03); transition:all 0.15s; white-space:nowrap; }
    .ref-link:hover { color:var(--text-primary); border-color:rgba(148,163,184,0.2); background:rgba(148,163,184,0.07); }
    .get-access-btn { font-family:var(--font-ui); font-size:11px; font-weight:600; padding:6px 14px; border-radius:var(--radius-sm); border:1px solid rgba(168,255,62,0.35); background:rgba(168,255,62,0.08); color:var(--accent); text-decoration:none; transition:all 0.15s; display:inline-flex; align-items:center; gap:5px; letter-spacing:0.03em; cursor:pointer; }
    .get-access-btn:hover { background:rgba(168,255,62,0.15); border-color:rgba(168,255,62,0.55); transform:translateY(-1px); }
    .empty-state { grid-column:1/-1; text-align:center; padding:80px 20px; color:var(--text-muted); font-size:14px; }
    footer { border-top:1px solid var(--card-border); padding:28px 0; position:relative; z-index:1; }
    .footer-inner { max-width:1200px; margin:0 auto; padding:0 24px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px; }
    .footer-brand { font-size:12px; color:var(--text-muted); }
    .footer-brand strong { color:var(--text-secondary); font-weight:500; }
    .footer-note { font-size:11px; font-family:var(--font-mono); color:var(--text-muted); }
    /* detail view */
    .back-link { display:inline-block; margin-top:24px; font-size:13px; color:var(--text-secondary); text-decoration:none; }
    .back-link:hover { color:var(--text-primary); }
    .detail-head { padding:16px 0 8px; }
    .detail-title { font-family:var(--font-mono); font-size:22px; font-weight:600; color:var(--text-primary); letter-spacing:-0.3px; word-break:break-word; }
    .section { position:relative; z-index:1; background:var(--card-bg); border:1px solid var(--card-border); border-radius:var(--radius); padding:20px 22px; margin-bottom:18px; backdrop-filter:blur(12px); }
    .section h2 { font-size:12px; text-transform:uppercase; letter-spacing:0.09em; color:var(--text-secondary); margin-bottom:14px; }
    .sub-h { font-size:12px; text-transform:uppercase; letter-spacing:0.06em; color:var(--text-muted); margin:16px 0 8px; }
    .kv { display:grid; grid-template-columns:170px 1fr; gap:9px 16px; font-size:13px; }
    .kv dt { color:var(--text-muted); }
    .kv dd { color:var(--text-primary); word-break:break-word; }
    pre.code { background:#0a0f1d; border:1px solid var(--card-border); border-radius:8px; padding:14px; overflow:auto; max-height:520px; font-family:var(--font-mono); font-size:12px; line-height:1.55; color:#cbd5e1; white-space:pre; }
    pre.code code { font-family:inherit; }
    .vp { margin-bottom:14px; }
    .vp-loc { font-family:var(--font-mono); font-size:12px; color:var(--accent); margin-bottom:6px; }
    .md-body { font-size:14px; line-height:1.7; color:var(--text-secondary); }
    .md-body h1,.md-body h2,.md-body h3,.md-body h4 { color:var(--text-primary); margin:18px 0 8px; line-height:1.3; }
    .md-body h1 { font-size:19px; } .md-body h2 { font-size:16px; } .md-body h3 { font-size:14px; }
    .md-body p { margin:8px 0; } .md-body ul { margin:8px 0 8px 22px; } .md-body li { margin:3px 0; }
    .md-body code { font-family:var(--font-mono); font-size:0.9em; background:rgba(148,163,184,0.1); padding:1px 5px; border-radius:4px; color:#cbd5e1; }
    .md-body pre.code code { background:none; padding:0; }
    .md-body a { color:var(--c-low); }
    .md-body blockquote { border-left:3px solid var(--card-border); padding-left:12px; color:var(--text-muted); margin:10px 0; }
    .md-body table { border-collapse:collapse; margin:12px 0; font-size:13px; width:100%; }
    .md-body th,.md-body td { border:1px solid var(--card-border); padding:6px 10px; text-align:left; }
    .md-body th { color:var(--text-primary); background:rgba(148,163,184,0.05); }
    details.raw { margin-top:10px; }
    details.raw summary { cursor:pointer; color:var(--text-secondary); font-size:12px; font-family:var(--font-mono); }
    .file-list { display:flex; flex-direction:column; gap:6px; }
    .file-row { display:flex; justify-content:space-between; gap:12px; font-family:var(--font-mono); font-size:12px; padding:6px 10px; border:1px solid var(--card-border); border-radius:6px; background:rgba(148,163,184,0.03); }
    .file-row a { color:var(--accent); text-decoration:none; }
    .file-row span { color:var(--text-muted); }
    .warn-note { font-size:12px; color:#fbbf24; background:rgba(251,191,36,0.06); border:1px solid rgba(251,191,36,0.2); border-radius:6px; padding:8px 12px; margin-bottom:14px; }
    /* entries-by-state bar chart */
    .chart { margin-bottom:28px; }
    .chart .bar-row { display:flex; align-items:center; gap:12px; margin:7px 0; }
    .chart .bar-label { width:130px; flex-shrink:0; font-family:var(--font-mono); font-size:12px; color:var(--text-secondary); text-align:right; }
    .chart .bar-track { flex:1; height:16px; background:rgba(148,163,184,0.06); border-radius:4px; overflow:hidden; }
    .chart .bar-fill { height:100%; min-width:2px; border-radius:4px; transition:width .6s ease; }
    .chart .bar-count { width:60px; flex-shrink:0; font-family:var(--font-mono); font-size:12px; color:var(--text-primary); text-align:right; }
    .chart .bar-fill[data-tier="CONFIRMED"]  { background:var(--accent); }
    .chart .bar-fill[data-tier="ANALYZED"]   { background:var(--c-low); }
    .chart .bar-fill[data-tier="QUALIFYING"] { background:var(--c-medium); }
    .chart .bar-fill[data-tier="REJECTED"]   { background:var(--c-critical); }
    .chart .bar-fill[data-tier="DEFERRED"]   { background:#c8a0ff; }
    .chart .bar-fill[data-tier="STUB"]       { background:var(--text-secondary); }
    .chart .bar-fill[data-tier="OTHER"]      { background:var(--text-muted); }
    .modal-back { position:fixed; inset:0; background:rgba(0,0,0,0.6); display:none; align-items:center; justify-content:center; z-index:200; }
    .modal-back.open { display:flex; }
    .modal { background:var(--surface); border:1px solid var(--card-border); border-radius:12px; padding:26px; max-width:380px; text-align:center; }
    .modal p { font-size:13px; color:var(--text-secondary); line-height:1.6; margin-bottom:18px; }
    .modal button { font-family:var(--font-ui); font-size:13px; font-weight:600; padding:8px 18px; border-radius:8px; border:none; background:var(--accent); color:#060b16; cursor:pointer; }
    @media (max-width:680px) { .cards-grid { grid-template-columns:1fr; } .nav-links { display:none; } .kv { grid-template-columns:1fr; gap:2px 0; } .kv dt { margin-top:8px; } }
"""

INDEX_JS = r"""
const TIER_RANK = {CONFIRMED:0,ANALYZED:1,QUALIFYING:2,DEFERRED:3,REJECTED:4,STUB:5,OTHER:6};
let allRows = [], activeTiers = new Set(), activeSev = new Set(), q = '';

function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtStars(n){ if(!n||n<500) return ''; const l = n>=1000000?(n/1000000).toFixed(1)+'M':n>=10000?Math.round(n/1000)+'k':n>=1000?(n/1000).toFixed(1)+'k':n; const t=n>=50000?'mega':n>=10000?'high':'mid'; return `<span class="star-chip star-${t}">★ ${l}</span>`; }

function card(e){
  const ids=[...e.cve_ids,...e.ghsa_ids,...e.osv_ids];
  const idsHtml=ids.map(i=>`<span class="id-chip">${esc(i)}</span>`).join('');
  const tagsHtml=(e.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('');
  const sevBadge = e.severity?`<span class="badge sev-badge" data-severity="${esc(e.severity)}">${esc(e.severity)}</span>`:'';
  const ecoBadge = e.ecosystem?`<span class="badge eco-badge" data-eco="${esc(e.ecosystem)}">${esc(e.ecosystem)}</span>`:'';
  return `<a class="card" data-severity="${esc(e.severity)}" href="/entry/${encodeURIComponent(e.id)}">
    <div class="card-top">
      <span class="tier-badge" data-tier="${esc(e.tier)}">${esc(e.tier)}</span>
      <span class="status-chip">${esc(e.status)}</span>
      <div class="badge-spacer"></div>
      ${fmtStars(e.stars)}
    </div>
    <div class="card-pkg">${esc(e.package)}</div>
    ${ids.length?`<div class="card-ids">${idsHtml}</div>`:''}
    <div class="card-top">${sevBadge}${ecoBadge}</div>
    ${tagsHtml?`<div class="card-tags">${tagsHtml}</div>`:''}
  </a>`;
}

function filtered(){
  return allRows.filter(e=>{
    if(activeTiers.size && !activeTiers.has(e.tier)) return false;
    if(activeSev.size && !activeSev.has(e.severity)) return false;
    if(q && !e._s.includes(q)) return false;
    return true;
  });
}
function render(){
  const grid=document.getElementById('cardsGrid'), meta=document.getElementById('resultsMeta');
  const f=filtered();
  meta.innerHTML=`Showing <strong>${f.length}</strong> of ${allRows.length} entries`;
  grid.innerHTML = f.length ? f.slice(0,600).map(card).join('') +
      (f.length>600?`<div class="empty-state">…and ${f.length-600} more — narrow the filters.</div>`:'')
    : `<div class="empty-state">No entries match your filters.</div>`;
}
function syncBtns(){
  document.querySelectorAll('.filter-btn[data-tier]').forEach(b=>b.classList.toggle('active',activeTiers.has(b.dataset.tier)));
  document.querySelectorAll('.filter-btn[data-sev]').forEach(b=>b.classList.toggle('active',activeSev.has(b.dataset.sev)));
  document.querySelector('.filter-btn[data-filter="all"]').classList.toggle('active-all',!activeTiers.size&&!activeSev.size);
}
document.querySelectorAll('.filter-btn').forEach(b=>b.addEventListener('click',()=>{
  if(b.dataset.filter==='all'){activeTiers.clear();activeSev.clear();}
  else if(b.dataset.tier){activeTiers.has(b.dataset.tier)?activeTiers.delete(b.dataset.tier):activeTiers.add(b.dataset.tier);}
  else if(b.dataset.sev){activeSev.has(b.dataset.sev)?activeSev.delete(b.dataset.sev):activeSev.add(b.dataset.sev);}
  syncBtns();render();
}));
const si=document.getElementById('searchInput');
si.addEventListener('input',()=>{q=si.value.trim().toLowerCase();render();});
document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement!==si){e.preventDefault();si.focus();}
  if(e.key==='Escape'&&document.activeElement===si){si.blur();si.value='';q='';render();}
});
fetch('/api/entries.json').then(r=>r.json()).then(rows=>{
  allRows=rows.map(e=>({...e,_s:[e.id,e.package,e.status,...e.cve_ids,...e.ghsa_ids,...e.osv_ids,...(e.tags||[])].join(' ').toLowerCase()}));
  render();
}).catch(err=>{document.getElementById('cardsGrid').innerHTML='<div class="empty-state">Failed to load entries.</div>';console.error(err);});
"""

DETAIL_JS = r"""
function pocDemo(){ document.getElementById('modal').classList.add('open'); }
"""


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  CLI                                                                       ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local", action="store_true",
                      help="serve the INTERNAL dashboard on 127.0.0.1 only (Basic Auth)")
    mode.add_argument("--serve-public", action="store_true",
                      help="serve the public redacted site (static pages + JSON)")
    mode.add_argument("--export", action="store_true",
                      help="regenerate feed.json + metrics.json (default)")
    parser.add_argument("--research", type=Path, default=RESEARCH_DIR, help="Path to vulnfeed/research/")
    parser.add_argument("--out", type=Path, default=OUT_FILE, help="Output feed.json (export)")
    parser.add_argument("--metrics-out", type=Path, default=METRICS_FILE, help="Output metrics.json (export)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host for --serve-public")
    parser.add_argument("--port", type=int, default=None, help="Bind port for serve modes")
    args = parser.parse_args()

    if args.local:
        serve_local(args.research, args.port or 8077)
    elif args.serve_public:
        serve_public(args.research, args.host, args.port or 8078)
    else:
        run_export(args)


if __name__ == "__main__":
    main()
