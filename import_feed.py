#!/usr/bin/env python3
"""
import_feed.py  — build feed.json + metrics.json from sub-zero-days research.

feed.json    — only CONFIRMED entries (sandbox/Dockerfile present) for the
               public-facing VulnFeed page.

metrics.json — full pipeline view: funnel stats, rejection breakdown, and all
               CONFIRMED / ANALYZED / QUALIFYING entries for metrics.html.

Usage:
  ./import_feed.py                    # writes both files next to this script
  ./import_feed.py --research /path/to/sub-zero-days/research
  ./import_feed.py --out feed.json --metrics-out metrics.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Default paths ──────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).parent
RESEARCH_DIR = SCRIPT_DIR.parent / "sub-zero-days" / "research"
OUT_FILE     = SCRIPT_DIR / "feed.json"

# ── Severity mapping ───────────────────────────────────────────────────────────
def sev_from_hint(hint: float) -> str:
    if hint >= 0.9:  return "CRITICAL"
    if hint >= 0.55: return "HIGH"
    if hint >= 0.25: return "MEDIUM"
    return "LOW"

# ── Ecosystem normalisation ────────────────────────────────────────────────────
ECO_ALIASES = {
    "pypi":    "PyPI",
    "npm":     "npm",
    "go":      "Go",
    "maven":   "Maven",
    "nuget":   "NuGet",
    "cargo":   "Rust",
    "rubygems":"RubyGems",
    "packagist":"PHP",
    "hex":     "Elixir",
    "pub":     "Dart",
    "cran":    "R",
}
PLATFORM_ECO = {
    "alpine-secfixes": "Alpine",
    "redhat-tracker":  "RPM",
    "ubuntu-tracker":  "Debian",
    "oss-security":    "Linux",
}

def normalise_eco(raw: str) -> str:
    return ECO_ALIASES.get(raw.lower(), raw)

def ecosystem_from(data: dict) -> str:
    for sig in data.get("signals", []):
        eco = sig.get("extra", {}).get("ecosystem", "")
        if eco:
            return normalise_eco(eco)
    return PLATFORM_ECO.get(data.get("platform", ""), "Unknown")

# ── Pipeline tier ──────────────────────────────────────────────────────────────
# Maps canonical status (lib/status.py) → display tier.
# Inlined here to avoid a cross-repo import (vulnfeed/ and sub-zero-days/ are siblings).
_STATUS_TO_TIER = {
    "confirmed":       "CONFIRMED",
    "sandbox-aborted": "ANALYZED",
    "not-triggered":   "ANALYZED",
    "analyzed":        "ANALYZED",
    "analysis-aborted":"QUALIFYING",
    "qualified":       "QUALIFYING",
}

def _parse_outcome_status(entry_dir: Path) -> str:
    """Return the lowercase status string from outcome.md, or ''."""
    import re
    path = entry_dir / "outcome.md"
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return ""
    # YAML frontmatter
    fm = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    if fm:
        for line in fm.group(1).splitlines():
            m = re.match(r"^status:\s*(.+)", line.strip(), re.IGNORECASE)
            if m:
                return m.group(1).strip().lower()
    # Markdown bullets and table rows
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
    """Return the display tier (CONFIRMED/ANALYZED/QUALIFYING) or None to skip.

    Fast path: reads status.json written by each skill.
    Fallback: derives tier from artifact presence with correct partial-state handling:
    - Partial sandbox (Dockerfile present, run_poc.sh or README.md missing)
      → ANALYZED, not CONFIRMED.
    - Partial analysis (only one of analysis.json / analysis.md)
      → QUALIFYING, not ANALYZED.
    - outcome.md with 'aborted' at analysis tier → QUALIFYING (previous state).
    """
    # Fast path: status.json
    status_path = entry_dir / "status.json"
    if status_path.exists():
        try:
            s = json.loads(status_path.read_text())
            status = s.get("status", "")
            if status in _STATUS_TO_TIER:
                return _STATUS_TO_TIER[status]
            if status in ("rejected", "deferred", "stub"):
                return None
        except Exception:
            pass  # fall through to artifact inference

    # Fallback: derive from artifacts
    out_status = _parse_outcome_status(entry_dir)

    sandbox = entry_dir / "sandbox"
    if (sandbox / "Dockerfile").exists():
        if (sandbox / "run_poc.sh").exists() and (sandbox / "README.md").exists():
            return "CONFIRMED"
        # Partial sandbox: fall through to analysis check

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

# ── ID extraction ─────────────────────────────────────────────────────────────
def _osv_ids_raw(data: dict) -> list[str]:
    seen, out = set(), []
    for sig in data.get("signals", []):
        oid = sig.get("extra", {}).get("osv_id", "")
        if oid and oid not in seen:
            seen.add(oid); out.append(oid)
    return out

def ghsa_ids_from(data: dict) -> list[str]:
    """Merge explicit ghsa_ids field + GHSA-prefixed OSV IDs from signal extras."""
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
    """Non-GHSA OSV IDs (MAL-, GO-, PYSEC-, etc.)."""
    return [oid for oid in _osv_ids_raw(data) if not oid.startswith("GHSA-")]

# ── Fixed-version extraction ───────────────────────────────────────────────────
def fixed_versions_from(data: dict) -> list[str]:
    seen, out = set(), []
    for sig in data.get("signals", []):
        for v in sig.get("extra", {}).get("all_fixed_versions", []):
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out

# ── Reference building ─────────────────────────────────────────────────────────
def build_refs(data: dict, disc: dict | None) -> list[dict]:
    seen_urls: set[str] = set()
    refs: list[dict] = []

    def add(kind: str, url: str, label: str) -> None:
        if not url or url in seen_urls:
            return
        seen_urls.add(url)
        refs.append({"kind": kind, "url": url, "label": label})

    # Qualification evidence URLs (highest quality — agent-verified)
    if disc:
        for url in disc.get("qualification", {}).get("evidence_urls", []):
            if "osv.dev" in url:
                add("osv", url, url.rsplit("/", 1)[-1])
            elif "github.com/advisories" in url:
                label = url.rsplit("/", 1)[-1]
                add("advisory", url, label)
            elif "github.com" in url and "/commit/" in url:
                add("commit", url, "Fix commit · " + url.rsplit("/", 1)[-1][:10])
            else:
                add("advisory", url, url.rsplit("/", 1)[-1][:40])

    # Fix commit SHAs from discovery.json
    if disc:
        repo = disc.get("repo_url", data.get("repo_url", ""))
        for sha in disc.get("fix_commit_shas", []):
            if repo:
                url = f"{repo.rstrip('/')}/commit/{sha}"
                add("commit", url, f"Fix commit · {sha[:10]}")

    # GHSA IDs not yet linked
    for ghsa in data.get("ghsa_ids", []):
        add("advisory", f"https://github.com/advisories/{ghsa}", ghsa)

    # Signal URLs as fallback
    for sig in data.get("signals", []):
        url = sig.get("url", "")
        title = sig.get("title", url.rsplit("/", 1)[-1])[:50]
        if "osv.dev" in url:
            add("osv", url, sig.get("extra", {}).get("osv_id", title))
        elif url:
            add("advisory", url, title)

    return refs

# ── Tag inference ──────────────────────────────────────────────────────────────
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

# ── Teaser extraction ──────────────────────────────────────────────────────────
def _is_prose_line(line: str) -> bool:
    """Return True if a line looks like a prose sentence, not markdown scaffolding."""
    stripped = line.strip()
    if not stripped or len(stripped) < 35:
        return False
    if stripped.startswith(("#", "-", "*", "|", ">")):  # headings, bullets, tables, blockquotes
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
        # Split into paragraphs first; pick the first prose paragraph
        paragraphs = [p.strip() for p in excerpt.split("\n\n") if p.strip()]
        for para in paragraphs:
            # Flatten multi-line paragraph into a single string
            flat = " ".join(l.strip() for l in para.splitlines() if l.strip())
            if flat.lower().rstrip(".") == title_norm:
                continue
            if _is_prose_line(flat):
                import re
                # Strip HTML tags (complete and truncated), then inline markdown
                flat = re.sub(r"<[^>]+>", "", flat)
                flat = re.sub(r"<[^>]*$", "", flat).strip()
                flat = re.sub(r"`([^`]+)`", r"\1", flat)
                flat = re.sub(r"\*\*([^*]+)\*\*", r"\1", flat)
                flat = re.sub(r"\*([^*]+)\*",   r"\1", flat)
                flat = flat.strip()
                if len(flat) < 35:
                    continue
                return flat[:240]
    return f"Security vulnerability in {data.get('project_name', 'unknown package')}."

# ── Per-entry processor ────────────────────────────────────────────────────────
def process_entry(entry_dir: Path) -> dict | None:
    stub_path = entry_dir / "stub.json"
    disc_path = entry_dir / "discovery.json"

    if not stub_path.exists() and not disc_path.exists():
        return None

    # Prefer discovery.json (richer, agent-verified) over stub.json
    primary_path = disc_path if disc_path.exists() else stub_path
    data = json.loads(primary_path.read_text())
    disc = json.loads(disc_path.read_text()) if disc_path.exists() else None

    # Determine pipeline tier
    status = pipeline_tier(entry_dir)
    if status is None:
        return None

    cve_ids  = data.get("cve_ids") or []
    ghsa_ids = ghsa_ids_from(data)
    osv_ids  = osv_ids_from(data)

    # Must have at least one public identifier to appear in feed
    if not cve_ids and not ghsa_ids and not osv_ids:
        return None

    signals  = data.get("signals", [])
    title    = signals[0]["title"] if signals else data.get("project_name", entry_dir.name)
    priority = data.get("priority_components", {})
    severity = sev_from_hint(priority.get("severity_hint", 0.3))

    # Prefer the structured attacker-centric description from analysis.json
    # (written by vuln-analysis, polished by poc-sandbox) over scraped advisory text.
    analysis_path = entry_dir / "analysis.json"
    if analysis_path.exists():
        try:
            analysis_desc = json.loads(analysis_path.read_text()).get("description", "")
        except Exception:
            analysis_desc = ""
    else:
        analysis_desc = ""
    teaser = analysis_desc if analysis_desc else extract_teaser(data, title)

    # clone_of lives in stub.json even when discovery.json is primary
    stub_data = json.loads(stub_path.read_text()) if stub_path.exists() else {}
    clone_of         = stub_data.get("clone_of") or data.get("clone_of") or None
    clone_source_url = stub_data.get("clone_source_url") or data.get("clone_source_url") or None

    entry: dict = {
        "id":           entry_dir.name,
        "title":        title,
        "teaser":       teaser,
        "package":      data.get("project_name", entry_dir.name),
        "ecosystem":    ecosystem_from(data),
        "severity":     severity,
        "cve_ids":      cve_ids,
        "ghsa_ids":     ghsa_ids,
        "osv_ids":      osv_ids,
        "fixed_in":     fixed_versions_from(data),
        "action":       None,
        "discovered_at": data.get("discovered_at", ""),
        "poc_status":   status,
        "priority_score": data.get("priority_score", 0.0),
        "tags":         infer_tags(data),
        "references":   build_refs(data, disc),
    }
    if clone_of:
        entry["clone_of"]         = clone_of
        entry["clone_source_url"] = clone_source_url
    return entry

# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--research",     type=Path, default=RESEARCH_DIR, help="Path to sub-zero-days/research/")
    parser.add_argument("--out",          type=Path, default=OUT_FILE,              help="Output feed.json (CONFIRMED only)")
    parser.add_argument("--metrics-out",  type=Path, default=SCRIPT_DIR / "metrics.json", help="Output metrics.json (all tiers)")
    args = parser.parse_args()

    research: Path = args.research
    if not research.is_dir():
        print(f"error: research dir not found: {research}", file=sys.stderr)
        sys.exit(1)

    all_entries: list[dict] = []
    rejection_reasons: dict[str, int] = {}
    total_dirs = 0
    total_qualified = 0

    for entry_dir in sorted(research.iterdir()):
        if not entry_dir.is_dir():
            continue
        total_dirs += 1

        # Collect rejection reasons for metrics
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

    # Sort: tier order (CONFIRMED > ANALYZED > QUALIFYING), then priority_score desc
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

    # ── feed.json — CONFIRMED only ─────────────────────────────────────────────
    confirmed = [
        {k: v for k, v in e.items() if k != "priority_score"}
        for e in all_entries if e["poc_status"] == "CONFIRMED"
    ]
    feed = {
        "generated_at":              now,
        "pipeline":                  "sub-zero-days/0.1",
        "total_candidates_analyzed": total_dirs,
        "confirmed_pocs":            totals["CONFIRMED"],
        "entries":                   confirmed,
    }
    args.out.write_text(json.dumps(feed, indent=2, ensure_ascii=False))

    # ── metrics.json — all tiers + pipeline stats ──────────────────────────────
    metrics_entries = [
        {k: v for k, v in e.items() if k != "priority_score"}
        for e in all_entries
    ]
    # Include rejection rationale from discovery.json for QUALIFYING entries
    for e in metrics_entries:
        disc_path = research / e["id"] / "discovery.json"
        if disc_path.exists():
            disc = json.loads(disc_path.read_text())
            q = disc.get("qualification", {})
            e["qualification_rationale"] = q.get("rationale", "")
            e["fix_commit_shas"] = disc.get("fix_commit_shas", [])

    metrics = {
        "generated_at": now,
        "pipeline":     "sub-zero-days/0.1",
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
    args.metrics_out.write_text(json.dumps(metrics, indent=2, ensure_ascii=False))

    clone_passed   = sum(clone_totals.values())
    clone_analyzed = clone_totals["CONFIRMED"] + clone_totals["ANALYZED"]
    print(f"feed.json    → {args.out}  ({totals['CONFIRMED']} CONFIRMED entries)")
    print(f"metrics.json → {args.metrics_out}  ({len(all_entries)} total entries)")
    print(f"  CONFIRMED  {totals['CONFIRMED']}  (clone: {clone_totals['CONFIRMED']})")
    print(f"  ANALYZED   {totals['ANALYZED']}  (clone: {clone_totals['ANALYZED']})")
    print(f"  QUALIFYING {totals['QUALIFYING']}  (clone: {clone_totals['QUALIFYING']})")
    print(f"  funnel: {total_dirs} discovered → {total_qualified} qualified → "
          f"{totals['CONFIRMED']+totals['ANALYZED']+totals['QUALIFYING']} passed → "
          f"{totals['CONFIRMED']} confirmed")
    print(f"  clone-qualify: {total_clone_stubs} discovered → {clone_passed} passed → "
          f"{clone_analyzed} analyzed → {clone_totals['CONFIRMED']} confirmed")


if __name__ == "__main__":
    main()
