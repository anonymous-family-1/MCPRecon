#!/usr/bin/env python3
"""
MCPRecon: protocol-aware, transport-agnostic MCP artifact reconstruction from raw memory snapshots.

Usage:
    ./mcprecon.py snapshot.vmem --keywords jsonrpc tools/list tools/call --window 16384 --emit-raw > out.jsonl

Outputs newline-delimited JSON objects with fields:
    offset: integer file offset of carved JSON
    session: session index (heuristic by proximity)
    vma: placeholder (unknown in raw-file mode)
    type: request|response|notification|unknown
    id: JSON-RPC id if present
    method: method name if present
    tool: tool name for tools/call if present
    confidence: float 0..1
    json: parsed object
    raw: optional raw JSON text (when --emit-raw)
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional, Iterable

AnchorHit = Tuple[int, bytes]

JSONRPC_RE = re.compile(rb'"jsonrpc"\s*:\s*"2\.0"')
BRACE_OPEN = ord('{')
BRACE_CLOSE = ord('}')

DEFAULT_KEYWORDS = [b"jsonrpc", b"tools/list", b"tools/call"]
SESSION_WEIGHTS = {
    "json": 0.2,
    "rpc": 0.2,
    "mcp": 0.2,
    "pair": 0.2,
    "prov": 0.2,
}
SESSION_GAP = 512 * 1024
DEFAULT_TEMP_DIR = ".mcpsniffer_tmp"
CLIENT_PATTERNS = {
    "codex": ["code", "code helper", "codex", "cursor"],  # VS Code / Cursor variants
    "cursor": ["cursor"],
    "copilot": ["copilot", "github-copilot", "copilot-agent"],
}


def find_anchors(buf: bytes, keywords: List[bytes]) -> List[AnchorHit]:
    hits: List[AnchorHit] = []
    for kw in keywords:
        start = 0
        while True:
            idx = buf.find(kw, start)
            if idx == -1:
                break
            hits.append((idx, kw))
            start = idx + 1
    hits.sort(key=lambda x: x[0])
    return hits


def carve_json(buf: bytes, anchor_pos: int, window: int) -> Tuple[int, bytes] | None:
    """Carve a JSON object around anchor using brace balancing inside a window.
    Returns (start_offset, json_bytes) in global buffer coordinates.
    """
    start = max(0, anchor_pos - window)
    end = min(len(buf), anchor_pos + window)
    slice_buf = buf[start:end]
    # find nearest '{' before anchor
    left = slice_buf.rfind(b'{', 0, anchor_pos - start + 1)
    if left == -1:
        return None
    # balance braces from left
    depth = 0
    json_end_rel = None
    for i in range(left, len(slice_buf)):
        b = slice_buf[i]
        if b == BRACE_OPEN:
            depth += 1
        elif b == BRACE_CLOSE:
            depth -= 1
            if depth == 0:
                json_end_rel = i + 1
                break
    if json_end_rel is None:
        return None
    carved = slice_buf[left:json_end_rel]
    return start + left, carved


def is_valid_jsonrpc(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    if obj.get("jsonrpc") != "2.0":
        return False
    has_method = "method" in obj
    has_result = "result" in obj
    has_error = "error" in obj
    if not (has_method or has_result or has_error):
        return False
    # id consistency
    if "id" in obj and not isinstance(obj["id"], (str, int)):
        return False
    return True


def is_mcp_semantic(obj: Dict[str, Any]) -> bool:
    method = obj.get("method")
    if isinstance(method, str) and method.startswith(("tools/", "resources/", "prompts/", "notifications/")):
        return True
    # tool schema in results
    res = obj.get("result")
    if isinstance(res, dict) and "tools" in res:
        return True
    return False


def classify_type(obj: Dict[str, Any]) -> str:
    if "method" in obj and "id" in obj:
        return "request"
    if "method" in obj and "id" not in obj:
        return "notification"
    if "result" in obj or "error" in obj:
        return "response"
    return "unknown"


def tool_name(obj: Dict[str, Any]) -> str | None:
    method = obj.get("method")
    if method == "tools/call":
        params = obj.get("params")
        if isinstance(params, dict):
            return params.get("name")
    return None


def score_pairing(recs: List[Dict[str, Any]]) -> float:
    """Pairing score: fraction of id-bearing messages that are part of a req/resp pair."""
    by_id: Dict[Any, set] = defaultdict(set)
    for r in recs:
        rid = r.get("id")
        if rid is None:
            continue
        by_id[rid].add(r["type"])
    total_with_id = sum(1 for r in recs if r.get("id") is not None)
    if total_with_id == 0:
        return 0.5
    paired_msgs = 0
    for rid, types in by_id.items():
        if "request" in types and "response" in types:
            # count only req/resp messages contributing to a complete pair
            paired_msgs += sum(1 for r in recs if r.get("id") == rid and r["type"] in ("request", "response"))
    return min(1.0, paired_msgs / total_with_id)


def score_provenance(recs: List[Dict[str, Any]]) -> float:
    """Heuristic provenance coherence based on offset compactness."""
    if len(recs) < 2:
        return 1.0
    offs = [r["offset"] for r in recs]
    span = max(offs) - min(offs)
    # normalize span against 2 * SESSION_GAP (empirical)
    return max(0.0, min(1.0, 1 / (1 + span / (SESSION_GAP * 2))))


def compute_session_scores(attempts: List[Dict[str, Any]], records: List[Dict[str, Any]]) -> Dict[Tuple[Any, int], Dict[str, float]]:
    """Aggregate component scores per (tag, session) and combine with weights."""
    attempts_by_sess: Dict[Tuple[Any, int], List[Dict[str, Any]]] = defaultdict(list)
    for a in attempts:
        attempts_by_sess[(a.get("tag"), a["session"])].append(a)

    records_by_sess: Dict[Tuple[Any, int], List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        records_by_sess[(r.get("tag"), r["session"])].append(r)

    scores: Dict[Tuple[Any, int], Dict[str, float]] = {}
    for key, att in attempts_by_sess.items():
        recs = records_by_sess.get(key, [])
        total = len(att)
        parsed = sum(1 for a in att if a["parsed"])
        valid_rpc = sum(1 for a in att if a["rpc_valid"])
        mcp_hits = sum(1 for a in att if a["mcp"])

        c_json = parsed / total if total else 0.0
        c_rpc = valid_rpc / parsed if parsed else 0.0
        c_mcp = mcp_hits / valid_rpc if valid_rpc else 0.0
        c_pair = score_pairing(recs)
        c_prov = score_provenance(att)

        combined = (
            SESSION_WEIGHTS["json"] * c_json
            + SESSION_WEIGHTS["rpc"] * c_rpc
            + SESSION_WEIGHTS["mcp"] * c_mcp
            + SESSION_WEIGHTS["pair"] * c_pair
            + SESSION_WEIGHTS["prov"] * c_prov
        )
        scores[key] = {
            "json": round(c_json, 3),
            "rpc": round(c_rpc, 3),
            "mcp": round(c_mcp, 3),
            "pair": round(c_pair, 3),
            "prov": round(c_prov, 3),
            "combined": round(combined, 3),
        }
    return scores


def cluster_sessions(hits: List[Dict[str, Any]], gap: int = 512 * 1024, tag_key: str = "tag") -> None:
    """Assign session numbers independently within each tag bucket using gap heuristic."""
    if not hits:
        return
    buckets: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for h in hits:
        buckets[h.get(tag_key)].append(h)
    for tag, bucket in buckets.items():
        bucket.sort(key=lambda r: r["offset"])
        current = 0
        last_off = bucket[0]["offset"]
        for h in bucket:
            if h["offset"] - last_off > gap:
                current += 1
            h["session"] = current
            last_off = h["offset"]


def load_regions(path: str, default_tag: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load regions from JSON/JSONL/TSV file. Each entry: start,end[,tag]. Offsets are integers."""
    regions: List[Dict[str, Any]] = []
    if path.endswith(".tsv") or path.endswith(".txt"):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) < 2:
                    continue
                start, end = int(parts[0], 0), int(parts[1], 0)
                tag = parts[2] if len(parts) > 2 else default_tag
                regions.append({"start": start, "end": end, "tag": tag})
    else:
        with open(path, "r", encoding="utf-8") as f:
            txt = f.read().strip()
            if not txt:
                return regions
            if txt[0] == "[":
                entries = json.loads(txt)
                for e in entries:
                    regions.append(
                        {
                            "start": int(e["start"]),
                            "end": int(e["end"]),
                            "tag": e.get("tag", default_tag),
                        }
                    )
            else:
                # JSONL
                for line in txt.splitlines():
                    e = json.loads(line)
                    regions.append(
                        {
                            "start": int(e["start"]),
                            "end": int(e["end"]),
                            "tag": e.get("tag", default_tag),
                        }
                    )
    return regions


def load_pslist(path: str) -> List[Dict[str, Any]]:
    """Parse a pslist/psscan-style text/JSON/JSONL/vol3-json into [{pid,name}]."""
    entries: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    if not txt.strip():
        return entries
    # JSON array or JSONL
    if txt.lstrip().startswith("[") or txt.lstrip().startswith("{"):
        # vol3 json output: {"columns": [...], "rows": [...]}
        if txt.lstrip().startswith("{") and "\"columns\"" in txt and "\"rows\"" in txt:
            data = json.loads(txt)
            col_idx = {c: i for i, c in enumerate(data.get("columns", []))}
            for row in data.get("rows", []):
                try:
                    pid = int(row[col_idx.get("PID", 1)])
                    name = str(row[col_idx.get("ImageFileName", -1)]).lower()
                    entries.append({"pid": pid, "name": name})
                except Exception:
                    continue
            return entries
        for line in txt.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line) if line.startswith("{") else None
            if obj is None and line.startswith("["):
                arr = json.loads(line)
                for o in arr:
                    entries.append({"pid": int(o.get("pid", 0)), "name": str(o.get("name", "")).lower()})
                return entries
            if obj:
                entries.append({"pid": int(obj.get("pid", 0)), "name": str(obj.get("name", "")).lower()})
        return entries
    # Plain text volatility pslist output
    for line in txt.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        # heuristic: PID is an int in column 1 or 2, name last
        pid = None
        for p in parts:
            if p.isdigit():
                pid = int(p)
                break
        if pid is None:
            continue
        name = parts[-1].lower()
        entries.append({"pid": pid, "name": name})
    return entries


def pick_pid_for_client(client: Optional[str], pslist: List[Dict[str, Any]]) -> Optional[int]:
    if not client or not pslist:
        return None
    patterns = CLIENT_PATTERNS.get(client, [])
    for p in pslist:
        name = p["name"]
        if any(tok in name for tok in patterns):
            return p["pid"]
    return None


def load_vmas(path: str, target_pid: int, default_tag: Optional[str]) -> List[Dict[str, Any]]:
    """Load VMA ranges for a PID. Supports JSON/JSONL/TSV with fields: pid,start,end[,tag]."""
    regions: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    if not lines:
        return regions
    if lines[0].lstrip().startswith("["):
        data = json.loads("\n".join(lines))
        for e in data:
            if int(e.get("pid", -1)) != target_pid:
                continue
            regions.append({"start": int(e["start"]), "end": int(e["end"]), "tag": e.get("tag", default_tag)})
        return regions
    # JSONL or TSV
    for line in lines:
        if not line.strip():
            continue
        if line.lstrip().startswith("{"):
            e = json.loads(line)
            if int(e.get("pid", -1)) != target_pid:
                continue
            regions.append({"start": int(e["start"]), "end": int(e["end"]), "tag": e.get("tag", default_tag)})
        else:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pid = int(parts[0], 0)
            if pid != target_pid:
                continue
            start, end = int(parts[1], 0), int(parts[2], 0)
            tag = parts[3] if len(parts) > 3 else default_tag
            regions.append({"start": start, "end": end, "tag": tag})
    return regions


def region_for_offset(regions: List[Dict[str, Any]], offset: int) -> Optional[Dict[str, Any]]:
    for reg in regions:
        if reg["start"] <= offset < reg["end"]:
            return reg
    return None


def auto_regions_from_anchors(anchors: List[Tuple[int, bytes]], window: int, tag: Optional[str]) -> List[Dict[str, Any]]:
    """Derive coarse regions from anchor positions using the session gap heuristic."""
    if not anchors:
        return []
    anchors = sorted(anchors, key=lambda a: a[0])
    regions: List[Dict[str, Any]] = []
    start = max(0, anchors[0][0] - window)
    last = anchors[0][0]
    for pos, _ in anchors[1:]:
        if pos - last > SESSION_GAP:
            regions.append({"start": start, "end": last + window, "tag": tag})
            start = max(0, pos - window)
        last = pos
    regions.append({"start": start, "end": last + window, "tag": tag})
    return regions


def log(msg: str, quiet: bool = False) -> None:
    if quiet:
        return
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def render_progress(done: int, total: int, width: int = 40) -> str:
    if total <= 0:
        return "[progress unavailable]"
    ratio = min(1.0, max(0.0, done / total))
    filled = int(ratio * width)
    bar = "=" * filled + " " * (width - filled)
    return f"[{bar}] {ratio*100:5.1f}% ({done}/{total})"


def run_vol3_pslist(vol_path: str, snapshot: str, temp_dir: str, quiet: bool) -> Optional[str]:
    """Run volatility3 linux.pslist and save JSON output. Return path or None on failure."""
    out_path = os.path.join(temp_dir, "pslist.json")
    cache_dir = os.path.join(temp_dir, "volcache")
    os.makedirs(cache_dir, exist_ok=True)
    cmd = [
        "python3",
        vol_path,
        "-f",
        snapshot,
        "--cache-path",
        cache_dir,
        "-r",
        "json",
        "linux.pslist",
    ]
    log(f"[+] Running vol3 pslist: {' '.join(cmd)}", quiet)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        log(f"[+] pslist written to {out_path}", quiet)
        return out_path
    except Exception as e:
        log(f"[!] vol3 pslist failed: {e}", quiet)
        return None


def process_file(path: str, keywords: List[str], window: int, emit_raw: bool, tools_only: bool,
                 mcp_only: bool, regions_file: Optional[str], client_tag: Optional[str], ps_file: Optional[str],
                 vma_file: Optional[str], vol3: Optional[str], temp_dir: str, quiet: bool):
    log(f"[+] Loading snapshot: {path}", quiet)
    with open(path, "rb") as f:
        data = f.read()
    log(f"[+] Snapshot size: {len(data):,} bytes", quiet)

    # Acquire pslist only when a client tag is specified
    pslist: List[Dict[str, Any]] = []
    if client_tag:
        if ps_file is None and vol3:
            ps_file = run_vol3_pslist(vol3, path, temp_dir, quiet)
        pslist = load_pslist(ps_file) if ps_file else []
    target_pid: Optional[int] = None
    if client_tag and pslist:
        target_pid = pick_pid_for_client(client_tag, pslist)
        if target_pid is None:
            log(f"[!] No process found matching client '{client_tag}' in ps list; aborting.", quiet)
            return
        log(f"[+] Matched client '{client_tag}' to PID {target_pid}", quiet)

    regions: List[Dict[str, Any]] = []
    if regions_file:
        if target_pid is not None and vma_file:
            regions = load_vmas(vma_file, target_pid, default_tag=client_tag)
            log(f"[+] Loaded {len(regions)} regions from VMA file for PID {target_pid}", quiet)
        else:
            regions = load_regions(regions_file, default_tag=client_tag)
            log(f"[+] Loaded {len(regions)} regions", quiet)

    # Always include jsonrpc as an anchor so responses are carved even if the
    # user overrides --keywords with tool-only anchors.
    kw_bytes = sorted({k.encode() for k in keywords} | {b"jsonrpc"})
    anchors = find_anchors(data, kw_bytes)
    log(f"[+] Found {len(anchors)} anchor hits", quiet)

    if not regions_file:
        regions = auto_regions_from_anchors(anchors, window, client_tag)
        if regions:
            auto_regions_path = os.path.join(temp_dir, "regions_auto.json")
            with open(auto_regions_path, "w", encoding="utf-8") as f:
                json.dump(regions, f, indent=2)
            log(f"[+] Auto-derived {len(regions)} regions -> {auto_regions_path}", quiet)
        else:
            log("[!] No regions auto-derived (no anchors)", quiet)

    seen_offsets = set()
    attempts: List[Dict[str, Any]] = []
    records = []
    for idx, (pos, kw) in enumerate(anchors):
        reg = region_for_offset(regions, pos) if regions else None
        tag = reg["tag"] if reg else client_tag
        if regions and reg is None:
            continue  # outside allowed regions
        carved = carve_json(data, pos, window)
        if not carved:
            attempts.append(
                {
                    "offset": pos,
                    "parsed": False,
                    "rpc_valid": False,
                    "mcp": False,
                    "type": "unknown",
                    "id": None,
                    "tag": tag,
                }
            )
            continue
        start, blob = carved
        if start in seen_offsets:
            continue
        seen_offsets.add(start)
        try:
            obj = json.loads(blob.decode(errors="ignore"))
            parsed_ok = True
        except Exception:
            parsed_ok = False
        if not parsed_ok:
            attempts.append(
                {
                    "offset": start,
                    "parsed": False,
                    "rpc_valid": False,
                    "mcp": False,
                    "type": "unknown",
                    "id": None,
                    "tag": tag,
                }
            )
            continue
        valid = is_valid_jsonrpc(obj)
        mcp = is_mcp_semantic(obj)
        attempts.append(
            {
                "offset": start,
                "parsed": True,
                "rpc_valid": valid,
                "mcp": mcp,
                "type": classify_type(obj) if valid else "unknown",
                "id": obj.get("id") if isinstance(obj, dict) else None,
                "tag": tag,
            }
        )
        if not valid:
            continue
        rec = {
            "offset": start,
            "type": classify_type(obj),
            "id": obj.get("id"),
            "method": obj.get("method"),
            "tool": tool_name(obj),
            "valid": valid,
            "mcp": mcp,
            "json": obj,
            "tag": tag,
        }
        if emit_raw:
            rec["raw"] = blob.decode(errors="ignore")
        records.append(rec)
        if not quiet and (idx + 1) % 50 == 0:
            sys.stderr.write("\r" + render_progress(idx + 1, len(anchors)))
            sys.stderr.flush()
    if not quiet:
        sys.stderr.write("\r" + render_progress(len(anchors), len(anchors)) + "\n")
        sys.stderr.flush()
    # Optional filtering to only MCP-semantic records (plus their paired responses)
    if mcp_only:
        mcp_ids = {r["id"] for r in records if r.get("mcp")}
        records = [r for r in records if r.get("mcp") or (r.get("id") in mcp_ids)]
        attempts = [a for a in attempts if a.get("mcp") or (a.get("id") in mcp_ids)]

    # Optional filtering to tools/call only (requests and their matched responses)
    if tools_only:
        tool_ids = {r["id"] for r in records if r.get("method") == "tools/call"}
        records = [r for r in records if (r.get("method") == "tools/call") or (r.get("id") in tool_ids)]
    attempts.sort(key=lambda r: r["offset"])
    records.sort(key=lambda r: r["offset"])
    cluster_sessions(attempts, gap=SESSION_GAP)
    offset_to_session = {a["offset"]: a["session"] for a in attempts}
    for r in records:
        r["session"] = offset_to_session.get(r["offset"], 0)
    session_scores = compute_session_scores(attempts, records)
    log(f"[+] Attempts: {len(attempts)}, valid records: {len(records)}, sessions: {len(session_scores)}", quiet)
    for r in records:
        key = (r.get("tag"), r["session"])
        r["confidence"] = session_scores.get(key, {}).get("combined", 0.0)
        print(json.dumps(r, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser(description="MCPSniffer: carve MCP JSON-RPC artifacts from a memory snapshot")
    ap.add_argument("snapshot", help="path to memory image")
    ap.add_argument("--keywords", nargs="*", default=[k.decode() if isinstance(k, bytes) else k for k in DEFAULT_KEYWORDS],
                    help="anchor keywords (default: jsonrpc tools/list tools/call)")
    ap.add_argument("--window", type=int, default=16384, help="bytes to search around anchor (default 16KB)")
    ap.add_argument("--emit-raw", action="store_true", help="include raw JSON text in output")
    ap.add_argument("--tools-only", action="store_true",
                    help="retain only tools/call requests and their matched responses")
    ap.add_argument("--mcp-only", action="store_true",
                    help="retain only records where mcp semantic detection is true")
    ap.add_argument("--regions-file", help="JSON/JSONL/TSV file with offset ranges: start,end[,tag]")
    ap.add_argument("--client", choices=["codex", "cursor", "copilot", "auto", "other"], default=None,
                    help="tag applied to regions lacking tag (for provenance separation)")
    ap.add_argument("--ps-file", help="process list file (text/JSON/JSONL) to verify client presence")
    ap.add_argument("--vma-file", help="VMA mapping file with pid,start,end[,tag] to bound regions per PID")
    ap.add_argument("--vol3", help="Path to vol.py for running linux.pslist automatically (uses python3)")
    ap.add_argument("--temp-dir", default=DEFAULT_TEMP_DIR,
                    help="temp folder for auxiliary outputs (created in current directory)")
    ap.add_argument("--quiet", action="store_true", help="suppress progress logs")
    args = ap.parse_args()
    os.makedirs(args.temp_dir, exist_ok=True)
    process_file(
        args.snapshot,
        args.keywords,
        args.window,
        args.emit_raw,
        args.tools_only,
        args.mcp_only,
        args.regions_file,
        args.client if args.client != "auto" else None,
        args.ps_file,
        args.vma_file,
        args.vol3,
        args.temp_dir,
        args.quiet,
    )


if __name__ == "__main__":
    main()
