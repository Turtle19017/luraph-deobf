#!/usr/bin/env python3
"""R179B: offline census of stack/frame underflow evidence already on disk.

No devirtualizer import, no lift, and no target execution.  The analyzer scans
existing JSON/JSONL/log/report artifacts for FRAMEFAIL-style records and the
fallback textual underflow error.  Results are fail-closed: incomplete records
stay explicit and an optional expected-site count can be enforced.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "luraph-deobf.r179b-underflow-artifact-census.v1"
TEXT_RE = re.compile(
    r"\b(?P<op>read|store) below the stack VM's frame \(register (?P<reg>-?\d+(?:\.\d+)?)\)"
)
ALLOWED_SUFFIXES = {".json", ".jsonl", ".log", ".md", ".txt"}
UNDERFLOW_KINDS = {"below_stack", "below_stack_store"}


def _number(v: Any):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v) if float(v).is_integer() else float(v)
    if isinstance(v, str):
        try:
            f = float(v)
            return int(f) if f.is_integer() else f
        except ValueError:
            return None
    return None


def _record_from_dict(obj: dict, source: Path, line: int | None):
    kind = obj.get("kind")
    err = str(obj.get("error") or obj.get("exception") or "")
    if kind not in UNDERFLOW_KINDS:
        m = TEXT_RE.search(err)
        if not m:
            return None
        kind = "below_stack" if m.group("op") == "read" else "below_stack_store"
        reg = _number(m.group("reg"))
    else:
        reg = _number(obj.get("register"))
    stack_base = _number(obj.get("stack_base"))
    jump_regs = obj.get("jump_regs") if isinstance(obj.get("jump_regs"), list) else []
    in_jump = reg in [_number(x) for x in jump_regs] if reg is not None else False
    facts = str(obj.get("facts") or obj.get("step_facts") or "")
    zero_nil_hint = bool(reg == 0 and re.search(
        r"(?:^|[,{ ])0\s*:\s*\(['\"]c['\"]\s*,\s*None\)", facts))
    return {
        "source": str(source),
        "line": line,
        "kind": kind,
        "operation": "read" if kind == "below_stack" else "store",
        "register": reg,
        "stack_base": stack_base,
        "delta_from_floor": None if reg is None else reg - 1,
        "bucket": "ZERO_SLOT" if reg == 0 else "NEGATIVE_SLOT" if reg is not None and reg < 0 else "UNPARSED",
        "proto": obj.get("proto"),
        "proto_tid": obj.get("proto_tid"),
        "function": obj.get("function"),
        "walk": obj.get("walk"),
        "state_key": obj.get("state_key") or obj.get("state"),
        "mode": obj.get("mode"),
        "pc": obj.get("pc"),
        "last_op": obj.get("last_op") or obj.get("op"),
        "in_jump_regs": in_jump,
        "zero_slot_nil_fact_hint": zero_nil_hint,
        "raw_key_type": obj.get("raw_key_type") or obj.get("key_type"),
        "raw_key": obj.get("raw_key") or obj.get("key_fmt"),
    }


def _walk_json(value: Any, source: Path, line: int | None = None) -> Iterable[dict]:
    if isinstance(value, dict):
        rec = _record_from_dict(value, source, line)
        if rec is not None:
            yield rec
        for child in value.values():
            yield from _walk_json(child, source, line)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child, source, line)


def _json_from_line(text: str):
    text = text.strip()
    if not text:
        return None
    candidates = [text]
    brace = text.find("{")
    bracket = text.find("[")
    # Prefixes such as [FRAMEFAIL] begin with '[' but the JSON payload starts
    # at the later '{'. Try every plausible JSON start instead of choosing the
    # earliest bracket.
    for start in sorted({x for x in (brace, bracket) if x >= 0}):
        candidates.append(text[start:])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    return None


def scan_file(path: Path) -> list[dict]:
    out = []
    if path.suffix.lower() == ".json":
        try:
            obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            obj = None
        if obj is not None:
            out.extend(_walk_json(obj, path))
            return out
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                obj = _json_from_line(line)
                if obj is not None:
                    out.extend(_walk_json(obj, path, line_no))
                    continue
                m = TEXT_RE.search(line)
                if m:
                    out.append({
                        "source": str(path), "line": line_no,
                        "kind": "below_stack" if m.group("op") == "read" else "below_stack_store",
                        "operation": m.group("op"), "register": _number(m.group("reg")),
                        "stack_base": None,
                        "delta_from_floor": _number(m.group("reg")) - 1,
                        "bucket": "ZERO_SLOT" if _number(m.group("reg")) == 0 else "NEGATIVE_SLOT",
                        "proto": None, "proto_tid": None, "function": None, "walk": None,
                        "state_key": None, "mode": None, "pc": None, "last_op": None,
                        "in_jump_regs": False, "zero_slot_nil_fact_hint": False,
                        "raw_key_type": None, "raw_key": None,
                    })
    except OSError:
        pass
    return out


def iter_files(inputs: list[Path]) -> list[Path]:
    files = []
    for p in inputs:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in ALLOWED_SUFFIXES)
        else:
            raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(files))


def site_key(r: dict):
    # Prefer explicit attribution coordinates; fall back to diagnostic site.
    primary = (r.get("function"), r.get("walk"), r.get("state_key"))
    if any(x is not None for x in primary):
        return primary + (r.get("kind"), r.get("register"))
    diagnostic = (r.get("proto"), r.get("mode"), r.get("pc"), r.get("last_op"),
                  r.get("kind"), r.get("register"), r.get("stack_base"))
    if any(x is not None for x in diagnostic[:-3]):
        return diagnostic
    return (r.get("source"), r.get("line"), r.get("kind"), r.get("register"))


def analyze(inputs: list[Path], expect_unique: int | None = None):
    files = iter_files(inputs)
    raw = [r for p in files for r in scan_file(p)]
    by_site = {}
    duplicate_records = 0
    for rec in raw:
        key = repr(site_key(rec))
        if key in by_site:
            duplicate_records += 1
            # Prefer the richer copy if the same site appears in log + report.
            score = lambda x: sum(x.get(k) is not None for k in (
                "stack_base", "proto", "state_key", "mode", "pc", "last_op"))
            if score(rec) > score(by_site[key]):
                by_site[key] = rec
        else:
            by_site[key] = rec
    sites = list(by_site.values())
    counts = Counter()
    for r in sites:
        counts[r["operation"]] += 1
        counts[r["bucket"]] += 1
        if r["in_jump_regs"]: counts["in_jump_regs"] += 1
        if r["zero_slot_nil_fact_hint"]: counts["zero_slot_nil_fact_hint"] += 1
        if r["stack_base"] is None: counts["missing_stack_base"] += 1
    by_register = Counter(str(r["register"]) for r in sites)
    by_last_op = Counter(str(r["last_op"]) for r in sites if r["last_op"] is not None)
    by_proto = Counter(str(r["proto"]) for r in sites if r["proto"] is not None)
    out = {
        "schema": SCHEMA,
        "inputs": [str(p) for p in inputs],
        "files_scanned": [str(p) for p in files],
        "summary": {
            "raw_records": len(raw),
            "unique_sites": len(sites),
            "duplicate_records": duplicate_records,
            "reads": counts["read"],
            "stores": counts["store"],
            "zero_slot": counts["ZERO_SLOT"],
            "negative_slot": counts["NEGATIVE_SLOT"],
            "unparsed_slot": counts["UNPARSED"],
            "in_jump_regs": counts["in_jump_regs"],
            "zero_slot_nil_fact_hint": counts["zero_slot_nil_fact_hint"],
            "missing_stack_base": counts["missing_stack_base"],
            "expected_unique_sites": expect_unique,
            "expected_matches": expect_unique is None or len(sites) == expect_unique,
        },
        "by_register": dict(sorted(by_register.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_last_op": dict(by_last_op.most_common()),
        "by_proto": dict(by_proto.most_common()),
        "sites": sorted(sites, key=lambda r: (str(r.get("proto")), str(r.get("mode")), str(r.get("pc")), str(r.get("register")))),
        "proof_status": "EXISTING_ARTIFACT_CENSUS_ONLY",
        "no_lift_rerun": True,
        "no_target_execution": True,
    }
    if expect_unique is not None and len(sites) != expect_unique:
        raise ValueError(f"expected {expect_unique} unique underflow sites, found {len(sites)}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", type=Path)
    ap.add_argument("--expect-unique", type=int)
    ap.add_argument("--json-out", type=Path, required=True)
    a = ap.parse_args()
    try:
        out = analyze(a.inputs, a.expect_unique)
        a.json_out.parent.mkdir(parents=True, exist_ok=True)
        a.json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        s = out["summary"]
        print(f"R179B underflow census: sites={s['unique_sites']} read={s['reads']} store={s['stores']} R0={s['zero_slot']} negative={s['negative_slot']}")
        print(f"jump_regs={s['in_jump_regs']} zero_nil_hint={s['zero_slot_nil_fact_hint']} duplicates={s['duplicate_records']}")
        print("proof: EXISTING_ARTIFACT_CENSUS_ONLY")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
