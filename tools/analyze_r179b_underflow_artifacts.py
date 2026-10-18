#!/usr/bin/env python3
"""R179B v4: accepted underflow census keyed by function-local graph state identity.

Canonical identity is the explicit pair (function_id, state_id) from
`graph_error_states.json`.  A bare state_id is intentionally insufficient:
state hashes are function-local and may repeat across functions.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

SCHEMA = "luraph-deobf.r179b-underflow-artifact-census.v4"
SUFFIX = {".json", ".jsonl", ".log", ".md", ".txt"}
UF = re.compile(r"(?P<op>read|store) below the stack VM's frame \(register (?P<reg>-?\d+)\)")
AT = re.compile(r"\(at (?P<mode>-?\d+):(?P<pc>-?\d+)\)")
FAMS = {"underflow": 49, "symbolic_control": 5, "missing_condition": 9, "nil_bxor": 1}

FUNCTION_ID_KEYS = {
    "function_id", "graph_function_id", "backend_function_id",
    "resolved_function_id", "final_function_id", "source_function_id",
}
STATE_ID_KEYS = {
    "state_id", "graph_state_id", "error_state_id", "backend_state_id",
    "resolved_state_id", "final_state_id", "source_state_id",
}


def family(error: str) -> str:
    if UF.search(error):
        return "underflow"
    if "symbolic next pc/mode:" in error:
        return "symbolic_control"
    if "needs a constant that is not decoded yet" in error:
        return "missing_condition"
    if "bit32.bxor failed:" in error:
        return "nil_bxor"
    return "other"


def iter_files(inputs: list[Path]) -> list[Path]:
    out = []
    for p in inputs:
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in SUFFIX)
        else:
            raise ValueError(f"input not found: {p}")
    return sorted(dict.fromkeys(out))


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def walk_lists(value, path="$"):
    if isinstance(value, list):
        yield path, value
        for i, child in enumerate(value):
            yield from walk_lists(child, f"{path}[{i}]")
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from walk_lists(child, f"{path}.{key}")


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def checkpoint(files: list[Path], expected=(78, 64, 0, 594)) -> dict:
    hits = []
    for p in files:
        if p.suffix.lower() != ".json":
            continue
        obj = load_json(p)
        if not isinstance(obj, dict) or not isinstance(obj.get("stats"), dict):
            continue
        stats = obj["stats"]
        got = (stats.get("functions"), stats.get("errors"), stats.get("fallbacks"), obj.get("requests"))
        if got == expected:
            hits.append((p, obj.get("output_sha256")))
    if not hits:
        raise ValueError(f"accepted checkpoint manifest {expected} not found")
    hashes = {h for _, h in hits if h}
    if len(hashes) > 1:
        raise ValueError(f"checkpoint output hash conflict: {sorted(hashes)}")
    return {
        "expected": {"functions": 78, "errors": 64, "fallbacks": 0, "requests": 594},
        "sources": [str(p) for p, _ in hits],
        "output_sha256": next(iter(hashes), None),
    }


def atom(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (str, int)):
        return str(value)
    return None


def graph_identity(record: dict):
    function_id = atom(record.get("function_id"))
    state_id = atom(record.get("state_id"))
    if function_id is None or state_id is None:
        return None
    return (function_id, state_id)


def graph_universe(files: list[Path], count=64) -> dict:
    candidates = []
    graph_files = [p for p in files if p.name == "graph_error_states.json"]
    if not graph_files:
        raise ValueError("graph_error_states.json not found; refusing to invent final-node identity")
    for p in graph_files:
        obj = load_json(p)
        if obj is None:
            continue
        for json_path, records in walk_lists(obj):
            if len(records) != count or not all(isinstance(x, dict) for x in records):
                continue
            identities = [graph_identity(x) for x in records]
            if any(x is None for x in identities):
                continue
            if len(set(identities)) != count:
                continue
            candidates.append((p, json_path, records, tuple(sorted(identities))))
    if not candidates:
        raise ValueError(
            "graph_error_states.json has no 64-record list with 64 unique (function_id, state_id) pairs"
        )
    groups = defaultdict(list)
    for candidate in candidates:
        groups[candidate[3]].append(candidate)
    if len(groups) != 1:
        raise ValueError("conflicting graph_error_states composite identity universes")
    group = next(iter(groups.values()))
    p, json_path, records, identities = group[0]
    return {
        "records": records,
        "ids": set(identities),
        "source": f"{p}:{json_path}",
        "source_files": {str(x[0]) for x in group},
        "unique_state_ids": len({state_id for _, state_id in identities}),
        "unique_function_ids": len({function_id for function_id, _ in identities}),
    }


def explicit_composite_refs(value, valid_ids: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """Collect only function+state pairs that co-occur in the same dict object."""
    found = set()
    if isinstance(value, dict):
        function_values = []
        state_values = []
        for key, child in value.items():
            lowered = str(key).lower()
            if lowered in FUNCTION_ID_KEYS or lowered.endswith("_function_id"):
                item = atom(child)
                if item is not None:
                    function_values.append(item)
            if lowered in STATE_ID_KEYS or lowered.endswith("_state_id"):
                item = atom(child)
                if item is not None:
                    state_values.append(item)
        for function_id in function_values:
            for state_id in state_values:
                ident = (function_id, state_id)
                if ident in valid_ids:
                    found.add(ident)
        for child in value.values():
            found.update(explicit_composite_refs(child, valid_ids))
    elif isinstance(value, list):
        for child in value:
            found.update(explicit_composite_refs(child, valid_ids))
    return found


def record_error(record: dict):
    value = record.get("error")
    return value if isinstance(value, str) and value else None


def error_map(files: list[Path], graph: dict, count=64) -> dict:
    """Map every graph identity to an error using direct or explicit composite provenance."""
    valid = graph["ids"]
    direct = {}
    for record in graph["records"]:
        ident = graph_identity(record)
        error = record_error(record)
        if not error:
            direct = {}
            break
        direct[ident] = {
            "error": error,
            "record": record,
            "source": graph["source"],
            "join": "graph_record.error",
        }
    if len(direct) == count and dict(Counter(family(x["error"]) for x in direct.values())) == FAMS:
        return direct

    candidates = []
    for p in files:
        if str(p) in graph["source_files"] or p.suffix.lower() != ".json":
            continue
        obj = load_json(p)
        if obj is None:
            continue
        for json_path, records in walk_lists(obj):
            if len(records) != count or not all(isinstance(x, dict) for x in records):
                continue
            mapping = {}
            for record in records:
                error = record_error(record)
                refs = explicit_composite_refs(record, valid)
                if not error or len(refs) != 1:
                    mapping = {}
                    break
                ident = next(iter(refs))
                if ident in mapping:
                    mapping = {}
                    break
                mapping[ident] = {
                    "error": error,
                    "record": record,
                    "source": f"{p}:{json_path}",
                    "join": "explicit_function_state_reference",
                }
            if set(mapping) == valid and dict(Counter(family(x["error"]) for x in mapping.values())) == FAMS:
                candidates.append(mapping)
    if not candidates:
        raise ValueError(
            "no provenance-complete 64-record error census maps to graph_error_states "
            "(function_id, state_id); refusing bare-state/order/diagnostic identity synthesis"
        )
    groups = defaultdict(list)
    for mapping in candidates:
        identity = tuple(sorted((fid, sid, item["error"]) for (fid, sid), item in mapping.items()))
        groups[identity].append(mapping)
    if len(groups) != 1:
        raise ValueError("conflicting provenance-complete error censuses for composite graph identities")
    return next(iter(groups.values()))[0]


def parse_underflow(error: str):
    match = UF.search(error)
    if not match:
        return None
    at = AT.search(error)
    return {
        "operation": match.group("op"),
        "register": int(match.group("reg")),
        "mode": int(at.group("mode")) if at else None,
        "pc": int(at.group("pc")) if at else None,
    }


def json_line(line: str):
    starts = sorted(x for x in {0, line.find("{"), line.find("[")} if x >= 0)
    for start in starts:
        try:
            return json.loads(line[start:].strip())
        except json.JSONDecodeError:
            pass
    return None


def aux_record(record: dict, source: Path, valid_ids, line=None):
    refs = explicit_composite_refs(record, valid_ids)
    if len(refs) != 1:
        return None
    ident = next(iter(refs))
    error = str(record.get("error") or record.get("exception") or "")
    kind = record.get("kind")
    if kind in ("below_stack", "below_stack_store"):
        register = record.get("register")
        if not isinstance(register, int) or isinstance(register, bool):
            return None
        parsed = {
            "operation": "read" if kind == "below_stack" else "store",
            "register": register,
            "mode": record.get("mode"),
            "pc": record.get("pc"),
        }
    else:
        parsed = parse_underflow(error)
        if not parsed:
            return None
    jump_regs = record.get("jump_regs") if isinstance(record.get("jump_regs"), list) else []
    facts = str(record.get("facts") or record.get("step_facts") or "")
    return {
        "function_id": ident[0],
        "state_id": ident[1],
        "source": str(source),
        "line": line,
        **parsed,
        "stack_base": record.get("stack_base"),
        "last_op": record.get("last_op") or record.get("op"),
        "proto": record.get("proto"),
        "function": record.get("function"),
        "walk": record.get("walk"),
        "in_jump_regs": parsed["register"] in jump_regs,
        "zero_slot_nil_fact_hint": bool(
            parsed["register"] == 0 and re.search(r"0\s*:\s*\(['\"]c['\"]\s*,\s*None\)", facts)
        ),
    }


def scan_aux(files: list[Path], graph: dict) -> list[dict]:
    out = []
    for p in files:
        if str(p) in graph["source_files"]:
            continue
        if p.suffix.lower() == ".json":
            obj = load_json(p)
            if obj is not None:
                for record in walk_dicts(obj):
                    item = aux_record(record, p, graph["ids"])
                    if item:
                        out.append(item)
                continue
        try:
            for line_no, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                obj = json_line(line)
                if obj is None:
                    continue
                for record in walk_dicts(obj):
                    item = aux_record(record, p, graph["ids"], line_no)
                    if item:
                        out.append(item)
        except OSError:
            pass
    return out


def richness(record: dict) -> int:
    return sum(record.get(k) is not None for k in ("stack_base", "last_op", "proto", "function", "walk"))


def analyze(inputs: list[Path], expect_unique=49) -> dict:
    files = iter_files(inputs)
    receipt = checkpoint(files)
    graph = graph_universe(files)
    mapping = error_map(files, graph)
    graph_by_id = {graph_identity(record): record for record in graph["records"]}

    sites = []
    for ident, item in mapping.items():
        parsed = parse_underflow(item["error"])
        if not parsed:
            continue
        source_record = item["record"]
        graph_record = graph_by_id[ident]
        row = {
            "function_id": ident[0],
            "state_id": ident[1],
            "error": item["error"],
            **parsed,
            "identity_source": graph["source"],
            "error_source": item["source"],
            "provenance_join": item["join"],
        }
        for key in (
            "stack_base", "last_op", "proto", "function", "walk",
            "in_jump_regs", "zero_slot_nil_fact_hint",
        ):
            value = source_record.get(key)
            if value is None:
                value = graph_record.get(key)
            row[key] = value
        sites.append(row)

    if expect_unique is not None and len(sites) != expect_unique:
        raise ValueError(
            f"provenance-resolved accepted-node universe has {len(sites)} underflows, expected {expect_unique}"
        )

    aux = scan_aux(files, graph)
    by_identity = defaultdict(list)
    for record in aux:
        by_identity[(record["function_id"], record["state_id"])].append(record)
    enriched = 0
    for site in sites:
        candidates = by_identity.get((site["function_id"], site["state_id"]), [])
        if not candidates:
            site["enrichment_status"] = "NO_EXPLICIT_COMPOSITE_MATCH"
            continue
        best = max(candidates, key=richness)
        enriched += 1
        site["enrichment_status"] = "MATCHED_EXPLICIT_COMPOSITE_ID"
        site["enrichment_source"] = best["source"]
        site["enrichment_line"] = best["line"]
        for key in (
            "stack_base", "last_op", "proto", "function", "walk",
            "in_jump_regs", "zero_slot_nil_fact_hint",
        ):
            if best.get(key) is not None:
                site[key] = best[key]

    counts = Counter()
    by_register = Counter()
    for site in sites:
        register = site["register"]
        bucket = "ZERO_SLOT" if register == 0 else "NEGATIVE_SLOT" if register < 0 else "UNPARSED"
        site["bucket"] = bucket
        counts[site["operation"]] += 1
        counts[bucket] += 1
        if site.get("in_jump_regs"):
            counts["jump"] += 1
        if site.get("zero_slot_nil_fact_hint"):
            counts["nilhint"] += 1
        if site.get("stack_base") is None:
            counts["nostack"] += 1
        by_register[str(register)] += 1

    return {
        "schema": SCHEMA,
        "checkpoint": receipt,
        "canonical_error_nodes": {
            "count": 64,
            "identity_scheme": ["function_id", "state_id"],
            "identity_source": graph["source"],
            "unique_composite_ids": len(graph["ids"]),
            "unique_state_ids": graph["unique_state_ids"],
            "unique_function_ids": graph["unique_function_ids"],
            "family_counts": FAMS,
            "bare_state_id_identity_allowed": False,
            "diagnostic_tuple_identity_allowed": False,
            "positional_join_allowed": False,
        },
        "summary": {
            "unique_sites": len(sites),
            "reads": counts["read"],
            "stores": counts["store"],
            "zero_slot": counts["ZERO_SLOT"],
            "negative_slot": counts["NEGATIVE_SLOT"],
            "unparsed_slot": counts["UNPARSED"],
            "in_jump_regs": counts["jump"],
            "zero_slot_nil_fact_hint": counts["nilhint"],
            "missing_stack_base": counts["nostack"],
            "enriched_sites": enriched,
            "auxiliary_records_with_explicit_composite_id": len(aux),
            "expected_unique_sites": expect_unique,
        },
        "by_register": dict(by_register.most_common()),
        "sites": sorted(sites, key=lambda x: (x["function_id"], x["state_id"])),
        "proof_status": "FUNCTION_LOCAL_GRAPH_STATE_PROVENANCE_CENSUS",
        "raw_records_can_create_sites": False,
        "no_lift_rerun": True,
        "no_target_execution": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--expect-unique", type=int, default=49)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.inputs, args.expect_unique)
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        summary = result["summary"]
        identity = result["canonical_error_nodes"]
        print(
            f"R179B underflow census: sites={summary['unique_sites']} read={summary['reads']} "
            f"store={summary['stores']} R0={summary['zero_slot']} negative={summary['negative_slot']}"
        )
        print(
            f"graph identity: composite={identity['unique_composite_ids']} "
            f"raw_state_ids={identity['unique_state_ids']} functions={identity['unique_function_ids']}"
        )
        print("proof: FUNCTION_LOCAL_GRAPH_STATE_PROVENANCE_CENSUS")
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
