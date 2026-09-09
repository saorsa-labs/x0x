#!/usr/bin/env python3
"""Derive #501 controlled-load attempt facts from retained per-test raw output.

This is an arithmetic/provenance companion, not a runtime launcher or CI receipt
replacement. Completeness of the literal topic universe requires exact-source
review. Source/lock/binary, isolated selection, child exit and reaping remain
mandatory separate execution-custody checks. Raw identities are never emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

PREFIX = b"ISSUE501_MEASUREMENT "
SELECTOR = "legacy_bus_interop_tests::paired_controlled_load_bus_eager_attempts_default_vs_optout"
KINDS = ("eager", "ihave", "iwant", "anti_entropy")
BUS = "a746d680e31732d1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
PUBSUB_SHA = "f75f756d26e5011e17d15aa5cfaad17b5d56b8be37ab1003f9fd2592181ee09d"


class Inconclusive(ValueError):
    """Missing/invalid evidence: never converts to a passing zero."""


def require(condition, code):
    if not condition:
        raise Inconclusive(code)


def integer(value):
    require(type(value) is int and 0 <= value < 2**64, "INVALID_COUNTER")
    return value


LABELS = ("G5", "D5", "O5", "W5")
EXPECTED = {"G5": ["D5", "O5"], "D5": ["G5", "W5"], "O5": ["G5", "W5"], "W5": ["D5", "O5"]}
EDGES = ("G5|W5", "W5|G5", "D5|O5", "O5|D5")
TTL_NS, MARGIN_NS = 120_000_000_000, 5_000_000_000
STATIC = ("expected_allowed", "forbidden_pairs", "peer_ids", "intervening_allowed_edge_state", "configuration", "operations")


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), "TOPOLOGY_KEYS")


def interval(value):
    begin, end = integer(value["begin_ns"]), integer(value["end_ns"])
    require(begin <= end, "TOPOLOGY_INTERVAL")
    return begin, end


def validate_topology(record):
    require(type(record["schema"]) is int and record["schema"] == 2, "SCHEMA2_REQUIRED")
    t = record["topology"]
    keys(t, (*STATIC, "observations", "suppression"))
    require(t["expected_allowed"] == EXPECTED and t["forbidden_pairs"] == [["G5", "W5"], ["D5", "O5"]], "LITERAL_DIAMOND")
    require(t["intervening_allowed_edge_state"] == "unknown" and t["configuration"] == "two reverse test Admin installations and two public forward disconnects; gossip admission only", "TOPOLOGY_SCOPE")
    keys(t["peer_ids"], LABELS)
    require(len(record["identities"]) == 4, "FOUR_PEER_TOPOLOGY")
    ids = [t["peer_ids"][label] for label in LABELS]
    require(all(type(v) is str and HEX64.fullmatch(v) for v in ids) and len(set(ids)) == 4, "FULL_PEER_MAPPING")
    require(ids == [i["machine"] for i in record["identities"]], "FULL_PEER_MAPPING")
    cuts = [record["samples"][arm] for arm in ("D5", "O5")]
    for cut in cuts:
        require(interval(cut["t0"])[1] < interval(cut["t1"])[0], "NONMONOTONIC_CUT")
    first = min(interval(c["t0"])[0] for c in cuts)
    last = max(interval(c["t1"])[1] for c in cuts)
    keys(t["observations"], ("pre_cut", "t1"))
    for phase in ("pre_cut", "t1"):
        observed = t["observations"][phase]
        keys(observed, LABELS)
        for label in LABELS:
            row = observed[label]
            keys(row, ("begin_ns", "end_ns", "admitted"))
            begin, end = interval(row)
            require(end <= first if phase == "pre_cut" else begin >= last, "ADJACENCY_BRACKET")
            actual = row["admitted"]
            require(type(actual) is list and all(type(v) is str for v in actual), "ADMITTED_SET")
            require(len(actual) == len(set(actual)) and set(actual) == {t["peer_ids"][v] for v in EXPECTED[label]}, "ADMITTED_SET")
    keys(t["suppression"], EDGES)
    for edge in EDGES:
        row = t["suppression"][edge]
        keys(row, ("initial_set_at_ns", "pre_check", "final_check", "set_at_stable", "ttl_ns", "margin_ns"))
        original = integer(row["initial_set_at_ns"])
        require(integer(row["ttl_ns"]) == TTL_NS and integer(row["margin_ns"]) == MARGIN_NS, "TTL_MARGIN_CONTRACT")
        require(row["set_at_stable"] is True, "SET_AT_CHANGED")
        for phase in ("pre_check", "final_check"):
            check = row[phase]
            keys(check, ("begin_ns", "end_ns", "set_at_ns", "check_ns", "age_ns", "live", "verdict"))
            begin, end = interval(check)
            at, now, age = (integer(check[k]) for k in ("set_at_ns", "check_ns", "age_ns"))
            require(check["live"] is True and check["verdict"] == "Suppressed", "SUPPRESSION_NOT_LIVE")
            require(at == original <= begin <= now <= end and now - at == age, "SUPPRESSION_CHRONOLOGY")
            require(age + MARGIN_NS < 2**64 and age + MARGIN_NS <= TTL_NS, "SUPPRESSION_MARGIN")
            require(end <= first if phase == "pre_check" else begin >= last, "SUPPRESSION_BRACKET")

    validate_operations(t)


def validate_operations(t):
    keys(t["operations"], ("G5|W5", "D5|O5"))
    for owner, peer in (("G5", "W5"), ("D5", "O5")):
        pair, reverse = owner + "|" + peer, peer + "|" + owner
        ops = t["operations"][pair]
        keys(ops, ("reverse_install", "forward_disconnect"))
        reverse_end = None
        for kind, source, target, edge, result in (("reverse_install", peer, owner, reverse, "Installed"),
                                                  ("forward_disconnect", owner, peer, pair, "Ok")):
            op = ops[kind]
            keys(op, ("owner", "peer", "owner_peer_id", "peer_id", "begin_ns", "end_ns", "set_at_ns", "result"))
            begin, end = interval(op)
            at = integer(op["set_at_ns"])
            require(op["owner"] == source and op["peer"] == target and op["owner_peer_id"] == t["peer_ids"][source]
                    and op["peer_id"] == t["peer_ids"][target] and op["result"] == result, "OPERATION_BINDING_RESULT")
            require(begin <= at <= end and at == integer(t["suppression"][edge]["initial_set_at_ns"])
                    and end <= integer(t["suppression"][edge]["pre_check"]["begin_ns"]), "OPERATION_TIMESTAMP")
            if kind == "reverse_install":
                reverse_end = end
            else:
                require(begin >= reverse_end, "OPERATION_ORDER")


def preserve_topology(records):
    first, final = records[0]["topology"], records[-1]["topology"]
    for record in records[1:]:
        t = record["topology"]
        require(all(t[k] == first[k] for k in STATIC), "TOPOLOGY_IDENTITY_DRIFT")
        require(t["observations"]["pre_cut"] == first["observations"]["pre_cut"], "PRE_TOPOLOGY_REPLACED")
        for edge in EDGES:
            require(all(t["suppression"][edge][k] == first["suppression"][edge][k]
                        for k in ("initial_set_at_ns", "pre_check", "ttl_ns", "margin_ns")), "PRE_SUPPRESSION_REPLACED")
    for record in records[2:]:
        require(record["topology"] == final, "FINAL_TOPOLOGY_REPLACED")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse(raw):
    require(len(raw) <= 16 * 1024 * 1024, "RAW_TOO_LARGE")
    records = []
    for line in raw.splitlines():
        if line.startswith(PREFIX):
            require(len(records) < 8, "EXCESS_RECORDS")
            records.append(json.loads(line[len(PREFIX):], object_pairs_hook=unique_object))
    require(bool(records), "NO_RECORDS")
    require(all(type(r["schema"]) is int and r["schema"] == 2 and r["selector"] == SELECTOR for r in records), "WRONG_SELECTOR")
    require([r["phase"] for r in records] == ["setup", "t0", "t1", "validated", "complete"], "INCOMPLETE_OR_DUPLICATE_PHASES")
    require(records[-1]["outcome"] == "PASS", "NO_COMPLETED_OBSERVATION")
    # Successful completion changes only the phase and outcome; the captured
    # pre-shutdown facts must not be recaptured from torn-down state.
    before, final = records[-2], records[-1]
    require({k: v for k, v in before.items() if k not in ("phase", "outcome")} ==
            {k: v for k, v in final.items() if k not in ("phase", "outcome")}, "POST_SHUTDOWN_RECAPTURE")
    for earlier in records[:-1]:
        for field in ("pid", "identities", "universe", "generator_peer_hex8", "build_lock_sha256", "binary_sha256"):
            require(earlier[field] == final[field], "CAPTURE_IDENTITY_DRIFT")
    for arm in ("D5", "O5"):
        require(records[1]["samples"][arm]["t0"] == final["samples"][arm]["t0"], "T0_REPLACED")
        require(records[2]["samples"][arm] == final["samples"][arm], "T1_REPLACED")
    preserve_topology(records)
    validate_topology(final)
    return final


def rows(sample, allowed):
    result = {}
    for row in sample["egress"]["outbound_by_topic_named"]:
        key = row["topic_id_hex8"]
        require(key in allowed and key not in result, "UNEXPECTED_OR_DUPLICATE_TOPIC")
        result[key] = {kind: {field: integer(row["outbound"][kind][field])
                             for field in ("msgs", "bytes")} for kind in KINDS}
    return result


def derive(record, lock_bytes):
    validate_topology(record)
    require(hashlib.sha256(lock_bytes).hexdigest() == record["build_lock_sha256"], "BUILD_LOCK_MISMATCH")
    require(HEX64.fullmatch(record["binary_sha256"]) is not None, "BINARY_HASH_MISSING")
    packages = [p for p in tomllib.loads(lock_bytes.decode())["package"] if p["name"] == "saorsa-gossip-pubsub"]
    require(len(packages) == 1 and packages[0]["version"] == "0.5.76" and packages[0]["checksum"] == PUBSUB_SHA, "PRODUCER_PIN_MISMATCH")
    require(0 < len(record["universe"]) <= 64, "UNIVERSE_BOUND")
    full, allowed = set(), set()
    for topic in record["universe"]:
        long, short = topic["full_id_hex"], topic["topic_id_hex8"]
        require(HEX64.fullmatch(long) is not None and HEX16.fullmatch(short) is not None, "INVALID_TOPIC_ID")
        require(long not in full and short not in allowed and short == long[:16], "NONINJECTIVE_UNIVERSE")
        full.add(long)
        allowed.add(short)
    require(BUS in allowed, "BUS_NOT_ENUMERATED")
    require(len(record["identities"]) == 4, "FOUR_PEER_TOPOLOGY")
    for field in ("agent", "machine"):
        ids = [i[field] for i in record["identities"]]
        require(len(set(ids)) == 4 and all(HEX64.fullmatch(i) for i in ids), "IDENTITY_ALIAS")
    require(record["generator_peer_hex8"] == record["identities"][0]["machine"][:16], "GENERATOR_PROJECTION")
    require(integer(record["load"]["sent"]) == 200 and record["load"]["payload_bytes"] == 4096 and record["load"]["period_ms"] == 50, "LOAD_SHAPE")
    require(len(record["load"]["fanouts"]) == 200, "LOAD_ACCOUNTING")
    for count in record["load"]["fanouts"]:
        integer(count)
    load_seconds = integer(record["load"]["elapsed_ns"]) / 1e9
    require(load_seconds > 0, "LOAD_CLOCK")
    result = {}
    oracle_failures = []
    for arm in ("D5", "O5"):
        a, b = (record["samples"][arm][cut] for cut in ("t0", "t1"))
        require(integer(a["begin_ns"]) <= integer(a["end_ns"]) < integer(b["begin_ns"]) <= integer(b["end_ns"]), "NONMONOTONIC_CUT")
        elapsed = (b["end_ns"] - a["end_ns"]) / 1e9
        require(a["egress"]["subscribed_topics"] == b["egress"]["subscribed_topics"], "MEMBERSHIP_CHANGED")
        expected_bus = arm == "D5"
        require(any(t["topic_id_hex8"] == BUS for t in a["egress"]["subscribed_topics"]) == expected_bus, "BUS_SUBSCRIPTION_PREMISE")
        for sample in (a, b):
            require(sample["participation"]["mode"] == "leaf" and sample["egress"]["egress_budget"]["byte_policy"] == "observe_only", "POLICY_PREMISE")
            require(integer(sample["egress"]["egress_budget"]["repair"]["tracking_overflow"]) == 0, "REPAIR_OVERFLOW")
        before, after = rows(a, allowed), rows(b, allowed)
        require(set(before) <= set(after), "ROW_DISAPPEARED")
        deltas = {}
        for key, counters in after.items():
            deltas[key] = {}
            for kind in KINDS:
                deltas[key][kind] = {}
                for field in ("msgs", "bytes"):
                    x = before.get(key, {}).get(kind, {}).get(field, 0)
                    y = counters[kind][field]
                    require(y >= x, "COUNTER_DECREASE")
                    deltas[key][kind][field] = y - x
        if arm == "D5":
            require(BUS in after, "POSITIVE_BUS_ROW_ABSENT")
            # Endpoint peer_scores are retained diagnostics, not a send premise.
        delta = deltas.get(BUS, {}).get("eager", {}).get("bytes", 0)
        if (arm == "D5" and delta == 0) or (arm == "O5" and delta != 0):
            oracle_failures.append(arm + "_EAGER_ORACLE")
        relay_delta = integer(b["participation"]["relay_bytes"]) - integer(a["participation"]["relay_bytes"])
        require(relay_delta >= 0, "RELAY_COUNTER_DECREASE")
        if relay_delta != 0:
            oracle_failures.append(arm + "_RELAY_CHANGED")
        result[arm] = {"elapsed_seconds": elapsed, "bus_row_present_t0": BUS in before,
                       "bus_row_present_t1": BUS in after, "bus_eager_attempt_bytes": delta,
                       "bus_eager_attempt_KiB_per_s": delta / elapsed / 1024,
                       "relay_delta": relay_delta, "all_topic_kind_deltas": deltas,
                       "row_count_t0": len(before), "row_count_t1": len(after)}
    return {"derivation": "FAIL" if oracle_failures else "CONSISTENT", "oracle_failures": oracle_failures,
            "arms": result, "load_achieved_per_second": 200 / load_seconds,
            "universe_cardinality": len(full), "build_lock_sha256": record["build_lock_sha256"],
            "binary_sha256": record["binary_sha256"], "witness_observed_without_path_attribution": integer(record["load"]["witness_observed_during_load"]),
            "scope": "send attempts only; raw rolling rates and repair subsets retained in raw input; repair never re-added",
            "execution_acceptance": "UNVERIFIED: bind exact source and this binary/lock to isolated selection, terminal exit and reaping separately",
            "universe_completeness": "exact-source review premise; projection checks alone cannot establish completeness"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True, help="private exact per-test output, unmodified")
    parser.add_argument("--lock", type=Path, required=True, help="actual retained build Cargo.lock")
    args = parser.parse_args()
    raw, lock = args.raw.read_bytes(), args.lock.read_bytes()
    try:
        output = derive(parse(raw), lock)
        code = 1 if output["derivation"] == "FAIL" else 0
    except (Inconclusive, ValueError, KeyError, TypeError, IndexError) as error:
        output = {"derivation": "INCONCLUSIVE", "reason": str(error) if isinstance(error, Inconclusive) else "MALFORMED_INPUT"}
        code = 2
    output["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    output["retained_lock_sha256"] = hashlib.sha256(lock).hexdigest()
    print(json.dumps(output, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
