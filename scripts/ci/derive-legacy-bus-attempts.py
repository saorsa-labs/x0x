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
    require(all(r["schema"] == 1 and r["selector"] == SELECTOR for r in records), "WRONG_SELECTOR")
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
            for sample in (a, b):
                require(any(p["topic"] == BUS and p["role"] == "eager" and p["eager_eligible"] is True and
                            p["peer_id"] != record["generator_peer_hex8"] for p in sample["stages"]["peer_scores"]), "NONORIGIN_EAGER_OPPORTUNITY_ABSENT")
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
