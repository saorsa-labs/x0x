#!/usr/bin/env python3
"""Fail-closed validator for retained #613 typed-delivery test receipts."""

import argparse
import json
import re
import sys
from pathlib import Path

PREFIX = "ISSUE613_APPLICATION_DELIVERY "
SELECTORS = {
    "legacy_bus_interop_tests::paired_application_delivery_ids_no_disconnect_control": "full_mesh",
    "legacy_bus_interop_tests::paired_application_delivery_ids_directed_cut": "directed_diamond",
}
HEX32 = re.compile(r"[0-9a-f]{32}").fullmatch
HEX64 = re.compile(r"[0-9a-f]{64}").fullmatch
# nextest renders captured test output under CARGO_TERM_COLOR=always and closes the
# final captured line with complete ANSI SGR sequences (e.g. ESC[0m reset wrappers).
LEADING_SGR = re.compile(r"\x1b\[[0-9;]*m").match
TRAILING_SGR = re.compile(r"\x1b\[[0-9;]*m\Z").search
RAW_CONTROL = re.compile(r"[\x00-\x1f]").search
DIAMOND_TTL_NS = 120_000_000_000
DIAMOND_MARGIN_NS = 5_000_000_000


def strip_terminal_wrappers(raw):
    """Strip only complete ANSI SGR sequences at the outer boundary of the receipt payload.

    Anything else — unknown or truncated escapes, raw control characters — survives
    here and is rejected by the caller, so wrapping never masks corrupted content.
    """
    payload = raw
    while (lead := LEADING_SGR(payload)) is not None:
        payload = payload[lead.end():]
    while (trail := TRAILING_SGR(payload)) is not None:
        payload = payload[:trail.start()]
    return payload


def interval(value):
    if not isinstance(value, dict):
        raise ValueError("topology interval missing")
    begin, end = value.get("begin_ns"), value.get("end_ns")
    if not isinstance(begin, int) or not isinstance(end, int) or begin > end:
        raise ValueError("invalid topology interval")


def validate_observations(topology, phases, expected):
    peer_ids = topology.get("peer_ids")
    if not isinstance(peer_ids, dict) or set(peer_ids) != set(expected):
        raise ValueError("topology peer mapping missing")
    if any(not HEX64(str(value)) for value in peer_ids.values()) or len(set(peer_ids.values())) != 4:
        raise ValueError("topology peer hashes invalid")
    observations = topology.get("observations")
    if not isinstance(observations, dict) or set(observations) != set(phases):
        raise ValueError("topology observations incomplete")
    for phase in phases:
        if set(observations[phase]) != set(expected):
            raise ValueError("observation labels incomplete")
        for label, neighbours in expected.items():
            row = observations[phase][label]
            interval(row)
            admitted = row.get("admitted")
            wanted = {peer_ids[peer] for peer in neighbours}
            if not isinstance(admitted, list) or len(admitted) != len(set(admitted)) or set(admitted) != wanted:
                raise ValueError("observed adjacency mismatch")


def validate_directed_chronology(topology, cuts):
    interval(cuts.get("t0")); interval(cuts.get("t1"))
    load_begin = cuts["t0"]["begin_ns"]
    load_end = cuts["t1"]["end_ns"]
    if any(row["end_ns"] > load_begin for row in topology["observations"]["pre_cut"].values()):
        raise ValueError("pre-cut observation overlaps load")
    if any(row["begin_ns"] < load_end for row in topology["observations"]["t1"].values()):
        raise ValueError("final observation precedes load completion")
    suppression = topology["suppression"]
    for edge, (owner, peer) in {"G5|W5":("G5","W5"), "D5|O5":("D5","O5")}.items():
        reverse_edge = f"{peer}|{owner}"
        reverse = topology["operations"][edge]["reverse_install"]
        forward = topology["operations"][edge]["forward_disconnect"]
        if reverse["end_ns"] > forward["begin_ns"]:
            raise ValueError("forward cut precedes reverse installation")
        for operation, suppression_edge in ((reverse, reverse_edge), (forward, edge)):
            set_at = operation.get("set_at_ns")
            if not isinstance(set_at, int) or not operation["begin_ns"] <= set_at <= operation["end_ns"]:
                raise ValueError("operation set-at outside interval")
            if set_at != suppression[suppression_edge].get("initial_set_at_ns"):
                raise ValueError("operation/suppression set-at mismatch")
            if operation["end_ns"] > suppression[suppression_edge]["pre_check"]["begin_ns"]:
                raise ValueError("pre-check precedes completed operation")
    for row in suppression.values():
        initial = row.get("initial_set_at_ns")
        if not isinstance(initial, int) or row.get("ttl_ns") != DIAMOND_TTL_NS or row.get("margin_ns") != DIAMOND_MARGIN_NS:
            raise ValueError("suppression TTL/margin contract changed")
        for phase in ("pre_check", "final_check"):
            check = row[phase]
            set_at, checked, age = check.get("set_at_ns"), check.get("check_ns"), check.get("age_ns")
            if set_at != initial or not all(isinstance(value, int) for value in (checked, age)):
                raise ValueError("suppression check binding missing")
            if set_at > check["begin_ns"] or not check["begin_ns"] <= checked <= check["end_ns"]:
                raise ValueError("suppression check chronology invalid")
            if checked - set_at != age or age + DIAMOND_MARGIN_NS > DIAMOND_TTL_NS:
                raise ValueError("suppression age expired or inconsistent")
            if phase == "pre_check" and check["end_ns"] > load_begin:
                raise ValueError("pre-check does not precede load")
            if phase == "final_check" and check["begin_ns"] < load_end:
                raise ValueError("final check does not follow load")


def validate(receipt):
    selector = receipt.get("selector")
    if receipt.get("schema") != 1 or selector not in SELECTORS:
        raise ValueError("unknown schema or selector")
    if receipt.get("topology") != SELECTORS[selector] or receipt.get("outcome") != "PASS":
        raise ValueError("topology/outcome mismatch")
    topology = receipt.get("topology_evidence")
    if not isinstance(topology, dict):
        raise ValueError("topology evidence missing")
    directed = {"G5":["D5","O5"],"D5":["G5","W5"],"O5":["G5","W5"],"W5":["D5","O5"]}
    full = {label: [peer for peer in directed if peer != label] for label in directed}
    if receipt["topology"] == "directed_diamond":
        if topology.get("expected_allowed") != directed:
            raise ValueError("directed adjacency changed")
        if topology.get("forbidden_pairs") != [["G5", "W5"], ["D5", "O5"]]:
            raise ValueError("directed cuts missing")
        validate_observations(topology, ("pre_cut", "t1"), directed)
        operations = topology.get("operations")
        if not isinstance(operations, dict) or set(operations) != {"G5|W5", "D5|O5"}:
            raise ValueError("directed operations incomplete")
        for edge, (owner, peer) in {"G5|W5":("G5","W5"), "D5|O5":("D5","O5")}.items():
            operation = operations[edge]
            reverse, forward = operation.get("reverse_install"), operation.get("forward_disconnect")
            if reverse.get("owner") != peer or reverse.get("peer") != owner or reverse.get("result") != "Installed":
                raise ValueError("reverse cut operation invalid")
            if forward.get("owner") != owner or forward.get("peer") != peer or forward.get("result") != "Ok":
                raise ValueError("forward cut operation invalid")
            if reverse.get("owner_peer_id") != topology["peer_ids"][peer] or reverse.get("peer_id") != topology["peer_ids"][owner]:
                raise ValueError("reverse cut identity mismatch")
            if forward.get("owner_peer_id") != topology["peer_ids"][owner] or forward.get("peer_id") != topology["peer_ids"][peer]:
                raise ValueError("forward cut identity mismatch")
            interval(reverse); interval(forward)
        suppression = topology.get("suppression")
        expected_edges = {"G5|W5", "W5|G5", "D5|O5", "O5|D5"}
        if not isinstance(suppression, dict) or set(suppression) != expected_edges:
            raise ValueError("suppression evidence incomplete")
        for row in suppression.values():
            if row.get("set_at_stable") is not True:
                raise ValueError("suppression timestamp changed")
            for phase in ("pre_check", "final_check"):
                check = row.get(phase)
                interval(check)
                if check.get("live") is not True or check.get("verdict") != "Suppressed":
                    raise ValueError("suppression check invalid")
        cuts = receipt.get("outer_load_cuts")
        if not isinstance(cuts, dict):
            raise ValueError("load cuts missing")
        validate_directed_chronology(topology, cuts)
    else:
        if topology.get("configuration") != "full admitted mesh; no administrative disconnects":
            raise ValueError("control topology contract changed")
        validate_observations(topology, ("t0", "t1"), full)
    if not HEX64(str(receipt.get("run_nonce_hash", ""))):
        raise ValueError("invalid run hash")
    for field in ("binary_sha256", "build_lock_sha256"):
        if not HEX64(str(receipt.get(field, ""))):
            raise ValueError(f"invalid {field}")
    identities = receipt.get("identity_hashes")
    if not isinstance(identities, dict) or set(identities) != {"G5", "D5", "O5", "W5"}:
        raise ValueError("identity mapping missing")
    if any(not HEX64(str(value)) for value in identities.values()) or len(set(identities.values())) != 4:
        raise ValueError("identity hashes invalid or non-distinct")
    if topology.get("peer_ids") != identities:
        raise ValueError("topology peer mapping is not bound to run identities")
    if receipt.get("pairs") != ["G5>D5", "G5>O5"]:
        raise ValueError("measured pairs changed")
    if any(receipt.get(k) != v for k, v in {
        "attempted": 200, "published": 200, "delivered": 200,
        "duplicates": 0, "unexpected": 0, "receiver_closed": 0,
        "payload_bytes": 4096, "period_ms": 50,
    }.items()):
        raise ValueError("count/load/anomaly contract failed")
    records = receipt.get("records")
    if not isinstance(records, list) or len(records) != 200:
        raise ValueError("record count mismatch")
    ids, sequences, counts = set(), set(), {"G5>D5": 0, "G5>O5": 0}
    for record in records:
        request_id = record.get("request_id")
        if not HEX32(str(request_id)) or request_id in ids:
            raise ValueError("invalid or duplicate request ID")
        ids.add(request_id)
        pair = record.get("pair")
        if pair not in counts:
            raise ValueError("unexpected pair")
        counts[pair] += 1
        sequence = record.get("sequence")
        destination = record.get("destination")
        expected_destination = 1 if pair == "G5>D5" else 2
        if not isinstance(sequence, int) or not 0 <= sequence < 200 or sequence in sequences:
            raise ValueError("invalid or duplicate sequence")
        if destination != expected_destination or destination != (1 if sequence % 2 == 0 else 2):
            raise ValueError("sequence/pair/destination binding failed")
        sequences.add(sequence)
        invoked, ack, delivered = (record.get(k) for k in ("invoked_ns", "ack_ns", "delivered_ns"))
        if not all(isinstance(v, int) and v >= 0 for v in (invoked, ack, delivered)):
            raise ValueError("missing timestamp")
        if ack < invoked or delivered < invoked:
            raise ValueError("event precedes invocation")
        # Delivery before publish acknowledgement is explicitly valid.
        if not isinstance(record.get("fanout"), int) or record["fanout"] <= 0:
            raise ValueError("publication has no fanout")
        if not isinstance(record.get("wire_bytes"), int) or record["wire_bytes"] <= 4096:
            raise ValueError("invalid inner envelope size")
        if not isinstance(record.get("attempted_peer_sends"), int) or record["attempted_peer_sends"] <= 0:
            raise ValueError("missing attempted peer sends")
    if counts != {"G5>D5": 100, "G5>O5": 100}:
        raise ValueError("per-pair equality failed")
    if sequences != set(range(200)):
        raise ValueError("sequence set incomplete")
    witnessed = receipt.get("witness_records")
    witnessed_count = receipt.get("w5_raw_witnessed")
    if (receipt.get("w5_witness_contract") !=
            "positive current-run topology evidence; not loss-free subscriber delivery"):
        raise ValueError("W5 witness scope missing")
    if not isinstance(witnessed, list) or not witnessed or witnessed_count != len(witnessed):
        raise ValueError("positive W5 witness evidence missing")
    witness_ids = set()
    witness_lags = []
    invoked_by_id = {record["request_id"]: record["invoked_ns"] for record in records}
    for witness in witnessed:
        request_id = witness.get("request_id") if isinstance(witness, dict) else None
        observed_ns = witness.get("observed_ns") if isinstance(witness, dict) else None
        if (request_id not in ids or request_id in witness_ids or not isinstance(observed_ns, int)
                or observed_ns < invoked_by_id[request_id]):
            raise ValueError("invalid W5 witness binding")
        witness_ids.add(request_id)
        witness_lags.append(observed_ns - invoked_by_id[request_id])
    missing = receipt.get("witness_missing_ids")
    if not isinstance(missing, list) or set(missing) != ids - witness_ids or len(missing) != len(set(missing)):
        raise ValueError("W5 missing-ID evidence mismatch")
    if receipt.get("witness_max_lag_ns") != max(witness_lags):
        raise ValueError("W5 witness lag evidence mismatch")
    inner = [record["wire_bytes"] for record in records]
    if receipt.get("inner_envelope_bytes_min") != min(inner) or receipt.get("inner_envelope_bytes_max") != max(inner):
        raise ValueError("inner envelope extrema mismatch")
    if min(inner) != max(inner):
        raise ValueError("fixed-size workload produced variable inner envelopes")
    attempted = sum(record["attempted_peer_sends"] for record in records)
    outer_messages = receipt.get("outer_eager_messages")
    extra = receipt.get("recovery_extra_eager_messages")
    if receipt.get("initial_attempted_peer_sends") != attempted or not isinstance(outer_messages, int) or outer_messages < attempted:
        raise ValueError("outer peer-send accounting mismatch")
    if not isinstance(extra, int) or extra != outer_messages - attempted:
        raise ValueError("recovery EAGER arithmetic mismatch")
    outer_bytes = receipt.get("outer_eager_bytes")
    average = receipt.get("outer_eager_average_bytes")
    source_lower_bound = max(inner) + 3309 + 1952
    if receipt.get("outer_eager_source_lower_bound_bytes") != source_lower_bound:
        raise ValueError("outer source-derived lower bound mismatch")
    if not isinstance(outer_bytes, int) or average != outer_bytes // outer_messages or average <= source_lower_bound:
        raise ValueError("outer frame omits required current encoding material")
    return selector


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    found = {}
    for line in args.log.read_text(encoding="utf-8").splitlines():
        if PREFIX not in line:
            continue
        raw = line.split(PREFIX, 1)[1]
        payload = strip_terminal_wrappers(raw)
        if RAW_CONTROL(payload):
            raise ValueError("raw control character corrupts receipt payload")
        receipt = json.loads(payload)
        selector = validate(receipt)
        if selector in found:
            raise ValueError(f"duplicate receipt for {selector}")
        found[selector] = receipt
    if set(found) != set(SELECTORS):
        raise ValueError("both exact selector receipts are required")
    args.receipt.write_text(json.dumps({"schema": 1, "receipts": found}, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"#613 receipt validation failed: {error}", file=sys.stderr)
        sys.exit(1)
