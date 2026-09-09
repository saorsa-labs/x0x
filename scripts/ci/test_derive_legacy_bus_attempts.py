#!/usr/bin/env python3
"""Constructor-free synthetic controls over the actual #501 derivation module."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("derive501", Path(__file__).with_name("derive-legacy-bus-attempts.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
LOCK = ('[[package]]\nname="saorsa-gossip-pubsub"\nversion="0.5.76"\nchecksum="' + module.PUBSUB_SHA + '"\n').encode()


def fixture():
    def sample(at, eager, subscribed):
        counters = {k: {"msgs": int(eager > 0) if k == "eager" else 0, "bytes": eager if k == "eager" else 0} for k in module.KINDS}
        return {"begin_ns": at, "end_ns": at + 1,
                "egress": {"subscribed_topics": [{"topic_id_hex8": module.BUS}] if subscribed else [],
                           "outbound_by_topic_named": [{"topic_id_hex8": module.BUS, "outbound": counters}] if subscribed else [],
                           "egress_budget": {"byte_policy": "observe_only", "repair": {"tracking_overflow": 0}}},
                "participation": {"mode": "leaf", "relay_bytes": 0},
                "stages": {"peer_scores": [{"topic": module.BUS, "role": "eager", "eager_eligible": True, "peer_id": "44" * 8}]}}
    record = {"schema": 2, "selector": module.SELECTOR, "phase": "complete", "outcome": "PASS", "pid": 10,
            "identities": [{"agent": b * 32, "machine": b * 32} for b in ("11", "22", "33", "44")],
            "generator_peer_hex8": "11" * 8, "binary_sha256": "ab" * 32,
            "build_lock_sha256": hashlib.sha256(LOCK).hexdigest(),
            "universe": [{"name": "synthetic-bus", "full_id_hex": module.BUS + "0" * 48, "topic_id_hex8": module.BUS}],
            "samples": {"D5": {"t0": sample(2_000_000_000, 0, True), "t1": sample(12_000_000_000, 100, True)},
                        "O5": {"t0": sample(2_000_000_000, 0, False), "t1": sample(12_000_000_000, 0, False)}},
            "load": {"sent": 200, "payload_bytes": 4096, "period_ms": 50, "elapsed_ns": 10000000000, "fanouts": [3] * 200, "witness_observed_during_load": 170}}

    ids = {label: record["identities"][i]["machine"] for i, label in enumerate(module.LABELS)}
    def check(at):
        return {"begin_ns": at, "end_ns": at + 2, "set_at_ns": 100,
                "check_ns": at + 1, "age_ns": at + 1 - 100, "live": True, "verdict": "Suppressed"}
    record["topology"] = {"expected_allowed": copy.deepcopy(module.EXPECTED),
        "forbidden_pairs": [["G5", "W5"], ["D5", "O5"]], "peer_ids": ids,
        "intervening_allowed_edge_state": "unknown",
        "configuration": "two reverse test Admin installations and two public forward disconnects; gossip admission only",
        "observations": {phase: {label: {"begin_ns": at, "end_ns": at + 1,
                            "admitted": [ids[v] for v in module.EXPECTED[label]]}
                         for label in module.LABELS}
                         for phase, at in (("pre_cut", 1_000_000_000), ("t1", 13_000_000_000))},
        "suppression": {edge: {"initial_set_at_ns": 100, "pre_check": check(1_000_000_000),
                               "final_check": check(13_000_000_000), "set_at_stable": True,
                               "ttl_ns": module.TTL_NS, "margin_ns": module.MARGIN_NS}
                        for edge in module.EDGES}}
    record["topology"]["operations"] = {}
    for owner, peer in (("G5", "W5"), ("D5", "O5")):
        record["topology"]["operations"][owner + "|" + peer] = {
            kind: {"owner": source, "peer": target, "owner_peer_id": ids[source], "peer_id": ids[target],
                   "begin_ns": begin, "end_ns": end, "set_at_ns": 100, "result": result}
            for kind, source, target, begin, end, result in (
                ("reverse_install", peer, owner, 99, 100, "Installed"),
                ("forward_disconnect", owner, peer, 100, 101, "Ok"))}
    return record


def output(record):
    records = []
    for phase in ("setup", "t0", "t1", "validated", "complete"):
        r = copy.deepcopy(record)
        r["phase"] = phase
        r["outcome"] = "PASS" if phase == "complete" else "OBSERVED"
        records.append(module.PREFIX + json.dumps(r).encode())
    return b"\n".join(records) + b"\n"


class DerivationControls(unittest.TestCase):
    def test_actual_positive_arithmetic_and_absent_zero(self):
        result = module.derive(module.parse(output(fixture())), LOCK)
        self.assertEqual(result["derivation"], "CONSISTENT")
        self.assertEqual(result["arms"]["D5"]["bus_eager_attempt_KiB_per_s"], 100 / 10 / 1024)
        self.assertEqual(result["arms"]["O5"]["bus_eager_attempt_bytes"], 0)

    def test_present_zero_is_distinct(self):
        r = fixture()
        for cut in ("t0", "t1"):
            row = copy.deepcopy(r["samples"]["D5"]["t0"]["egress"]["outbound_by_topic_named"][0])
            r["samples"]["O5"][cut]["egress"]["outbound_by_topic_named"] = [row]
        self.assertTrue(module.derive(r, LOCK)["arms"]["O5"]["bus_row_present_t1"])

    def test_counter_regression_rejected(self):
        r = fixture()
        r["samples"]["D5"]["t0"]["egress"]["outbound_by_topic_named"][0]["outbound"]["eager"]["bytes"] = 101
        with self.assertRaisesRegex(module.Inconclusive, "COUNTER_DECREASE"):
            module.derive(r, LOCK)

    def test_full_key_projection_alias_rejected(self):
        r = fixture()
        r["universe"].append({"name": "alias", "full_id_hex": module.BUS + "1" * 48, "topic_id_hex8": module.BUS})
        with self.assertRaisesRegex(module.Inconclusive, "NONINJECTIVE_UNIVERSE"):
            module.derive(r, LOCK)

    def test_peer_scores_are_diagnostic_and_zero_default_fails(self):
        r = fixture()
        for cut in ("t0", "t1"):
            r["samples"]["D5"][cut]["stages"]["peer_scores"] = []
        self.assertEqual(module.derive(r, LOCK)["derivation"], "CONSISTENT")
        r["samples"]["D5"]["t1"]["egress"]["outbound_by_topic_named"][0]["outbound"]["eager"]["bytes"] = 0
        self.assertEqual(module.derive(r, LOCK)["oracle_failures"], ["D5_EAGER_ORACLE"])

    def test_nonzero_optout_is_failure(self):
        r = fixture()
        r["samples"]["O5"]["t1"]["egress"]["outbound_by_topic_named"] = copy.deepcopy(r["samples"]["D5"]["t1"]["egress"]["outbound_by_topic_named"])
        self.assertEqual(module.derive(r, LOCK)["oracle_failures"], ["O5_EAGER_ORACLE"])

    def test_unexpected_topic_cannot_be_counted_as_zero(self):
        r = fixture()
        r["samples"]["O5"]["t1"]["egress"]["outbound_by_topic_named"] = [{"topic_id_hex8": "fe" * 8}]
        with self.assertRaisesRegex(module.Inconclusive, "UNEXPECTED_OR_DUPLICATE_TOPIC"):
            module.derive(r, LOCK)

    def test_membership_change_and_overflow_refused(self):
        for mutation, code in (("membership", "MEMBERSHIP_CHANGED"), ("overflow", "REPAIR_OVERFLOW")):
            with self.subTest(mutation=mutation):
                r = fixture()
                if mutation == "membership":
                    r["samples"]["D5"]["t1"]["egress"]["subscribed_topics"] = []
                else:
                    r["samples"]["O5"]["t1"]["egress"]["egress_budget"]["repair"]["tracking_overflow"] = 1
                with self.assertRaisesRegex(module.Inconclusive, code):
                    module.derive(r, LOCK)

    def test_lock_mismatch_refused(self):
        with self.assertRaisesRegex(module.Inconclusive, "BUILD_LOCK_MISMATCH"):
            module.derive(fixture(), LOCK + b"\n")

    def test_truncated_duplicate_foreign_output_refused(self):
        good = output(fixture())
        for bad in (b"\n".join(good.splitlines()[:-1]), good + good.splitlines()[-1] + b"\n", good.replace(module.SELECTOR.encode(), b"foreign::test")):
            with self.subTest(raw=hashlib.sha256(bad).hexdigest()), self.assertRaises(module.Inconclusive):
                module.parse(bad)

    def test_shutdown_recapture_refused(self):
        lines = output(fixture()).splitlines()
        final = json.loads(lines[-1][len(module.PREFIX):])
        final["samples"]["O5"]["t1"]["egress"]["subscribed_topics"] = [{"topic_id_hex8": module.BUS}]
        lines[-1] = module.PREFIX + json.dumps(final).encode()
        with self.assertRaisesRegex(module.Inconclusive, "POST_SHUTDOWN_RECAPTURE"):
            module.parse(b"\n".join(lines))

    def test_boolean_counter_refused(self):
        r = fixture()
        r["load"]["sent"] = True
        with self.assertRaisesRegex(module.Inconclusive, "INVALID_COUNTER"):
            module.derive(r, LOCK)

    def test_literal_graph_and_full_peer_sets(self):
        for mutation in ("graph", "mapping", "unknown", "duplicate", "reverse", "extra", "short"):
            r = fixture(); t = r["topology"]
            if mutation == "graph": t["expected_allowed"]["G5"] = ["W5"]
            elif mutation == "mapping": t["peer_ids"]["G5"] = "ff" * 32
            elif mutation == "unknown": t["observations"]["t1"]["D5"]["admitted"].append("ff" * 32)
            elif mutation == "duplicate": t["observations"]["pre_cut"]["G5"]["admitted"] *= 2
            elif mutation == "reverse": del t["suppression"]["W5|G5"]
            elif mutation == "extra": t["suppression"]["G5|D5"] = t["suppression"]["G5|W5"]
            else: t["peer_ids"]["D5"] = "22" * 8
            with self.subTest(mutation=mutation), self.assertRaises(module.Inconclusive): module.derive(r, LOCK)

    def test_suppression_identity_clock_and_literal_margin(self):
        for mutation in ("refresh", "stable", "age", "ttl", "margin", "expired", "bool", "overflow", "notlive", "checkoutside"):
            r = fixture(); row = r["topology"]["suppression"]["O5|D5"]; c = row["final_check"]
            if mutation == "refresh": c["set_at_ns"] += 1
            elif mutation == "stable": row["set_at_stable"] = False
            elif mutation == "age": c["age_ns"] += 1
            elif mutation == "ttl": row["ttl_ns"] += 1
            elif mutation == "margin": row["margin_ns"] = 0
            elif mutation == "expired":
                c.update(begin_ns=116_000_000_100, check_ns=116_000_000_100, end_ns=116_000_000_100, age_ns=116_000_000_000)
            elif mutation == "bool": c["age_ns"] = True
            elif mutation == "overflow": c["age_ns"] = 2**64
            elif mutation == "notlive": c["live"] = False
            else: c["check_ns"] = c["end_ns"] + 1
            with self.subTest(mutation=mutation), self.assertRaises(module.Inconclusive): module.derive(r, LOCK)

    def test_both_cut_brackets_and_interval_order(self):
        for mutation in ("earlyfinal", "latepre", "unionD", "unionO", "reverse", "cutbool"):
            r = fixture()
            if mutation == "earlyfinal": r["topology"]["suppression"]["G5|W5"]["final_check"]["begin_ns"] = 0
            elif mutation == "latepre": r["topology"]["observations"]["pre_cut"]["W5"]["end_ns"] = 3_000_000_000
            elif mutation == "unionD": r["samples"]["D5"]["t1"]["end_ns"] = 14_000_000_000
            elif mutation == "unionO": r["samples"]["O5"]["t0"]["begin_ns"] = 0
            elif mutation == "reverse": r["samples"]["O5"]["t0"]["end_ns"] = 0
            else: r["samples"]["D5"]["t0"]["begin_ns"] = False
            with self.subTest(mutation=mutation), self.assertRaises(module.Inconclusive): module.derive(r, LOCK)

    def test_phase_topology_recapture_and_old_schema_refused(self):
        for index, field in ((1, "pre"), (2, "final"), (3, "identity")):
            lines = output(fixture()).splitlines()
            r = json.loads(lines[index][len(module.PREFIX):])
            if field == "pre": r["topology"]["observations"]["pre_cut"]["G5"]["end_ns"] += 1
            elif field == "final": r["topology"]["suppression"]["D5|O5"]["set_at_stable"] = False
            else: r["topology"]["peer_ids"]["G5"] = "ff" * 32
            lines[index] = module.PREFIX + json.dumps(r).encode()
            with self.subTest(field=field), self.assertRaises(module.Inconclusive): module.parse(b"\n".join(lines))
        r = fixture(); r["schema"] = 1
        with self.assertRaises(module.Inconclusive): module.derive(r, LOCK)
        with self.assertRaises(module.Inconclusive): module.parse(output(r))

    def test_exact_shaping_operations_and_timestamp_binding(self):
        for mutation in ("missing", "extra", "reverseclose", "failed", "binding", "timestamp", "order", "boolean"):
            r = fixture(); ops = r["topology"]["operations"]
            if mutation == "missing": del ops["D5|O5"]
            elif mutation == "extra": ops["W5|G5"] = {}
            elif mutation == "reverseclose": ops["G5|W5"]["reverse_disconnect"] = {}
            elif mutation == "failed": ops["G5|W5"]["forward_disconnect"]["result"] = "Err"
            elif mutation == "binding": ops["D5|O5"]["reverse_install"]["peer_id"] = "ff" * 32
            elif mutation == "timestamp": ops["G5|W5"]["reverse_install"]["set_at_ns"] = 99
            elif mutation == "order": ops["G5|W5"]["forward_disconnect"]["begin_ns"] = 99
            else: ops["G5|W5"]["reverse_install"]["set_at_ns"] = True
            with self.subTest(mutation=mutation), self.assertRaises(module.Inconclusive): module.derive(r, LOCK)

    def test_operation_capture_cannot_be_replaced(self):
        lines = output(fixture()).splitlines()
        r = json.loads(lines[1][len(module.PREFIX):])
        r["topology"]["operations"]["G5|W5"]["forward_disconnect"]["result"] = "Err"
        lines[1] = module.PREFIX + json.dumps(r).encode()
        with self.assertRaisesRegex(module.Inconclusive, "TOPOLOGY_IDENTITY_DRIFT"):
            module.parse(b"\n".join(lines))

    def test_generator_ancillary_preserves_exact_derivation(self):
        plain = fixture()
        expected = module.derive(module.parse(output(plain)), LOCK)
        for diagnostic in (None, {}, {"schema": 1, "role": "G5", "cuts": {},
                "load_returns": [{"ordinal": i, "reported_fanout": 3,
                    "attempted": 2, "succeeded": i % 3} for i in range(200)],
                "load_interpretation": None}):
            with self.subTest(diagnostic_type=type(diagnostic).__name__):
                enriched = copy.deepcopy(plain)
                enriched["generator_diagnostics"] = diagnostic
                self.assertEqual(module.derive(module.parse(output(enriched)), LOCK), expected)
                self.assertNotEqual(hashlib.sha256(output(enriched)).digest(), hashlib.sha256(output(plain)).digest())

    def test_generator_ancillary_cannot_relax_existing_oracles(self):
        for mutation in ("missing", "default_zero", "optout_nonzero"):
            record = fixture()
            if mutation == "missing":
                for cut in ("t0", "t1"):
                    record["samples"]["D5"][cut]["egress"]["outbound_by_topic_named"] = []
            elif mutation == "default_zero":
                record["samples"]["D5"]["t1"]["egress"]["outbound_by_topic_named"][0]["outbound"]["eager"]["bytes"] = 0
            else:
                record["samples"]["O5"]["t1"]["egress"]["outbound_by_topic_named"] = copy.deepcopy(record["samples"]["D5"]["t1"]["egress"]["outbound_by_topic_named"])
            enriched = copy.deepcopy(record)
            enriched["generator_diagnostics"] = {"schema": 1, "role": "G5", "cuts": {},
                "load_returns": [{"ordinal": i, "reported_fanout": 2, "attempted": 2, "succeeded": 2} for i in range(200)],
                "load_interpretation": {"attempted": 400, "send_stage_succeeded": 400,
                    "zero_attempt_calls": 0, "attempted_without_send_stage_success_calls": 0}}
            with self.subTest(mutation=mutation):
                if mutation == "missing":
                    for candidate in (record, enriched):
                        with self.assertRaisesRegex(module.Inconclusive, "POSITIVE_BUS_ROW_ABSENT"):
                            module.derive(module.parse(output(candidate)), LOCK)
                else:
                    expected = module.derive(module.parse(output(record)), LOCK)
                    self.assertEqual(expected["derivation"], "FAIL")
                    self.assertEqual(module.derive(module.parse(output(enriched)), LOCK), expected)

    def test_generator_ancillary_shutdown_recapture_refused(self):
        record = fixture()
        record["generator_diagnostics"] = {"schema": 1, "role": "G5", "cuts": {},
            "load_returns": [], "load_interpretation": None}
        lines = output(record).splitlines()
        final = json.loads(lines[-1][len(module.PREFIX):])
        final["generator_diagnostics"]["load_returns"].append({"ordinal": 0, "reported_fanout": 2, "attempted": 2, "succeeded": 2})
        lines[-1] = module.PREFIX + json.dumps(final).encode()
        with self.assertRaisesRegex(module.Inconclusive, "POST_SHUTDOWN_RECAPTURE"):
            module.parse(b"\n".join(lines))


if __name__ == "__main__":
    unittest.main()
