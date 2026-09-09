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
    return {"schema": 1, "selector": module.SELECTOR, "phase": "complete", "outcome": "PASS", "pid": 10,
            "identities": [{"agent": b * 32, "machine": b * 32} for b in ("11", "22", "33", "44")],
            "generator_peer_hex8": "11" * 8, "binary_sha256": "ab" * 32,
            "build_lock_sha256": hashlib.sha256(LOCK).hexdigest(),
            "universe": [{"name": "synthetic-bus", "full_id_hex": module.BUS + "0" * 48, "topic_id_hex8": module.BUS}],
            "samples": {"D5": {"t0": sample(1, 0, True), "t1": sample(10000000001, 100, True)},
                        "O5": {"t0": sample(1, 0, False), "t1": sample(10000000001, 0, False)}},
            "load": {"sent": 200, "payload_bytes": 4096, "period_ms": 50, "elapsed_ns": 10000000000, "fanouts": [3] * 200, "witness_observed_during_load": 170}}


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

    def test_missing_opportunity_never_passing_zero(self):
        r = fixture()
        r["samples"]["D5"]["t1"]["stages"]["peer_scores"][0]["peer_id"] = r["generator_peer_hex8"]
        with self.assertRaisesRegex(module.Inconclusive, "OPPORTUNITY_ABSENT"):
            module.derive(r, LOCK)

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


if __name__ == "__main__":
    unittest.main()
