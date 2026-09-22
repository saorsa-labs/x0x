import importlib.util
import pathlib
import json
import subprocess
import tempfile
import unittest

PATH = pathlib.Path(__file__).with_name("validate-613-application-delivery.py")
SPEC = importlib.util.spec_from_file_location("validator613", PATH)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def valid():
    records = []
    for i in range(200):
        records.append({
            "pair": "G5>D5" if i % 2 == 0 else "G5>O5",
            "destination": 1 if i % 2 == 0 else 2, "sequence": i,
            "request_id": f"{i:032x}", "invoked_ns": i * 10,
            "ack_ns": i * 10 + 2, "delivered_ns": i * 10 + 1,
            "fanout": 2, "attempted_peer_sends": 2, "wire_bytes": 5000,
        })
    return {"schema": 1, "selector": next(iter(MOD.SELECTORS)), "topology": "full_mesh",
            "run_nonce_hash": "a" * 64, "binary_sha256": "b" * 64,
            "build_lock_sha256": "c" * 64, "attempted": 200, "published": 200,
            "identity_hashes": {"G5": "1" * 64, "D5": "2" * 64, "O5": "3" * 64, "W5": "4" * 64},
            "delivered": 200, "duplicates": 0, "unexpected": 0, "receiver_closed": 0,
            "payload_bytes": 4096, "period_ms": 50, "w5_raw_witnessed": 200,
            "pairs": ["G5>D5", "G5>O5"], "records": records, "outcome": "PASS"}


def finish(receipt):
    peers = {"G5": "1" * 64, "D5": "2" * 64, "O5": "3" * 64, "W5": "4" * 64}
    full = {label: [value for peer, value in peers.items() if peer != label] for label in peers}
    observations = {phase: {label: {"admitted": admitted, "begin_ns": 1, "end_ns": 2} for label, admitted in full.items()} for phase in ("t0", "t1")}
    receipt["topology_evidence"] = {"configuration": "full admitted mesh; no administrative disconnects", "peer_ids": peers, "observations": observations}
    receipt["inner_envelope_bytes_min"] = 5000
    receipt["inner_envelope_bytes_max"] = 5000
    receipt["initial_attempted_peer_sends"] = 400
    receipt["outer_eager_messages"] = 400
    receipt["recovery_extra_eager_messages"] = 0
    receipt["outer_eager_bytes"] = 5_920_000
    receipt["outer_eager_average_bytes"] = 14_800
    return receipt


class ValidatorTests(unittest.TestCase):
    def test_accepts_delivery_before_ack(self):
        self.assertIn("no_disconnect", MOD.validate(finish(valid())))

    def test_rejects_missing_id(self):
        receipt = finish(valid()); receipt["records"].pop()
        with self.assertRaises(ValueError): MOD.validate(receipt)

    def test_rejects_duplicate_and_cross_pair(self):
        for mutate in (
            lambda r: r["records"][1].update(request_id=r["records"][0]["request_id"]),
            lambda r: r["records"][0].update(pair="W5>D5"),
        ):
            receipt = finish(valid()); mutate(receipt)
            with self.assertRaises(ValueError): MOD.validate(receipt)

    def test_rejects_pre_invocation_delivery_and_capture_loss(self):
        for field, value in (("delivered_ns", -1), ("receiver_closed", 1), ("w5_raw_witnessed", 199)):
            receipt = finish(valid()); receipt["records"][0][field] = value if field.endswith("_ns") else receipt["records"][0].get(field)
            if field in receipt: receipt[field] = value
            with self.assertRaises(ValueError): MOD.validate(receipt)

    def test_cli_requires_both_complete_success_logs(self):
        control = finish(valid())
        cut = json.loads(json.dumps(control))
        cut["selector"] = "legacy_bus_interop_tests::paired_application_delivery_ids_directed_cut"
        cut["topology"] = "directed_diamond"
        peers = cut["topology_evidence"]["peer_ids"]
        directed = {"G5":["D5","O5"],"D5":["G5","W5"],"O5":["G5","W5"],"W5":["D5","O5"]}
        observations = {phase: {label: {"admitted": [peers[p] for p in adjacent], "begin_ns": 1 if phase == "pre_cut" else 21, "end_ns": 2 if phase == "pre_cut" else 22} for label, adjacent in directed.items()} for phase in ("pre_cut", "t1")}
        def operation(owner, peer):
            return {"reverse_install":{"owner":peer,"peer":owner,"owner_peer_id":peers[peer],"peer_id":peers[owner],"result":"Installed","begin_ns":1,"end_ns":3,"set_at_ns":2}, "forward_disconnect":{"owner":owner,"peer":peer,"owner_peer_id":peers[owner],"peer_id":peers[peer],"result":"Ok","begin_ns":4,"end_ns":6,"set_at_ns":5}}
        def suppression(initial):
            return {"set_at_stable":True,"initial_set_at_ns":initial,"ttl_ns":120_000_000_000,"margin_ns":5_000_000_000,"pre_check":{"live":True,"verdict":"Suppressed","begin_ns":7,"end_ns":8,"set_at_ns":initial,"check_ns":7,"age_ns":7-initial},"final_check":{"live":True,"verdict":"Suppressed","begin_ns":30,"end_ns":32,"set_at_ns":initial,"check_ns":31,"age_ns":31-initial}}
        cut["topology_evidence"] = {"peer_ids":peers,"expected_allowed":directed,"forbidden_pairs":[["G5","W5"],["D5","O5"]],"observations":observations,"operations":{"G5|W5":operation("G5","W5"),"D5|O5":operation("D5","O5")},"suppression":{"G5|W5":suppression(5),"W5|G5":suppression(2),"D5|O5":suppression(5),"O5|D5":suppression(2)}}
        cut["outer_load_cuts"] = {"t0":{"begin_ns":10,"end_ns":11},"t1":{"begin_ns":19,"end_ns":20}}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); log = root / "test.log"; out = root / "receipt.json"
            log.write_text("\n".join(MOD.PREFIX + json.dumps(item) for item in (control, cut)))
            subprocess.run(["python3", str(PATH), str(log), str(out)], check=True)
            self.assertEqual(set(json.loads(out.read_text())["receipts"]), set(MOD.SELECTORS))
            log.write_text(MOD.PREFIX + json.dumps(control))
            self.assertNotEqual(subprocess.run(["python3", str(PATH), str(log), str(out)]).returncode, 0)

    def test_accepts_recovery_extra_and_rejects_bad_arithmetic(self):
        receipt = finish(valid())
        receipt["outer_eager_messages"] = 403
        receipt["outer_eager_bytes"] = 5_964_340
        receipt["outer_eager_average_bytes"] = receipt["outer_eager_bytes"] // 403
        receipt["recovery_extra_eager_messages"] = 3
        MOD.validate(receipt)
        receipt["recovery_extra_eager_messages"] = 2
        with self.assertRaises(ValueError): MOD.validate(receipt)
        receipt = finish(valid()); receipt["outer_eager_messages"] = 399
        with self.assertRaises(ValueError): MOD.validate(receipt)

    def test_rejects_directed_chronology_mutations(self):
        control = finish(valid())
        cut = json.loads(json.dumps(control))
        cut["selector"] = "legacy_bus_interop_tests::paired_application_delivery_ids_directed_cut"
        cut["topology"] = "directed_diamond"
        peers = cut["topology_evidence"]["peer_ids"]
        directed = {"G5":["D5","O5"],"D5":["G5","W5"],"O5":["G5","W5"],"W5":["D5","O5"]}
        observations = {phase: {label: {"admitted": [peers[p] for p in adjacent], "begin_ns": 1 if phase == "pre_cut" else 21, "end_ns": 2 if phase == "pre_cut" else 22} for label, adjacent in directed.items()} for phase in ("pre_cut", "t1")}
        def operation(owner, peer):
            return {"reverse_install":{"owner":peer,"peer":owner,"owner_peer_id":peers[peer],"peer_id":peers[owner],"result":"Installed","begin_ns":1,"end_ns":3,"set_at_ns":2},"forward_disconnect":{"owner":owner,"peer":peer,"owner_peer_id":peers[owner],"peer_id":peers[peer],"result":"Ok","begin_ns":4,"end_ns":6,"set_at_ns":5}}
        def suppression(initial):
            return {"set_at_stable":True,"initial_set_at_ns":initial,"ttl_ns":120_000_000_000,"margin_ns":5_000_000_000,"pre_check":{"live":True,"verdict":"Suppressed","begin_ns":7,"end_ns":8,"set_at_ns":initial,"check_ns":7,"age_ns":7-initial},"final_check":{"live":True,"verdict":"Suppressed","begin_ns":30,"end_ns":32,"set_at_ns":initial,"check_ns":31,"age_ns":31-initial}}
        cut["topology_evidence"] = {"peer_ids":peers,"expected_allowed":directed,"forbidden_pairs":[["G5","W5"],["D5","O5"]],"observations":observations,"operations":{"G5|W5":operation("G5","W5"),"D5|O5":operation("D5","O5")},"suppression":{"G5|W5":suppression(5),"W5|G5":suppression(2),"D5|O5":suppression(5),"O5|D5":suppression(2)}}
        cut["outer_load_cuts"] = {"t0":{"begin_ns":10,"end_ns":11},"t1":{"begin_ns":19,"end_ns":20}}
        MOD.validate(cut)
        for mutate in (
            lambda value: value["topology_evidence"]["operations"]["G5|W5"]["forward_disconnect"].update(begin_ns=2),
            lambda value: value["topology_evidence"]["suppression"]["G5|W5"].update(initial_set_at_ns=6),
            lambda value: value["topology_evidence"]["suppression"]["G5|W5"]["final_check"].update(age_ns=120_000_000_000),
            lambda value: value["topology_evidence"]["observations"]["pre_cut"]["G5"].update(end_ns=11),
            lambda value: value["topology_evidence"]["observations"]["t1"]["G5"].update(begin_ns=19),
        ):
            broken = json.loads(json.dumps(cut)); mutate(broken)
            with self.assertRaises(ValueError): MOD.validate(broken)


if __name__ == "__main__":
    unittest.main()
