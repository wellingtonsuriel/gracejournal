from __future__ import annotations

import ast
import copy
import csv
import hashlib
import itertools
import json
import random
import unittest
from pathlib import Path

from governance import (Bundle, ReplayAdapter, authorize, canonical, certificate_for, compile_bundles,
                        digest, exact_cover, fixture_key, greedy_cover, issue_permit, loss_availability,
                        role_values, sign)
from run_analysis import make_action, control_certificates


ROOT = Path(__file__).resolve().parents[1]


def independent_cover(bundles, roles, tolerance):
    best = None
    for chosen in itertools.product([False, True], repeat=len(bundles)):
        coverage = [sum(int(selected and bool(b.mask & (1 << r))) for selected, b in zip(chosen, bundles))
                    for r in range(roles)]
        if all(c >= tolerance + 1 for c in coverage):
            cost = sum(b.cost for selected, b in zip(chosen, bundles) if selected)
            if best is None or cost < best:
                best = cost
    return best


class ExperimentVerification(unittest.TestCase):
    def setUp(self):
        self.key = fixture_key()
        self.public = self.key.public_key()
        self.user = json.loads((ROOT / "data/upstream/data/user_cases.jsonl").read_text().splitlines()[1])
        self.action = make_action(self.user, "verification-task")
        self.certs = control_certificates(self.action, self.key)

    def test_exact_solver_against_independent_exhaustive_search(self):
        rng = random.Random(20261015)
        tested = 0
        for instance in range(200):
            roles = rng.randint(2, 4)
            n = rng.randint(5, 10)
            bundles = [Bundle(str(i), rng.randint(1, (1 << roles) - 1), rng.randint(1, 30)) for i in range(n)]
            tolerance = instance % 3
            expected = independent_cover(bundles, roles, tolerance)
            exact = exact_cover(bundles, roles, tolerance)
            self.assertEqual(expected, None if exact is None else exact.cost)
            greedy = greedy_cover(bundles, roles, tolerance)
            self.assertEqual(exact is None, greedy is None)
            if exact and greedy:
                self.assertLessEqual(exact.cost, greedy.cost)
            tested += 1
        print("Independent exhaustive optimization checks:", tested)

    def test_availability_against_enumerated_failure_states(self):
        rng = random.Random(8102)
        for instance in range(60):
            roles, n = 3, 7
            bundles = [Bundle(str(i), rng.randint(1, 7), 1) for i in range(n)]
            loss = (instance % 10 + 1) / 11
            expected = 0.0
            for failed in itertools.product([False, True], repeat=n):
                retained = [b for b, f in zip(bundles, failed) if not f]
                if all(any(b.mask & (1 << r) for b in retained) for r in range(roles)):
                    k = sum(failed)
                    expected += loss ** k * (1 - loss) ** (n - k)
            actual = loss_availability(bundles, range(n), roles, loss)
            self.assertAlmostEqual(expected, actual, places=12)

    def test_correlated_copies_count_as_one_domain(self):
        role = list(role_values(self.action))[0]
        copies = [certificate_for(self.action, "same-domain", [role], self.key) for _ in range(4)]
        compiled = compile_bundles(self.action, copies, self.public)
        self.assertEqual(len(compiled), 1)
        self.assertIsNone(exact_cover(compiled, len(role_values(self.action)), 1))

    def test_saved_copy_study_true_domain_cuts(self):
        fixtures = {f["case_id"]: f for f in (json.loads(line) for line in
                    (ROOT / "data/derived/optimization_fixtures.jsonl").read_text().splitlines())}
        with (ROOT / "results/optimization.csv").open() as stream:
            original_cost = {(row["case_id"], int(row["tolerance"])): int(row["cost_bytes"])
                             for row in csv.DictReader(stream) if row["method"] == "Exact"}
        with (ROOT / "results/copy_study.csv").open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 4080)
        for row in rows:
            fixture = fixtures[row["case_id"]]
            selected = set(json.loads(row["selected_domains"]))
            expected_cut = min(len({c["body"]["domain"] for c in fixture["certificates"]
                                    if c["body"]["domain"] in selected and
                                    c["body"]["bindings"].get(role) == digest(value)})
                               for role, value in role_values(fixture["action"]).items())
            self.assertEqual(int(row["actual_cut"]), expected_cut)
            self.assertEqual(int(row["true_domains"]), len(selected))
            self.assertEqual(int(row["budget_survives"]), int(expected_cut > int(row["tolerance"])))
            if row["method"] == "GRACE-R":
                self.assertGreater(expected_cut, int(row["tolerance"]))
            if int(row["copies"]) == 1:
                self.assertEqual(int(row["retained_bytes"]),
                                 original_cost[row["case_id"], int(row["tolerance"])])

    def test_control_and_diagnostics(self):
        self.assertTrue(authorize(self.action, self.certs, self.public, tolerance=1)[0])
        source = ROOT / "data/derived/diagnostic_fixtures.jsonl"
        count = 0
        for line in source.read_text().splitlines():
            fixture = json.loads(line)
            allowed = authorize(fixture["action"], fixture["certificates"], self.public, tolerance=1)[0]
            self.assertEqual(allowed, fixture["case"] == "control")
            count += 1
        print("Constructed certificate fixtures checked:", count)

    def test_bound_permit_negative_cases(self):
        ok, bundles, solution = authorize(self.action, self.certs, self.public, tolerance=1)
        self.assertTrue(ok)
        adapter = ReplayAdapter(self.public)
        adapter.register_witness(bundles, solution)
        permit = issue_permit(self.action, bundles, solution, "one-use", self.key)
        mutated = copy.deepcopy(self.action)
        mutated["parameters"][sorted(mutated["parameters"])[0]] = ["different"]
        self.assertFalse(adapter.commit(permit, mutated, 1))
        self.assertFalse(adapter.commit(permit, self.action, 2))
        self.assertFalse(adapter.commit(permit, self.action, 1, current_policy=2))
        self.assertFalse(adapter.commit(permit, self.action, 1, now=2001))
        tampered = copy.deepcopy(permit)
        tampered["body"]["nonce"] = "changed"
        self.assertFalse(adapter.commit(tampered, self.action, 1))
        missing = ReplayAdapter(self.public)
        self.assertFalse(missing.commit(permit, self.action, 1))
        self.assertTrue(adapter.commit(permit, self.action, 1))
        self.assertFalse(adapter.commit(permit, self.action, 1))
        self.assertEqual(len(adapter.effects), 1)

    def test_adapter_survives_one_revoked_domain(self):
        ok, bundles, solution = authorize(self.action, self.certs, self.public, tolerance=1)
        self.assertTrue(ok)
        for ix in solution.indices:
            adapter = ReplayAdapter(self.public)
            adapter.register_witness(bundles, solution)
            adapter.revoked_domains.add(bundles[ix].domain)
            permit = issue_permit(self.action, bundles, solution, "outage-" + str(ix), self.key)
            self.assertTrue(adapter.commit(permit, self.action, 1))
        role_domains = [b.domain for b in bundles if b.mask & 1]
        adapter = ReplayAdapter(self.public)
        adapter.register_witness(bundles, solution)
        adapter.revoked_domains.update(role_domains)
        permit = issue_permit(self.action, bundles, solution, "critical-cut", self.key)
        self.assertFalse(adapter.commit(permit, self.action, 1))

    def test_certificate_expiry_at_commit(self):
        expiring = []
        for cert in self.certs:
            body = copy.deepcopy(cert["body"])
            body["expires"] = 1001
            expiring.append(sign(body, self.key))
        ok, bundles, solution = authorize(self.action, expiring, self.public, tolerance=1, now=1000)
        self.assertTrue(ok)
        adapter = ReplayAdapter(self.public)
        adapter.register_witness(bundles, solution)
        permit = issue_permit(self.action, bundles, solution, "expiry-check", self.key)
        self.assertFalse(adapter.commit(permit, self.action, 1, now=1002))

    def test_committed_trace_bindings(self):
        for line in (ROOT / "results/commit_traces.jsonl").read_text().splitlines():
            trace = json.loads(line)
            self.assertEqual(digest(trace["witness"]), trace["permit"]["body"]["witness_digest"])
            self.assertEqual(trace["effect_record"]["witness_digest"], trace["permit"]["body"]["witness_digest"])
            self.assertEqual(trace["effect_record"]["action_digest"], trace["permit"]["body"]["action_digest"])

    def test_download_hashes(self):
        manifest = json.loads((ROOT / "data/upstream_manifest.json").read_text())
        for item in manifest["files"]:
            path = ROOT / "data/upstream" / item["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

    def test_public_record_counts(self):
        records = [json.loads(line) for line in (ROOT / "data/derived/public_cases.jsonl").read_text().splitlines()]
        self.assertEqual(len(records), 1054)
        self.assertEqual(len({r["user_tool"] for r in records}), 17)
        self.assertEqual(len({r["attacker_instruction"] for r in records}), 62)
        self.assertEqual(len({t for r in records for t in r["attacker_tools"]}), 63)
        self.assertEqual(sum(r["attacker_tools"][0] == r["user_tool"] for r in records), 1)
        self.assertEqual(sum(r["attacker_tools"][-1] == r["user_tool"] for r in records), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
