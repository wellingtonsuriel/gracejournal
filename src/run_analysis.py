from __future__ import annotations

import ast
import copy
import itertools
import json
import platform
import random
import re
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from governance import (Bundle, ReplayAdapter, authorize, canonical, certificate_for, compile_bundles, counts,
                        cut_size, digest, exact_cover, fixture_key, greedy_cover, issue_permit,
                        lineage_only, loss_availability, role_values, verify_loss_tolerance)


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "data" / "upstream" / "data"
DERIVED = ROOT / "data" / "derived"
RESULTS = ROOT / "results"
SEED = 20261014


def make_action(user: dict, task: str) -> dict:
    return {"task": task, "record": task + "/record", "intent": user["User Instruction"],
            "tool": user["User Tool"], "parameters": ast.literal_eval(user["Tool Parameters"]),
            "tool_version": "1", "policy_version": 1, "state_version": 1}


def change_value(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "_other"
    if isinstance(value, list):
        return [change_value(value[0])] + value[1:]
    if isinstance(value, dict):
        out = dict(value)
        key = sorted(out)[0]
        out[key] = change_value(out[key])
        return out
    raise TypeError(type(value))


def control_certificates(action, key):
    certs = []
    for r in role_values(action):
        for replica in range(2):
            certs.append(certificate_for(action, r + "/domain/" + str(replica), [r], key))
    return certs


def public_data_study(users, attacks, key):
    rows, normalized = [], []
    for ix, (family, source_index, entry) in enumerate(attacks):
        params = ast.literal_eval(entry["Tool Parameters"])
        task_id = family + "-" + str(source_index).zfill(4)
        normalized.append({"case_id": task_id, "family": family, "attack_type": entry["Attack Type"],
                           "user_tool": entry["User Tool"], "user_instruction": entry["User Instruction"],
                           "parameters": params, "attacker_tools": entry["Attacker Tools"],
                           "attacker_instruction": entry["Attacker Instruction"],
                           "tool_response": entry["Tool Response"], "upstream_index": source_index})
        for stage, operation in [("first", entry["Attacker Tools"][0]), ("terminal", entry["Attacker Tools"][-1])]:
            a = make_action(entry, task_id)
            a["tool"] = operation
            if operation == entry["User Tool"]:
                match = re.search(r"Username:\s*([A-Za-z0-9_]+)", entry["Attacker Instruction"])
                assert match and operation == "GitHubGetUserDetails"
                a["parameters"] = {"username": match.group(1)}
            certificate = certificate_for(a, "untrusted-response", list(role_values(a)), key, kind="external")
            result, _, _ = authorize(a, [certificate], key.public_key(), tolerance=0)
            rows.append({"case_id": task_id, "family": family, "attack_type": entry["Attack Type"],
                         "stage": stage, "requested_tool": operation,
                         "tool_allowlist_admitted": int(operation == entry["User Tool"]),
                         "provenance_admitted": int(result), "instruction_chars": len(entry["Attacker Instruction"]),
                         "response_chars": len(entry["Tool Response"])})
    with (DERIVED / "public_cases.jsonl").open("w") as f:
        for row in normalized:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")
    pd.DataFrame(rows).to_csv(RESULTS / "public_replay.csv", index=False)
    controls = []
    for i, user in enumerate(users):
        a = make_action(user, "control-" + str(i))
        certs = control_certificates(a, key)
        ok, _, _ = authorize(a, certs, key.public_key(), tolerance=1)
        controls.append({"user_tool": a["tool"], "parameters": json.dumps(a["parameters"], sort_keys=True),
                         "admitted": int(ok)})
    pd.DataFrame(controls).to_csv(RESULTS / "public_controls.csv", index=False)
    return rows


def diagnostic_study(users, key):
    public_key = key.public_key()
    out = []
    fixtures = []
    for i, user in enumerate(users):
        original = make_action(user, "diagnostic-" + str(i))
        certs = control_certificates(original, key)
        cases = [("control", copy.deepcopy(original), copy.deepcopy(certs))]
        field = sorted(original["parameters"])[0]
        field_role = "field:" + field
        changed = copy.deepcopy(original)
        changed["parameters"][field] = change_value(changed["parameters"][field])
        other_certs = [c for c in certs if field_role not in c["body"]["bindings"]]
        bad_field = [certificate_for(changed, "external-" + str(j), [field_role], key, kind="external") for j in range(2)]
        cases.append(("untrusted_argument", changed, other_certs + bad_field))
        cross_record = [certificate_for(changed, "foreign-record-" + str(j), [field_role], key,
                                         record="other-record") for j in range(2)]
        cases.append(("record_mixing", copy.deepcopy(changed), other_certs + cross_record))
        cases.append(("missing_role", copy.deepcopy(original), [c for c in certs if "intent" not in c["body"]["bindings"]]))
        wrong_scope = [certificate_for(original, c["body"]["domain"], list(c["body"]["bindings"]), key,
                                        task="different-task") for c in certs]
        cases.append(("wrong_scope", copy.deepcopy(original), wrong_scope))
        old_state = [certificate_for(original, c["body"]["domain"], list(c["body"]["bindings"]), key,
                                     state=0) for c in certs]
        cases.append(("stale_evidence", copy.deepcopy(original), old_state))
        descriptor = copy.deepcopy(original)
        descriptor["tool_version"] = "2"
        cases.append(("descriptor_change", descriptor, copy.deepcopy(certs)))
        relay = [c for c in certs if field_role not in c["body"]["bindings"]]
        relay += [certificate_for(original, "relay-" + str(j), [field_role], key, kind="opaque") for j in range(2)]
        cases.append(("erased_lineage", copy.deepcopy(original), relay))
        for kind, a, certificates in cases:
            flags = {
                "Tool allowlist": a["tool"] == original["tool"],
                "Lineage only": a["tool"] == original["tool"] and lineage_only(a, certificates, public_key),
                "Single cover": authorize(a, certificates, public_key, tolerance=0)[0],
                "GRACE-R": authorize(a, certificates, public_key, tolerance=1)[0],
                "Without scope": authorize(a, certificates, public_key, tolerance=1, scope=False)[0],
                "Without join": authorize(a, certificates, public_key, tolerance=1, join=False)[0],
                "Without freshness": authorize(a, certificates, public_key, tolerance=1, fresh=False)[0],
                "Without nonce": authorize(a, certificates, public_key, tolerance=1)[0],
            }
            for method, allowed in flags.items():
                out.append({"template": i, "tool": original["tool"], "case": kind, "method": method,
                            "admitted": int(allowed), "expected_admission": int(kind == "control")})
            fixtures.append({"template": i, "case": kind, "action": a, "certificates": certificates})
        ok, bundles, solution = authorize(original, certs, public_key, tolerance=1)
        assert ok
        for kind in ["state_change_at_commit", "permit_replay"]:
            for method in ["Tool allowlist", "Lineage only", "Single cover", "GRACE-R", "Without scope",
                           "Without join", "Without freshness", "Without nonce"]:
                if method in ["Tool allowlist", "Lineage only"]:
                    allowed = True
                else:
                    adapter = ReplayAdapter(public_key, check_nonce=method != "Without nonce",
                                            check_state=method != "Without freshness")
                    adapter.register_witness(bundles, solution)
                    permit = issue_permit(original, bundles, solution, str(i) + "/" + kind, key)
                    if kind == "state_change_at_commit":
                        allowed = adapter.commit(permit, original, current_state=2)
                    else:
                        assert adapter.commit(permit, original, current_state=1)
                        allowed = adapter.commit(permit, original, current_state=1)
                out.append({"template": i, "tool": original["tool"], "case": kind, "method": method,
                            "admitted": int(allowed), "expected_admission": 0})
    pd.DataFrame(out).to_csv(RESULTS / "diagnostics.csv", index=False)
    with (DERIVED / "diagnostic_fixtures.jsonl").open("w") as f:
        for fixture in fixtures:
            f.write(json.dumps(fixture, ensure_ascii=True) + "\n")
    return out


def workload(action: dict, rng: random.Random, key, n=18, roles_override=None) -> tuple[list[Bundle], list[dict]]:
    a = copy.deepcopy(action)
    if roles_override is not None:
        a["parameters"] = {"field_" + str(i): "value_" + str(i) for i in range(roles_override - 2)}
    roles = list(role_values(a))
    count = len(roles)
    while True:
        masks = [rng.randrange(1, (1 << count) - 1) for _ in range(n)]
        if all(sum(bool(mask & (1 << r)) for mask in masks) >= 3 for r in range(count)):
            break
    certs = []
    for i, mask in enumerate(masks):
        selected_roles = [r for j, r in enumerate(roles) if mask & (1 << j)]
        certs.append(certificate_for(a, a["task"] + "/domain/" + str(i).zfill(3), selected_roles, key,
                                     depth=rng.randrange(1, 6), padding=rng.randrange(0, 769)))
    bundles = compile_bundles(a, certs, key.public_key())
    assert len(bundles) == n
    return bundles, certs


def optimization_study(users, key):
    rng = random.Random(SEED)
    optimization, availability, outage, fixtures = [], [], [], []
    verified_outages = 0
    graph_count = 0
    timings = []
    commit_traces = []
    for i, user in enumerate(users):
        for replica in range(20):
            action = make_action(user, "graph-" + str(i) + "-" + str(replica))
            bundles, certs = workload(action, rng, key)
            roles = len(role_values(action))
            graph = {"case_id": action["task"], "template": i, "action": action, "certificates": certs}
            fixtures.append(graph)
            graph_count += 1
            all_cost = sum(b.cost for b in bundles)
            solutions = {"All sources": (0, type("AllSolution", (), {"cost": all_cost, "indices": tuple(range(len(bundles)))})())}
            for tolerance in [0, 1, 2]:
                start = time.perf_counter_ns()
                exact = exact_cover(bundles, roles, tolerance)
                elapsed = (time.perf_counter_ns() - start) / 1e6
                greedy = greedy_cover(bundles, roles, tolerance)
                assert exact is not None and greedy is not None
                verified_outages += verify_loss_tolerance(bundles, exact, roles, tolerance)
                solutions["Exact t=" + str(tolerance)] = (tolerance, exact)
                solutions["Greedy t=" + str(tolerance)] = (tolerance, greedy)
                for method, solution in [("Exact", exact), ("Greedy", greedy)]:
                    optimization.append({"case_id": action["task"], "template": i, "tool": action["tool"],
                                         "roles": roles, "domains": len(bundles), "tolerance": tolerance,
                                         "method": method, "cost_bytes": solution.cost, "all_bytes": all_cost,
                                         "fraction_bytes": solution.cost / all_cost,
                                         "selected_domains": len(solution.indices), "cut_size": cut_size(bundles, solution.indices, roles),
                                         "latency_ms": elapsed if method == "Exact" else np.nan})
            for method, (tolerance, solution) in solutions.items():
                for loss in np.linspace(0, 0.5, 11):
                    availability.append({"case_id": action["task"], "template": i, "method": method,
                                         "loss_probability": round(float(loss), 3),
                                         "availability": loss_availability(bundles, solution.indices, roles, float(loss))})
                cut = cut_size(bundles, solution.indices, roles)
                for lost in range(6):
                    outage.append({"case_id": action["task"], "template": i, "method": method,
                                   "lost_domains": lost, "worst_case_available": int(cut > lost)})
            valid, compiled, solved = authorize(action, certs, key.public_key(), tolerance=1)
            assert valid
            for trial in range(3):
                tick = time.perf_counter_ns()
                compiled = compile_bundles(action, certs, key.public_key())
                t1 = time.perf_counter_ns()
                solved = exact_cover(compiled, roles, 1)
                t2 = time.perf_counter_ns()
                permit = issue_permit(action, compiled, solved, action["task"] + "/" + str(trial), key)
                t3 = time.perf_counter_ns()
                adapter = ReplayAdapter(key.public_key())
                adapter.register_witness(compiled, solved)
                assert adapter.commit(permit, action, current_state=1)
                t4 = time.perf_counter_ns()
                if trial == 0:
                    commit_traces.append({"case_id": action["task"], "permit": permit,
                                          "witness": [compiled[j].certificate for j in solved.indices],
                                          "effect_record": adapter.effects[0]})
                timings.append({"case_id": action["task"], "template": i, "roles": roles, "trial": trial,
                                "certificate_verification_ms": (t1 - tick) / 1e6, "optimization_ms": (t2 - t1) / 1e6,
                                "permit_issue_ms": (t3 - t2) / 1e6, "local_commit_ms": (t4 - t3) / 1e6,
                                "total_ms": (t4 - tick) / 1e6})
    pd.DataFrame(optimization).to_csv(RESULTS / "optimization.csv", index=False)
    pd.DataFrame(availability).to_csv(RESULTS / "availability.csv", index=False)
    pd.DataFrame(outage).to_csv(RESULTS / "targeted_outages.csv", index=False)
    pd.DataFrame(timings).to_csv(RESULTS / "runtime.csv", index=False)
    with (DERIVED / "optimization_fixtures.jsonl").open("w") as f:
        for fixture in fixtures:
            f.write(json.dumps(fixture, ensure_ascii=True) + "\n")
    with (RESULTS / "commit_traces.jsonl").open("w") as f:
        for trace in commit_traces:
            f.write(json.dumps(trace, ensure_ascii=True) + "\n")
    return graph_count, verified_outages


def scaling_study(users, key):
    rng = random.Random(SEED + 1)
    action = make_action(users[0], "scaling")
    out = []
    for roles in [3, 4, 5, 6]:
        for n in [16, 32, 64]:
            for tolerance in [0, 1, 2]:
                bundles, _ = workload(action, rng, key, n=n, roles_override=roles)
                exact_cover(bundles, roles, tolerance)
                for trial in range(10):
                    tick = time.perf_counter_ns()
                    solution = exact_cover(bundles, roles, tolerance)
                    out.append({"roles": roles, "domains": n, "tolerance": tolerance, "trial": trial,
                                "latency_ms": (time.perf_counter_ns() - tick) / 1e6,
                                "state_bound": (tolerance + 2) ** roles, "cost_bytes": solution.cost})
    pd.DataFrame(out).to_csv(RESULTS / "scaling.csv", index=False)


def summary(users, attacks, graphs, verified_outages):
    public = pd.read_csv(RESULTS / "public_replay.csv")
    opt = pd.read_csv(RESULTS / "optimization.csv")
    av = pd.read_csv(RESULTS / "availability.csv")
    runtime = pd.read_csv(RESULTS / "runtime.csv")
    greedy = opt.pivot(index=["case_id", "tolerance"], columns="method", values="cost_bytes")
    findings = {
        "seed": SEED, "templates": len(users), "public_cases": len(attacks), "optimization_graphs": graphs,
        "checked_domain_outages": verified_outages,
        "first_tool_allowlist_admitted": int(public[public.stage == "first"].tool_allowlist_admitted.sum()),
        "terminal_tool_allowlist_admitted": int(public[public.stage == "terminal"].tool_allowlist_admitted.sum()),
        "public_provenance_admitted": int(public.provenance_admitted.sum()),
        "categories": dict(Counter(e[2]["Attack Type"] for e in attacks)),
        "attacker_templates": len(set(e[2]["Attacker Instruction"] for e in attacks)),
        "named_attacker_operations": len({t for e in attacks for t in e[2]["Attacker Tools"]}),
        "byte_fractions": opt.groupby(["method", "tolerance"]).fraction_bytes.agg(["mean", "median", "min", "max"]).reset_index().to_dict("records"),
        "greedy_gap": {"mean_relative": float((greedy.Greedy / greedy.Exact - 1).mean()),
                       "maximum_relative": float((greedy.Greedy / greedy.Exact - 1).max()),
                       "strict_suboptimal_count": int((greedy.Greedy > greedy.Exact).sum()), "comparisons": len(greedy)},
        "availability_at_020": av[np.isclose(av.loss_probability, .2)].groupby("method").availability.mean().to_dict(),
        "runtime_median_ms": runtime[["certificate_verification_ms", "optimization_ms", "permit_issue_ms", "local_commit_ms", "total_ms"]].median().to_dict(),
        "runtime_p95_ms": runtime.total_ms.quantile(.95),
        "platform": {"python": sys.version.split()[0], "system": platform.platform(), "machine": platform.machine()},
        "scope": "Static public operation replay; constructed certificate diagnostics and evidence-loss workloads. No language-model inference or live external effects."
    }
    (RESULTS / "summary.json").write_text(json.dumps(findings, indent=2) + "\n")
    print(json.dumps(findings, indent=2), flush=True)


def main():
    DERIVED.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    users = [json.loads(line) for line in (UPSTREAM / "user_cases.jsonl").read_text().splitlines()]
    attacks = []
    for family in ["dh", "ds"]:
        attacks += [(family, i, e) for i, e in enumerate(json.loads((UPSTREAM / ("test_cases_" + family + "_base.json")).read_text()))]
    assert len(users) == 17 and len(attacks) == 1054
    key = fixture_key()
    public_data_study(users, attacks, key)
    diagnostic_study(users, key)
    print("Public replay and constructed diagnostics completed.", flush=True)
    graphs, verified_outages = optimization_study(users, key)
    print("Optimization and evidence-loss analysis completed.", flush=True)
    scaling_study(users, key)
    summary(users, attacks, graphs, verified_outages)


if __name__ == "__main__":
    main()
