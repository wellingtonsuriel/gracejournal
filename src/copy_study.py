from __future__ import annotations

import itertools
import json
from pathlib import Path

import pandas as pd

from governance import Bundle, canonical, compile_bundles, cut_size, exact_cover, fixture_key, role_values


ROOT = Path(__file__).resolve().parents[1]


def main():
    public_key = fixture_key().public_key()
    rows = []
    checked = 0
    with (ROOT / "data/derived/optimization_fixtures.jsonl").open() as stream:
        for line in stream:
            fixture = json.loads(line)
            action = fixture["action"]
            roles = len(role_values(action))
            original = compile_bundles(action, fixture["certificates"], public_key)
            for copies in (1, 2, 3):
                repeated = [certificate for certificate in fixture["certificates"] for _ in range(copies)]
                grouped = compile_bundles(action, repeated, public_key)
                aliases = []
                true_domains = []
                for bundle in original:
                    for index in range(copies):
                        aliases.append(Bundle(bundle.domain + "/copy/" + str(index), bundle.mask, bundle.cost))
                        true_domains.append(bundle.domain)
                for tolerance in (1, 2):
                    for method, candidates in (("Copy counting", aliases), ("GRACE-R", grouped)):
                        solution = exact_cover(candidates, roles, tolerance)
                        assert solution is not None
                        selected_domains = sorted({true_domains[i] if method == "Copy counting" else candidates[i].domain
                                                   for i in solution.indices})
                        selected_original = [i for i, b in enumerate(original) if b.domain in selected_domains]
                        actual_cut = cut_size(original, selected_original, roles)
                        survives = True
                        for count in range(min(tolerance, len(selected_original)) + 1):
                            for failed in itertools.combinations(selected_original, count):
                                retained = set(selected_original).difference(failed)
                                complete = cut_size(original, retained, roles) >= 1
                                survives = survives and complete
                                checked += 1
                        assert survives == (actual_cut >= tolerance + 1)
                        if method == "GRACE-R":
                            assert survives
                        if copies == 1:
                            reference = exact_cover(original, roles, tolerance)
                            assert solution.cost == reference.cost
                        rows.append({"case_id": fixture["case_id"], "template": fixture["template"],
                                     "roles": roles, "copies": copies, "tolerance": tolerance,
                                     "method": method, "retained_bytes": solution.cost,
                                     "selected_items": len(solution.indices), "true_domains": len(selected_domains),
                                     "actual_cut": actual_cut, "budget_survives": int(survives),
                                     "selected_domains": json.dumps(selected_domains, separators=(",", ":"))})
    frame = pd.DataFrame(rows)
    frame.to_csv(ROOT / "results/copy_study.csv", index=False)
    summary = frame.groupby(["copies", "tolerance", "method"]).agg(
        workloads=("case_id", "size"), resilient_witnesses=("budget_survives", "sum"),
        mean_actual_cut=("actual_cut", "mean"), mean_retained_bytes=("retained_bytes", "mean"),
        mean_true_domains=("true_domains", "mean")).reset_index()
    summary.to_csv(ROOT / "results/copy_study_summary.csv", index=False)
    (ROOT / "results/copy_study_verification.json").write_text(json.dumps(
        {"rows": len(rows), "exhaustive_selected_domain_removals": checked,
         "one_copy_matches_original_optimum": True,
         "grouped_witnesses_all_satisfy_requested_cut": True}, indent=2) + "\n")
    print(summary.to_string(index=False))
    print("Checked", checked, "selected-domain removal sets.")


if __name__ == "__main__":
    main()
