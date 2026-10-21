# GRACE-R: resilient provenance authorization

This archive reproduces the experiments accompanying **Minimum-Byte Resilient Provenance Authorization for MCP–RAG Agents**. It includes public InjecAgent data, constructed certificate fixtures, numerical results and the implementation. The source of every input is explicit.

The experiments measure deterministic authorization and source-domain evidence resilience. They do not measure a language model's attack success, benign task completion, or a deployed MCP service. The local effect adapter records simulated operations; it sends no emails, payments, or external tool calls.

## Public source

- Benchmark paper: Qiusi Zhan, Zhixiang Liang, Zifan Ying and Daniel Kang, “InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents,” Findings of ACL 2024, pp. 10471–10506. DOI: https://doi.org/10.18653/v1/2024.findings-acl.624
- Repository: https://github.com/uiuc-kang-lab/InjecAgent
- Archived commit: `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`
- Retrieval date: 14 October 2026.
- Upstream license: `data/upstream/LICENCE`, retained unchanged.
- Exact download URLs, file sizes and full SHA-256 checksums: `data/upstream_manifest.json`.

The reported public replay uses 510 direct-harm and 544 data-stealing **base-setting** records. The enhanced-setting files are also retained, but are not pooled into the reported results. There are 17 user templates and 62 attacker-instruction templates. The archived attacker-tool lists contain 63 distinct operation names; that count is separate from the instruction-template count.

## Contents

| Path | Contents |
|---|---|
| `src/governance.py` | Signature checking, certificate compilation, exact and greedy witness selection, availability calculation, and the local effect adapter |
| `src/run_analysis.py` | Public operation replay, controls, diagnostic mutations, optimization fixtures, outage checks and timing |
| `src/verify_experiments.py` | Independent exhaustive checks, failure-state enumeration, certificate faults, source hashes and trace binding checks |
| `src/copy_study.py` | Correlated-copy experiment with exact occurrence and domain selection, followed by true-domain removal checks |
| `src/make_figures.py` | Thirteen scientific graphs from the saved numerical outputs |
| `data/upstream/` | Unchanged upstream benchmark files, tool definitions, README and license |
| `data/derived/` | Normalized public cases and constructed signed-certificate fixtures |
| `results/` | Per-case outcomes, witness costs, modeled availability, timing, signed permit traces and summaries |
| `experiment_config.json` | Seed, role-mask construction, outage settings and timing repetitions |
| `requirements.txt` | Exact analysis dependency versions |

The LaTeX source and compiled manuscript are supplied separately. This archive can be uploaded directly to a GitHub repository; it contains no credentials, external-service configuration, manuscript build files or raster figures.

## Reproduce

Use Python 3.12, preferably in a fresh virtual environment. From the archive root:

```bash
python -m pip install -r requirements.txt
python src/run_analysis.py
python src/copy_study.py
python src/verify_experiments.py
python src/make_figures.py
```

The experiment seed is `20261014`. Deterministic fixture values, decisions, witness costs and modeled availability should match the supplied outputs. Timings will vary with the machine and process scheduling. The plotting command creates a `figures/` folder with thirteen 350-dpi PNG graphs; the manuscript's three diagrams are written in TikZ in the separate source package.

The environment used for the supplied run was Python 3.12.14 on a shared Linux x86-64 host reporting an AMD EPYC 9V74 processor. Dependency versions are NumPy 2.3.5, pandas 2.2.3, Matplotlib 3.10.8 and cryptography 50.0.2.

## Experimental units

| Experiment | Units |
|---|---:|
| Public operation replay | 1,054 records, first and terminal stage each |
| Authorized initial-call controls | 17 |
| Constructed violations | 153, nine classes across 17 templates |
| Diagnostic decision rows | 1,360, including controls in eight configurations |
| Generated optimization graphs | 340, with 18 eligible source domains each |
| Exact/greedy optimization outcomes | 2,040 |
| Verified exact-witness removals | 7,399 |
| Independent exhaustive optimization comparisons | 200 |
| Independent availability-enumeration comparisons | 60 |
| Local timing repetitions | 1,020 |
| Solver scaling repetitions | 360 |
| Saved bound-permit commit traces | 340 |
| Copy-study selected witnesses | 4,080 |
| Copy-study selected-domain removal sets | 37,214 |

The public operation allowlist admits one first-stage same-tool request and no terminal attacker requests. This property of the snapshot is reported explicitly. Constructed same-tool mutations provide the additional authority, relation, freshness and nonce contrasts.

Generated graph roles comprise intent, schema and one role per top-level parameter. Nonempty proper role masks are sampled and redrawn until each role has at least three supporting domains. Paths sharing a domain are counted once. All generated evidence records are fixture metadata, rather than certificates supplied by the upstream dataset.

Availability curves are exact calculations under an **assumed independent source-domain loss probability**. They are not measured production reliability or language-model success probabilities. Worst-case outage guarantees use the minimum role-domain cut and make no independence assumption.

## Signature fixture and serialization

The Ed25519 signing key is deterministically derived from a public fixture string so that certificates and permits can be reproduced byte for byte. It is an experimental test key. A production integration must replace it with a protected issuer key and persistent atomic state/nonce storage.

The canonical serializer accepts strings, booleans, integers, arrays and string-keyed objects. It sorts keys, uses compact separators and escapes non-ASCII characters. It rejects floating-point values and is not a general RFC 8785 implementation.

The adapter registers the committed witness by digest, verifies its bound permit, rechecks surviving certificates after trusted domain revocation, requires one surviving certificate per role, checks live policy/state and consumes the nonce under a process lock. It records the committed local effect with action and witness digests and surviving domains.

## Reuse and citation

Preserve `data/upstream/LICENCE` and cite the InjecAgent paper and pinned source when redistributing its data. The generated fixtures remain labeled as constructed inputs. The new implementation is provided under the MIT license in `LICENSE`.

The copy study preserves each certificate's true domain while repeating it one, two or three times. The occurrence-counting comparator is a controlled ungrouped configuration. Its nominal support is evaluated against actual source removals; results/copy_study.csv retains the selected true domains for every witness. GRACE-R selects complete compiled bundles, so repeated certificates increase retained bundle bytes without increasing domain coverage.
