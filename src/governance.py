from __future__ import annotations

import base64
import hashlib
import itertools
import json
import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(obj) -> bytes:
    def check(x):
        if x is None or isinstance(x, (str, bool, int)):
            return
        if isinstance(x, list):
            for y in x:
                check(y)
            return
        if isinstance(x, dict) and all(isinstance(k, str) for k in x):
            for y in x.values():
                check(y)
            return
        raise TypeError("The replay serializer accepts only integer-valued JSON.")
    check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(obj) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def fixture_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"GRACE-R public replay fixture").digest())


def sign(body: dict, key: Ed25519PrivateKey) -> dict:
    return {"body": body, "signature": base64.b64encode(key.sign(canonical(body))).decode()}


def verify(signed: dict, public_key) -> bool:
    try:
        public_key.verify(base64.b64decode(signed["signature"], validate=True), canonical(signed["body"]))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False


@dataclass(frozen=True)
class Bundle:
    domain: str
    mask: int
    cost: int
    certificate: dict | None = None


@dataclass(frozen=True)
class Solution:
    cost: int
    indices: tuple[int, ...]


@lru_cache(maxsize=4096)
def transitions(roles: int, target: int, mask: int) -> tuple[int, ...]:
    base = target + 1
    weights = [base ** r for r in range(roles)]
    out = []
    for state in range(base ** roles):
        nxt = state
        for r in range(roles):
            if mask & (1 << r) and (state // weights[r]) % base < target:
                nxt += weights[r]
        out.append(nxt)
    return tuple(out)


def exact_cover(bundles: list[Bundle], roles: int, tolerance: int) -> Solution | None:
    if len({b.domain for b in bundles}) != len(bundles):
        raise ValueError("Compile correlated paths into one bundle per failure domain first.")
    target = tolerance + 1
    if any(sum(bool(b.mask & (1 << r)) for b in bundles) < target for r in range(roles)):
        return None
    dp = {0: (0, 0)}
    for j, bundle in enumerate(bundles):
        trans = transitions(roles, target, bundle.mask)
        nxt = dict(dp)
        for state, (cost, selected) in dp.items():
            new_state = trans[state]
            candidate = (cost + bundle.cost, selected | (1 << j))
            incumbent = nxt.get(new_state)
            if incumbent is None or candidate < incumbent:
                nxt[new_state] = candidate
        dp = nxt
    terminal = (target + 1) ** roles - 1
    if terminal not in dp:
        return None
    cost, bits = dp[terminal]
    return Solution(cost, tuple(i for i in range(len(bundles)) if bits & (1 << i)))


def greedy_cover(bundles: list[Bundle], roles: int, tolerance: int) -> Solution | None:
    if len({b.domain for b in bundles}) != len(bundles):
        raise ValueError("Non-distinct failure domains.")
    target = tolerance + 1
    counts = [0] * roles
    selected = []
    remaining = set(range(len(bundles)))
    while min(counts) < target:
        ranked = []
        for i in remaining:
            gain = sum(bool(bundles[i].mask & (1 << r)) and counts[r] < target for r in range(roles))
            if gain:
                ranked.append((bundles[i].cost / gain, bundles[i].cost, i))
        if not ranked:
            return None
        i = min(ranked)[2]
        remaining.remove(i)
        selected.append(i)
        for r in range(roles):
            counts[r] += bool(bundles[i].mask & (1 << r))
    return Solution(sum(bundles[i].cost for i in selected), tuple(sorted(selected)))


def counts(bundles: list[Bundle], indices: Iterable[int], roles: int) -> tuple[int, ...]:
    selected = list(indices)
    return tuple(sum(bool(bundles[i].mask & (1 << r)) for i in selected) for r in range(roles))


def cut_size(bundles: list[Bundle], indices: Iterable[int], roles: int) -> int:
    return min(counts(bundles, indices, roles))


def loss_availability(bundles: list[Bundle], indices: Iterable[int], roles: int, loss: float) -> float:
    selected = list(indices)
    probability = 0.0
    for role_subset in range(1 << roles):
        domains = sum(bool(bundles[i].mask & role_subset) for i in selected)
        probability += (-1.0 if role_subset.bit_count() % 2 else 1.0) * loss ** domains
    return min(1.0, max(0.0, probability))


def exhaustive_cover(bundles: list[Bundle], roles: int, tolerance: int) -> Solution | None:
    best = None
    for mask in range(1 << len(bundles)):
        ix = tuple(i for i in range(len(bundles)) if mask & (1 << i))
        if cut_size(bundles, ix, roles) >= tolerance + 1:
            cost = sum(bundles[i].cost for i in ix)
            candidate = Solution(cost, ix)
            if best is None or candidate.cost < best.cost:
                best = candidate
    return best


def role_values(action: dict) -> dict:
    values = {"intent": action["intent"], "schema": action["tool"] + ":" + action["tool_version"]}
    values.update({"field:" + k: v for k, v in sorted(action["parameters"].items())})
    return values


def certificate_for(action: dict, domain: str, role_names: list[str], key, *, kind="authoritative", record=None,
                    task=None, state=None, depth=1, padding=0) -> dict:
    values = role_values(action)
    body = {
        "domain": domain, "task": task or action["task"], "record": record or action["record"],
        "policy_version": action["policy_version"],
        "state_version": action["state_version"] if state is None else state,
        "tool_version": action["tool_version"], "kind": kind, "expires": 2000,
        "bindings": {r: digest(values[r]) for r in role_names},
        "lineage": [{"source": domain + "/" + str(j), "revision": digest([domain, j])} for j in range(depth)],
        "annotation": "x" * padding,
    }
    return sign(body, key)


def compile_bundles(action: dict, certificates: list[dict], public_key, *, scope=True, join=True, fresh=True,
                    now=1000) -> list[Bundle]:
    values = role_values(action)
    roles = list(values)
    grouped = {}
    for cert in certificates:
        if not verify(cert, public_key):
            continue
        b = cert["body"]
        if b["kind"] != "authoritative" or b["expires"] < now:
            continue
        if scope and b["task"] != action["task"]:
            continue
        if join and b["record"] != action["record"]:
            continue
        if fresh and (b["policy_version"] != action["policy_version"] or
                      b["state_version"] != action["state_version"] or b["tool_version"] != action["tool_version"]):
            continue
        mask = sum(1 << i for i, r in enumerate(roles) if b["bindings"].get(r) == digest(values[r]))
        if not mask:
            continue
        grouped.setdefault(b["domain"], []).append((cert, mask))
    out = []
    for domain in sorted(grouped):
        group = grouped[domain]
        mask = 0
        for _, m in group:
            mask |= m
        certificates_in_domain = [c for c, _ in group]
        out.append(Bundle(domain, mask, len(canonical(certificates_in_domain)), {"certificates": certificates_in_domain}))
    return out


def authorize(action: dict, certificates: list[dict], public_key, tolerance=0, *, scope=True, join=True,
              fresh=True, now=1000) -> tuple[bool, list[Bundle], Solution | None]:
    bundles = compile_bundles(action, certificates, public_key, scope=scope, join=join, fresh=fresh, now=now)
    solution = exact_cover(bundles, len(role_values(action)), tolerance)
    return solution is not None, bundles, solution


def lineage_only(action: dict, certificates: list[dict], public_key) -> bool:
    values = role_values(action)
    fields = {r for r in values if r.startswith("field:")}
    covered = set()
    for cert in certificates:
        if verify(cert, public_key) and cert["body"]["kind"] == "authoritative":
            covered.update(r for r, v in cert["body"]["bindings"].items() if r in fields and v == digest(values[r]))
    return covered == fields


class ReplayAdapter:
    def __init__(self, public_key, *, check_nonce=True, check_state=True):
        self.public_key = public_key
        self.check_nonce = check_nonce
        self.check_state = check_state
        self.used = set()
        self.effects = []
        self.witness_registry = {}
        self.lock = threading.Lock()
        self.revoked_domains = set()

    def register_witness(self, bundles: list[Bundle], solution: Solution) -> str:
        witness = [bundles[i].certificate for i in solution.indices]
        witness_digest = digest(witness)
        self.witness_registry[witness_digest] = witness
        return witness_digest

    def commit(self, permit: dict, action: dict, current_state: int, *, current_policy=1, now=1000) -> bool:
        with self.lock:
            return self._commit(permit, action, current_state, current_policy=current_policy, now=now)

    def _commit(self, permit: dict, action: dict, current_state: int, *, current_policy=1, now=1000) -> bool:
        if not verify(permit, self.public_key):
            return False
        b = permit["body"]
        if b["action_digest"] != digest(action) or b["policy_version"] != current_policy or b["expires"] < now:
            return False
        witness = self.witness_registry.get(b["witness_digest"])
        if witness is None or digest(witness) != b["witness_digest"]:
            return False
        certificates = [c for bundle in witness for c in bundle["certificates"]
                        if c["body"]["domain"] not in self.revoked_domains]
        if not authorize(action, certificates, self.public_key, tolerance=0, now=now)[0]:
            return False
        if self.check_nonce and b["nonce"] in self.used:
            return False
        if self.check_state and (b["state_version"] != current_state or current_state != action["state_version"]):
            return False
        self.used.add(b["nonce"])
        self.effects.append({"action_digest": digest(action), "witness_digest": b["witness_digest"],
                             "surviving_domains": sorted({c["body"]["domain"] for c in certificates}),
                             "nonce": b["nonce"], "state_version": current_state, "outcome": "committed"})
        return True


def issue_permit(action: dict, bundles: list[Bundle], solution: Solution, nonce: str, key) -> dict:
    return sign({"action_digest": digest(action), "witness_digest": digest([bundles[i].certificate for i in solution.indices]),
                 "policy_version": action["policy_version"], "state_version": action["state_version"], "nonce": nonce,
                 "expires": 2000}, key)


def verify_loss_tolerance(bundles: list[Bundle], solution: Solution, roles: int, tolerance: int) -> int:
    checked = 0
    for k in range(tolerance + 1):
        for failed in itertools.combinations(solution.indices, k):
            retained = [i for i in solution.indices if i not in failed]
            assert cut_size(bundles, retained, roles) >= 1
            checked += 1
    return checked
