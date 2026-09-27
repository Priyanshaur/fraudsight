"""Adversarial stress test — out-of-window fraud scenarios that probe whether the
detectors generalize beyond their tuned parameters (not just match their own spec).

Five scenarios, validated as meaningful:
  1. 4-node cycle (detector was hard-capped at 3 nodes)
  2. 90h escalation-to-transfer gap (detector cut off at 72h)
  3. structuring spread over 60h (detector window is 48h; sliding windows may still miss)
  4. hub fan-out spread over 10 days (detector window is 7d)
  5. 2-part sub-threshold pair — EXPECTED MISS, documented correct behavior
     (2-part "structuring" isn't structuring by definition; min_parts=3 stays)

Reports real catch rates. No targets, no fabrication.
"""
from __future__ import annotations
import random
from datetime import timedelta

from .graph_store import new_store
from .data_gen import (BASE_TS, gen_employees, gen_accounts, gen_legit_transfers,
                       gen_normal_access)
from .detectors import run_all_detectors


def _tx(store, tid, src, dst, amount, ts):
    store["transactions"].append({"id": tid, "src": src, "dst": dst,
        "amount": round(float(amount), 2), "ts": ts.isoformat(), "type": "TRANSFER",
        "ground_truth_fraud": True, "redteam": False})


def run_adversarial_stress_test(seed: int = 99) -> dict:
    rng = random.Random(seed)
    store = new_store()
    store["employees"] = gen_employees(rng, n=12)
    store["accounts"] = gen_accounts(rng, n=40, emps=store["employees"])
    gen_legit_transfers(store, rng, n=200)
    gen_normal_access(store, rng)
    accts = [a["id"] for a in store["accounts"]]
    emps = [e["id"] for e in store["employees"]]
    # Scenarios sit 90 days out, past all legit traffic (60d) and normal access (≤50d),
    # so catch rates measure the detectors, not interference from background data.
    T0 = BASE_TS + timedelta(days=90)
    tid = len(store["transactions"]) + 1
    scen = {}  # name -> list of tx ids (in insertion order)

    def nxt():
        nonlocal tid
        t = f"T-{tid:05d}"
        tid += 1
        return t

    # 1) 4-node cycle, 12k legs, 10h apart (30h span)
    ring = rng.sample(accts, 4)
    ids = []
    for j in range(4):
        i = nxt()
        _tx(store, i, ring[j], ring[(j + 1) % 4], 12000.0, T0 + timedelta(hours=j * 10))
        ids.append(i)
    scen["4-node cycle"] = ids

    # 2) 90h escalation gap, 50k transfer
    emp, acc = rng.choice(emps), rng.choice(accts)
    t_esc = T0 + timedelta(days=2)
    store["access_events"].append({"id": "AE-ADV-ESC", "emp": emp, "account": acc,
                                   "ts": t_esc.isoformat(), "kind": "escalation"})
    dst = rng.choice([a for a in accts if a != acc])
    i = nxt()
    _tx(store, i, acc, dst, 50000.0, t_esc + timedelta(hours=90))
    store["access_events"].append({"id": "AE-ADV-TOUCH", "emp": emp, "account": acc,
        "ts": (t_esc + timedelta(hours=89)).isoformat(), "kind": "touch"})
    scen["90h escalation gap"] = [i]

    # 3) structuring: 3 x 8k at 0/25/60h (no 48h window holds 3 parts)
    s3, d3 = rng.sample(accts, 2)
    ids = []
    for j, h in enumerate((0, 25, 60)):
        i = nxt()
        _tx(store, i, s3, d3, 8000.0, T0 + timedelta(days=5, hours=h))
        ids.append(i)
    scen["60h structuring spread"] = ids

    # 4) hub fan-out: 8 distinct dsts over 10 days (no 7d window holds 6)
    hub = rng.sample(accts, 1)[0]
    dsts = rng.sample([a for a in accts if a != hub], 8)
    ids = []
    for j, (d, day) in enumerate(zip(dsts, (0, 1, 2, 4, 6, 8, 9, 10))):
        i = nxt()
        _tx(store, i, hub, d, 9000.0, T0 + timedelta(days=10, hours=day * 24))
        ids.append(i)
    scen["10-day hub fan-out"] = ids

    # 5) 2-part pair — expected miss (correct behavior, min_parts=3 is definitional)
    s5, d5 = rng.sample(accts, 2)
    ids = []
    for j in range(2):
        i = nxt()
        _tx(store, i, s5, d5, 9000.0, T0 + timedelta(days=15, hours=j * 5))
        ids.append(i)
    scen["2-part pair (expected miss)"] = ids

    flagged = set()
    for a in run_all_detectors(store):
        flagged.update(a["tx_ids"])
    out, tot_c, tot_t = {}, 0, 0
    for name, ids in scen.items():
        c = sum(1 for i in ids if i in flagged)
        out[name] = {"total_tx": len(ids), "caught_tx": c,
                     "catch_rate": round(c / len(ids), 4)}
        tot_c += c
        tot_t += len(ids)
    out["_overall"] = {"total_tx": tot_t, "caught_tx": tot_c,
                       "catch_rate": round(tot_c / tot_t, 4)}
    return {"seed": seed, "scenarios": out}
