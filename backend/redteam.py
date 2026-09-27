"""Live red-team attack injector — same primitives as the dataset generator,
exposed on-demand against the running graph."""
from __future__ import annotations
import random
from datetime import datetime, timedelta

def _next_tx(store):
    return f"T-{len(store['transactions'])+1:05d}"

def inject_circular_transfer(store, n_accounts=3, amount=15000.0):
    rng = random.Random()
    accts = rng.sample([a["id"] for a in store["accounts"]], n_accounts)
    now = datetime.utcnow()
    ids = []
    for j in range(n_accounts):
        tid = _next_tx(store)
        store["transactions"].append({"id": tid, "src": accts[j], "dst": accts[(j+1) % n_accounts],
            "amount": amount, "ts": (now + timedelta(minutes=j*5)).isoformat(),
            "type": "TRANSFER", "ground_truth_fraud": True, "redteam": True})
        ids.append(tid)
    return {"template": "circular_transfer", "accounts": accts, "tx_ids": ids}

def inject_structuring(store, total_amount=48000.0, num_splits=6):
    rng = random.Random()
    src, dst = rng.sample([a["id"] for a in store["accounts"]], 2)
    now = datetime.utcnow(); ids = []
    each = round(total_amount / num_splits, 2)
    for j in range(num_splits):
        tid = _next_tx(store)
        store["transactions"].append({"id": tid, "src": src, "dst": dst, "amount": each,
            "ts": (now + timedelta(hours=j*3)).isoformat(), "type": "TRANSFER",
            "ground_truth_fraud": True, "redteam": True})
        ids.append(tid)
    return {"template": "structuring", "src": src, "dst": dst, "tx_ids": ids}

def inject_privilege_escalation_fraud(store, amount=85000.0):
    rng = random.Random()
    emp = rng.choice(store["employees"])["id"]
    acc = rng.choice(store["accounts"])["id"]
    now = datetime.utcnow()
    store["access_events"].append({"id": f"AE-RT-{len(store['access_events'])}",
        "emp": emp, "account": acc, "ts": now.isoformat(), "kind": "escalation"})
    dst = rng.choice([a["id"] for a in store["accounts"] if a["id"] != acc])
    tid = _next_tx(store)
    store["transactions"].append({"id": tid, "src": acc, "dst": dst, "amount": amount,
        "ts": (now + timedelta(hours=2)).isoformat(), "type": "TRANSFER",
        "ground_truth_fraud": True, "redteam": True})
    return {"template": "privilege_escalation", "emp": emp, "account": acc, "tx_ids": [tid]}

def inject_hub_burst(store, fanout=8, amount=12000.0):
    rng = random.Random()
    hub = rng.choice(store["accounts"])["id"]
    now = datetime.utcnow(); ids = []
    for j in range(fanout):
        dst = rng.choice([a["id"] for a in store["accounts"] if a["id"] != hub])
        tid = _next_tx(store)
        store["transactions"].append({"id": tid, "src": hub, "dst": dst, "amount": amount,
            "ts": (now + timedelta(hours=j)).isoformat(), "type": "TRANSFER",
            "ground_truth_fraud": True, "redteam": True})
        ids.append(tid)
    return {"template": "hub_burst", "account": hub, "tx_ids": ids}
