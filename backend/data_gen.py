"""Hybrid dataset builder.
Financial layer: PaySim-calibrated generator (mirrors PaySim schema: TRANSFER/CASH_OUT
fraud behavior). If a real PaySim CSV is placed at data/PS_*.csv it is sampled instead.
HR layer: restrained synthetic (90%+ normal). Fusion: EMPLOYEE_TOUCHED_ACCOUNT edges.
The red-team injector (redteam.py) reuses these same primitives live.
"""
from __future__ import annotations
import csv, glob, os, random
from datetime import datetime, timedelta

BASE_TS = (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
           - timedelta(days=60))

DEPTS = ["Payments", "Risk", "Retail Ops", "Treasury", "Compliance"]
ROLES = ["Analyst", "Senior Analyst", "Ops Manager", "Risk Officer", "Treasury Dealer"]

NAMES = ["Priya Sharma", "Rahul Verma", "Ananya Iyer", "Vikram Mehta", "Sneha Kulkarni",
    "Arjun Nair", "Divya Reddy", "Kabir Malhotra", "Meera Joshi", "Sanjay Gupta",
    "Pooja Desai", "Rohan Khanna", "Lakshmi Menon", "Aditya Rao", "Nisha Singhania",
    "Varun Kapoor", "Ishita Bose", "Karan Thakur", "Ritu Agarwal", "Manoj Pillai",
    "Shreya Ghosh", "Nikhil Anand", "Farah Khan", "Deepak Yadav", "Tanvi Patil",
    "Suresh Babu", "Kavya Nambiar", "Alok Mishra", "Rina Dutta", "Harish Chandra",
    "Nandini Rao", "Gopal Krishnan"]

BIZ = ["Acme Exports", "Sharma Retail", "Deccan Logistics", "Kaveri Textiles", "Nandi Foods",
    "Lotus Pharma", "Vijaya Steel", "Coastal Marine", "Ganga Jewels", "Peacock Garments",
    "Sahyadri Motors", "Malabar Spices", "Aditi Developers", "Kiran Electronics", "Nova Finserve",
    "Brass City Traders", "Emerald Hotels", "Sunrise Agro", "Vertex Labs", "Orchid Health",
    "Delta Freight", "Marigold Silks", "Tulip Plastics", "Banyan Traders", "Coral Fisheries",
    "Pearl Ceramics", "Topaz Gems", "Indigo Apparel", "Saffron Foods", "Zircon Tools",
    "Lotus Couriers", "Mango Orchards", "Cedar Furniture", "Opal Optics", "Ruby Printers",
    "Amber Chemicals", "Ivory Interiors", "Jade Jewels", "Onyx Oils", "Quartz Quarries"]
ACCT_KINDS = ["Operating Account", "Current Account", "Savings Account", "Salary Account", "Escrow Account"]

def _seeded(seed: int):
    return random.Random(seed)

def gen_employees(rng, n=28):
    emps = []
    names = rng.sample(NAMES, min(n, len(NAMES)))
    for i in range(n):
        eid = f"E-{101+i}"
        dept = rng.choice(DEPTS)
        role = rng.choice(ROLES[:2] if i > 4 else ROLES)
        mgr = f"E-{101+ (i % 4)}" if i >= 4 else None
        emps.append({"id": eid, "name": names[i % len(names)], "dept": dept, "role": role, "manager": mgr})
    return emps

def gen_accounts(rng, n=120, emps=()):
    accts = []
    biz = rng.sample(BIZ, min(n, len(BIZ)))
    for i in range(n):
        aid = f"A-{501+i}"
        mgr = rng.choice(emps)["id"] if emps else None
        label = f"{biz[i % len(biz)]} — {rng.choice(ACCT_KINDS)}" if i < len(biz) * 2 else None
        if label is None:
            s = rng.choice(NAMES).split()
            label = f"{s[0]} {s[-1]} — {rng.choice(ACCT_KINDS[2:])}"
        accts.append({"id": aid, "customer": f"C-{9000+i}", "label": label, "manager_emp": mgr,
                      "balance": round(rng.uniform(2000, 200000), 2)})
    return accts

def _add_tx(store, tid, src, dst, amount, ts, typ="TRANSFER", gt=False, redteam=False):
    store["transactions"].append({"id": tid, "src": src, "dst": dst,
        "amount": round(float(amount), 2), "ts": ts.isoformat(), "type": typ,
        "ground_truth_fraud": bool(gt), "redteam": bool(redteam)})

def gen_legit_transfers(store, rng, n=900):
    accts = [a["id"] for a in store["accounts"]]
    tid = len(store["transactions"])
    for k in range(n):
        src, dst = rng.sample(accts, 2)
        amt = round(rng.lognormvariate(7.2, 1.1), 2)  # median ~1.3k, like PaySim mass
        amt = min(amt, 60000)
        ts = BASE_TS + timedelta(hours=rng.uniform(0, 24*60), minutes=rng.uniform(0, 59))
        typ = rng.choices(["TRANSFER", "CASH_OUT", "PAYMENT"], weights=[0.5, 0.3, 0.2])[0]
        tid += 1
        _add_tx(store, f"T-{tid:05d}", src, dst, amt, ts, typ, gt=False)

def plant_ground_truth_fraud(store, rng):
    """Plant ~14 labeled suspicious clusters the detectors should catch."""
    accts = [a["id"] for a in store["accounts"]]
    emps = [e["id"] for e in store["employees"]]
    tid = len(store["transactions"]) + 1
    gt_ids = []
    # 1) 4 circular layering rings (A->B->C->A), amounts 8k-25k, within 48h
    for r in range(4):
        ring = rng.sample(accts, 3)
        t0 = BASE_TS + timedelta(days=rng.randint(30, 58))
        amt = rng.uniform(8000, 25000)
        for j in range(3):
            _add_tx(store, f"T-{tid:05d}", ring[j], ring[(j+1) % 3], amt,
                    t0 + timedelta(hours=j*7), "TRANSFER", gt=True)
            gt_ids.append(f"T-{tid:05d}"); tid += 1
    # 2) 4 structuring clusters: 4-6 splits under 10k summing above 10k, same pair, 36h
    for r in range(4):
        src, dst = rng.sample(accts, 2)
        t0 = BASE_TS + timedelta(days=rng.randint(30, 58))
        n = rng.randint(4, 6)
        for j in range(n):
            _add_tx(store, f"T-{tid:05d}", src, dst, rng.uniform(2500, 9500),
                    t0 + timedelta(hours=j*5), "TRANSFER", gt=True)
            gt_ids.append(f"T-{tid:05d}"); tid += 1
    # 3) 4 privilege-escalation frauds: escalation then large transfer <72h
    for r in range(4):
        emp = rng.choice(emps); acc = rng.choice(accts)
        t_esc = BASE_TS + timedelta(days=rng.randint(30, 58))
        store["access_events"].append({"id": f"AE-S{r}", "emp": emp, "account": acc,
            "ts": t_esc.isoformat(), "kind": "escalation"})
        t_tx = t_esc + timedelta(hours=rng.randint(2, 60))
        src2 = acc; dst2 = rng.choice([a for a in accts if a != acc])
        _add_tx(store, f"T-{tid:05d}", src2, dst2, rng.uniform(30000, 120000),
                t_tx, "TRANSFER", gt=True)
        gt_ids.append(f"T-{tid:05d}"); tid += 1
        # fusion edge
        store["access_events"].append({"id": f"AE-S{r}-t", "emp": emp, "account": acc,
            "ts": (t_tx - timedelta(hours=1)).isoformat(), "kind": "touch"})
    # 4) 2 centrality-hub bursts (one account fans out 8+ transfers in a day)
    for r in range(2):
        hub = rng.sample(accts, 1)[0]
        t0 = BASE_TS + timedelta(days=rng.randint(30, 58))
        dsts = rng.sample([a for a in accts if a != hub], 8)
        for j, dst in enumerate(dsts):
            _add_tx(store, f"T-{tid:05d}", hub, dst, rng.uniform(4000, 20000),
                    t0 + timedelta(hours=j*2), "TRANSFER", gt=True)
            gt_ids.append(f"T-{tid:05d}"); tid += 1
    return gt_ids

def gen_normal_access(store, rng):
    """90%+ ordinary access: grants spread over months, touches uncorrelated with fraud."""
    emps = store["employees"]; accts = store["accounts"]
    n = 0
    for e in emps:
        # each employee normally manages ~4 accounts
        mine = rng.sample(accts, min(4, len(accts)))
        for a in mine:
            t = BASE_TS + timedelta(days=rng.randint(0, 20))
            store["access_events"].append({"id": f"AE-{n:04d}", "emp": e["id"],
                "account": a["id"], "ts": t.isoformat(), "kind": "grant"})
            n += 1
            # ordinary touches far from any fraud time
            for _ in range(rng.randint(1, 3)):
                store["access_events"].append({"id": f"AE-{n:04d}", "emp": e["id"],
                    "account": a["id"], "ts": (t + timedelta(days=rng.randint(1, 30))).isoformat(),
                    "kind": "touch"})
                n += 1

def try_load_paysim_csv(store, path_pattern="data/PS_*.csv", max_rows=5000):
    """If a real PaySim CSV exists, sample TRANSFER/CASH_OUT rows as the financial layer.
    Returns number of rows loaded, else 0 (caller falls back to calibrated generator)."""
    files = glob.glob(path_pattern)
    if not files:
        return 0
    rng = random.Random(7)
    with open(files[0], newline="") as f:
        rd = csv.DictReader(f)
        rows = [r for r in rd if r.get("type") in ("TRANSFER", "CASH_OUT")]
    if not rows:
        return 0
    sample = rng.sample(rows, min(max_rows, len(rows)))
    # map names to A- accounts
    name2acct = {}
    def acct(nm):
        if nm not in name2acct:
            name2acct[nm] = f"A-EXT-{len(name2acct)+1}"
        return name2acct[nm]
    tid = 1
    step_base = BASE_TS
    for r in sample:
        try:
            amt = float(r["amount"]); step = int(float(r.get("step", 1)))
        except ValueError:
            continue
        ts = step_base + timedelta(hours=step)
        _add_tx(store, f"T-{tid:05d}", acct(r["nameOrig"]), acct(r["nameDest"]),
                amt, ts, r["type"], gt=(r.get("isFraud") == "1"))
        tid += 1
    # ensure accounts exist
    for nm, aid in name2acct.items():
        if not any(a["id"] == aid for a in store["accounts"]):
            store["accounts"].append({"id": aid, "customer": nm, "label": nm, "manager_emp": None, "balance": 0})
    return len(sample)

def build_demo_store(seed: int = 42) -> dict:
    from .graph_store import new_store
    rng = _seeded(seed)
    store = new_store()
    store["employees"] = gen_employees(rng)
    store["accounts"] = gen_accounts(rng, emps=store["employees"])
    n_real = try_load_paysim_csv(store)
    if n_real == 0:
        gen_legit_transfers(store, rng)
        plant_ground_truth_fraud(store, rng)
    else:
        # attach synthetic HR + fusion onto sampled real accounts
        rng2 = _seeded(seed + 1)
        for a in store["accounts"]:
            a["manager_emp"] = rng2.choice(store["employees"])["id"]
        plant_ground_truth_fraud(store, rng2)
    gen_normal_access(store, rng)
    store["meta"]["dataset"] = "PaySim-CSV-sample" if n_real else "PaySim-calibrated-generator (PaySim schema/behavior)"
    store["meta"]["seed"] = seed
    return store
