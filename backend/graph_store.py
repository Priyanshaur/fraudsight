"""Sentinel Graph — fused HR/access + financial transaction graph store."""
from __future__ import annotations
import json, os, random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict

DATA_FILE = os.path.join(os.path.dirname(__file__), "store.json")

# ---------- Entity dataclasses (JSON-serializable dicts) ----------
def new_store() -> dict:
    return {
        "employees": [],      # {id,name,dept,role,manager}
        "accounts": [],       # {id,customer,manager_emp,balance}
        "transactions": [],   # {id,src,dst,amount,ts,type,ground_truth_fraud,redteam}
        "access_events": [],  # {id,emp,account,ts,kind} kind: grant|touch|escalation
        "alerts": [],         # {id,risk,detectors,evidence,narrative,status,assignee,created_ts,ground_truth}
        "meta": {"created": datetime.utcnow().isoformat(), "struct_threshold": 10000.0},
    }

def load_store() -> dict:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    s = new_store()
    save_store(s)
    return s

def save_store(s: dict):
    with open(DATA_FILE, "w") as f:
        json.dump(s, f, indent=1)

def reset_store():
    if os.path.exists(DATA_FILE):
        os.remove(DATA_FILE)
