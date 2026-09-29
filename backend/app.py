"""Sentinel Graph API — FastAPI backend serving fused graph + detectors + cases."""
from __future__ import annotations
import io, json
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

from .graph_store import load_store, save_store, reset_store
from .data_gen import build_demo_store
from .detectors import run_all_detectors
from .intel import evidence_for_alert, llm_narrative, compute_metrics, nl_query, risk_neighbors
from . import redteam

app = FastAPI(title="Sentinel Graph")

# ---------- helpers ----------
def get_store():
    s = load_store()
    if not s["transactions"]:
        s = build_demo_store()
        refresh_alerts(s)
    return s

def refresh_alerts(store):
    """Re-run detectors; preserve case status/assignee for surviving anchors."""
    prev = {a["anchor"]: a for a in store.get("alerts", [])}
    new_alerts = []
    for i, a in enumerate(run_all_detectors(store)):
        aid = f"AL-{i+1:03d}"
        old = prev.get(a["anchor"])
        ev = evidence_for_alert(store, a)
        if old and old["detectors"] == a["detectors"] and set(old["tx_ids"]) == set(a["tx_ids"]):
            old.update({"risk": a["risk"], "risk_reason": a["risk_reason"], "hits": a["hits"]})
            old["evidence"] = ev
            new_alerts.append(old)
        else:
            alert = {"id": aid, "anchor": a["anchor"], "risk": a["risk"],
                     "risk_reason": a["risk_reason"], "detectors": a["detectors"],
                     "hits": a["hits"], "tx_ids": a["tx_ids"], "evidence": ev,
                     "status": "New", "assignee": None,
                     "ground_truth": any(next((t for t in store["transactions"] if t["id"] == tid), {}).get("ground_truth_fraud") for tid in a["tx_ids"])}
            txt, src = llm_narrative(alert, ev)
            alert["narrative"], alert["narrative_source"] = txt, src
            new_alerts.append(alert)
    # renumber
    for i, a in enumerate(new_alerts):
        a["id"] = f"AL-{i+1:03d}"
    store["alerts"] = new_alerts
    save_store(store)
    return store

# ---------- API ----------
@app.get("/api/health")
def health():
    return {"ok": True}

@app.post("/api/bootstrap")
def bootstrap(seed: int = 42):
    reset_store()
    s = build_demo_store(seed=seed)
    refresh_alerts(s)
    return {"alerts": len(s["alerts"]), "tx": len(s["transactions"]), "meta": s["meta"]}

@app.get("/api/alerts")
def alerts():
    s = get_store()
    return [{"id": a["id"], "risk": a["risk"], "detectors": a["detectors"],
             "det_conf": {d: next((h.get("confidence", "high") for h in a.get("hits", [])
                                   if h.get("type") == d), "high") for d in a["detectors"]},
             "ground_truth": a.get("ground_truth", False),
             "status": a["status"], "assignee": a["assignee"],
             "tx_count": len(a["tx_ids"]), "risk_reason": a["risk_reason"]} for a in s["alerts"]]

@app.get("/api/alerts/{aid}")
def alert_detail(aid: str):
    s = get_store()
    a = next((x for x in s["alerts"] if x["id"] == aid), None)
    if not a: raise HTTPException(404, "alert not found")
    out = dict(a)
    out["risk_neighbors"] = risk_neighbors(s, a)
    return out

class CasePatch(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None

@app.patch("/api/alerts/{aid}")
def patch_case(aid: str, p: CasePatch):
    s = get_store()
    a = next((x for x in s["alerts"] if x["id"] == aid), None)
    if not a: raise HTTPException(404, "alert not found")
    if p.status:
        if p.status not in ("New", "Under Review", "Escalated", "Cleared"):
            raise HTTPException(400, "bad status")
        a["status"] = p.status
    if p.assignee is not None:
        a["assignee"] = p.assignee
    save_store(s)
    return a

@app.get("/api/alerts/{aid}/export")
def export_case(aid: str):
    s = get_store()
    a = next((x for x in s["alerts"] if x["id"] == aid), None)
    if not a: raise HTTPException(404, "alert not found")
    buf = io.StringIO()
    json.dump({"case": a["id"], "risk": a["risk"], "risk_reason": a["risk_reason"],
               "status": a["status"], "assignee": a["assignee"],
               "narrative": a.get("narrative"), "evidence": a["evidence"]}, buf, indent=1)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={aid}-evidence.json"})

@app.get("/api/metrics")
def metrics():
    s = get_store()
    m = compute_metrics(s)
    by_risk, by_status = {}, {}
    for a in s["alerts"]:
        by_risk[a["risk"]] = by_risk.get(a["risk"], 0) + 1
        by_status[a["status"]] = by_status.get(a["status"], 0) + 1
    m.update({"by_risk": by_risk, "by_status": by_status, "dataset": s["meta"].get("dataset")})
    # Honest dual reporting: in-distribution accuracy AND out-of-window stress test.
    try:
        from .adversarial import run_adversarial_stress_test
        m["stress_test"] = run_adversarial_stress_test()
    except Exception as ex:
        m["stress_test"] = {"error": str(ex)}
    return m

@app.get("/api/employees")
def employees():
    return get_store()["employees"]

@app.get("/api/entities")
def entities():
    """Full entity records for Graph Explorer + global search (employees, accounts,
    transactions). Ground-truth fraud flags are included and labeled as demo labels."""
    s = get_store()
    return {"employees": s["employees"], "accounts": s["accounts"],
            "transactions": s["transactions"]}


class VerdictIn(BaseModel):
    employee: str
    status: str
    case_id: Optional[str] = None
    note: Optional[str] = None

@app.get("/api/verdicts")
def verdicts():
    return get_store().setdefault('verdicts', {})

@app.post("/api/verdicts")
def set_verdict(v: VerdictIn):
    from datetime import datetime
    s = get_store()
    if v.status not in ('Suspect', 'Guilty', 'Cleared'):
        raise HTTPException(400, 'bad status')
    if not any(e['id'] == v.employee for e in s['employees']):
        raise HTTPException(400, 'unknown employee')
    s.setdefault('verdicts', {})[v.employee] = {'status': v.status, 'case_id': v.case_id, 'note': v.note, 'updated': datetime.utcnow().isoformat(timespec='seconds')}
    save_store(s)
    return s['verdicts'][v.employee]

class InjectReq(BaseModel):
    template: str = "circular_transfer"
    amount: float = 15000.0
    splits: int = 6

@app.post("/api/redteam/inject")
def inject(r: InjectReq):
    s = get_store()
    if r.template == "circular_transfer":
        info = redteam.inject_circular_transfer(s, amount=r.amount)
    elif r.template == "structuring":
        info = redteam.inject_structuring(s, total_amount=r.amount, num_splits=r.splits)
    elif r.template == "privilege_escalation":
        info = redteam.inject_privilege_escalation_fraud(s, amount=r.amount)
    elif r.template == "hub_burst":
        info = redteam.inject_hub_burst(s, amount=r.amount)
    else:
        raise HTTPException(400, "unknown template")
    refresh_alerts(s)
    # return the alert(s) covering the injected txs
    matched = [a["id"] for a in s["alerts"] if set(a["tx_ids"]) & set(info["tx_ids"])]
    return {"injected": info, "matched_alerts": matched}

@app.get("/api/nlquery")
def nlquery(q: str):
    s = get_store()
    return nl_query(s, q)

@app.get("/api/graph")
def full_graph(limit: int = 400):
    s = get_store()
    txs = s["transactions"][:limit]
    nodes = {t["src"]: {"id": t["src"], "kind": "account"} for t in txs}
    nodes.update({t["dst"]: {"id": t["dst"], "kind": "account"} for t in txs})
    edges = [{"from": t["src"], "to": t["dst"], "title": f"{t['id']} ₹{t['amount']:,.0f}"} for t in txs]
    return {"nodes": [{"id": k, "label": k, **v} for k, v in nodes.items()], "edges": edges}

# ---------- Frontend ----------
import os
FRONT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "index.html")

@app.get("/", response_class=HTMLResponse)
def index():
    with open(FRONT, encoding="utf-8") as f:
        return f.read()