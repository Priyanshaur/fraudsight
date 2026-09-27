"""Sentinel Graph API — FastAPI backend serving fused graph + detectors + cases."""
from __future__ import annotations
import io, json
from fastapi import FastAPI, HTTPException, Request
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
             "notice": ((a.get("notices") or [None])[-1] or {}).get("status"),
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
def patch_case(aid: str, p: CasePatch, request: Request):
    s = get_store()
    if _actor(request, s):
        raise HTTPException(403, "employees cannot modify cases")
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
               "narrative": a.get("narrative"), "evidence": a["evidence"],
               "notices": a.get("notices", [])}, buf, indent=1)
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={aid}-evidence.json"})

# ---------- Employee notice & response (right-to-reply) ----------
# Notifying the subject is a sensitive step: it requires recorded HR/Legal sign-off,
# uses only facts already in the evidence, and tracks Sent→Acknowledged→Responded→Closed.

def _notice_employee_default(a: dict):
    for h in a.get("hits", []):
        if h.get("type") == "access_anomaly" and h.get("emp"):
            return h["emp"]
    return None

@app.get("/api/alerts/{aid}/notice-draft")
def notice_draft(aid: str, request: Request):
    s = get_store()
    if _actor(request, s):
        raise HTTPException(403, "drafts are a compose tool for the investigation team")
    a = next((x for x in s["alerts"] if x["id"] == aid), None)
    if not a: raise HTTPException(404, "alert not found")
    tl = (a.get("evidence") or {}).get("timeline", [])
    first = tl[0]["ts"][:16].replace("T", " ") if tl else "—"
    facts = "; ".join(h.get("detail", "") for h in a.get("hits", []))
    emp = _notice_employee_default(a)
    body = (
        f"You are receiving this notice because activity linked to you has been flagged for review under case {a['id']}.\n\n"
        f"What was noted: {facts}\n\n"
        f"Status: the matter is Under Investigation. No conclusion has been reached.\n\n"
        f"Your side: please reply with any context you can provide (authorization, business purpose, supporting references). "
        f"Your response will be attached to the case file unchanged.\n\n"
        f"Do not alter, delete, or discuss related records outside the review channel while this notice is open."
    )
    return {"employee": emp, "subject": f"Compliance review notice — case {a['id']} (evidence dated {first})", "body": body}

class NoticeIn(BaseModel):
    employee: str
    subject: str
    body: str
    approved_by: Optional[str] = None

class NoticePatch(BaseModel):
    status: Optional[str] = None  # Acknowledged | Responded | Closed
    response: Optional[str] = None
    by: Optional[str] = None

def _now():
    from datetime import datetime
    return datetime.utcnow().isoformat(timespec="seconds")

def _actor(request: Request, s: dict) -> Optional[str]:
    """Demo role identity from X-Actor header. Returns an employee id when the caller
    acts as an employee, else None (investigator). Unknown ids are rejected."""
    a = (request.headers.get("x-actor") or "investigator").strip()
    if a.lower() == "investigator":
        return None
    if any(e["id"] == a for e in s["employees"]):
        return a
    raise HTTPException(400, "unknown actor (use 'investigator' or a valid employee id)")

@app.get("/api/notices/mine")
def my_notices(request: Request):
    s = get_store()
    emp = _actor(request, s)
    if not emp:
        raise HTTPException(403, "switch to an employee view to see personal notices")
    out = []
    for a in s["alerts"]:
        for n in a.get("notices", []):
            if n["employee"] == emp:
                out.append({"alert_id": a["id"], "risk": a["risk"],
                            "detectors": a["detectors"], "notice": n})
    return out

@app.post("/api/alerts/{aid}/notices")
def create_notice(aid: str, n: NoticeIn, request: Request):
    s = get_store()
    if _actor(request, s):
        raise HTTPException(403, "employees cannot issue notices")
    a = next((x for x in s["alerts"] if x["id"] == aid), None)
    if not a: raise HTTPException(404, "alert not found")
    if not n.approved_by:
        raise HTTPException(400, "HR/Legal approval required before notifying the subject (pass approved_by)")
    if not any(e["id"] == n.employee for e in s["employees"]):
        raise HTTPException(400, "unknown employee")
    a.setdefault("notices", [])
    nid = f"N-{aid[3:]}-{len(a['notices']) + 1:02d}"
    notice = {"id": nid, "employee": n.employee, "subject": n.subject, "body": n.body,
              "status": "Sent", "approved_by": n.approved_by, "sent_at": _now(),
              "response": None, "events": [{"ts": _now(), "event": "Sent", "by": n.approved_by}]}
    a["notices"].append(notice)
    save_store(s)
    return notice

@app.patch("/api/alerts/{aid}/notices/{nid}")
def patch_notice(aid: str, nid: str, p: NoticePatch, request: Request):
    s = get_store()
    a = next((x for x in s["alerts"] if x["id"] == aid), None)
    if not a: raise HTTPException(404, "alert not found")
    n = next((x for x in a.get("notices", []) if x["id"] == nid), None)
    if not n: raise HTTPException(404, "notice not found")
    emp = _actor(request, s)
    if emp and emp != n["employee"]:
        raise HTTPException(403, "employees may only act on their own notices")
    if emp and p.status == "Closed":
        raise HTTPException(403, "only the investigation team can close a notice")
    order = ["Sent", "Acknowledged", "Responded", "Closed"]
    if p.status:
        if p.status not in order[1:]:
            raise HTTPException(400, "bad status")
        if order.index(p.status) < order.index(n["status"]):
            raise HTTPException(400, "cannot move notice backwards")
        if p.status == "Responded" and not (p.response or n["response"]):
            raise HTTPException(400, "a response text is required to mark Responded")
        n["status"] = p.status
        n["events"].append({"ts": _now(), "event": p.status, "by": p.by or n["employee"]})
    if p.response is not None:
        n["response"] = p.response
        if n["status"] in ("Sent", "Acknowledged"):
            n["status"] = "Responded"
            n["events"].append({"ts": _now(), "event": "Responded", "by": p.by or n["employee"]})
    save_store(s)
    return n

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

class InjectReq(BaseModel):
    template: str = "circular_transfer"
    amount: float = 15000.0
    splits: int = 6

@app.post("/api/redteam/inject")
def inject(r: InjectReq, request: Request):
    s = get_store()
    if _actor(request, s):
        raise HTTPException(403, "simulations are run by the investigation team")
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
