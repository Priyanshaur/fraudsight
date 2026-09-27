"""Evidence subgraph extraction + grounded narrative + metrics + NLQ + red-team."""
from __future__ import annotations
from datetime import datetime
import re

# ---------- Evidence ----------
def evidence_for_alert(store, alert) -> dict:
    tx_ids = set(alert["tx_ids"])
    txs = [t for t in store["transactions"] if t["id"] in tx_ids]
    acct_ids = {t["src"] for t in txs} | {t["dst"] for t in txs}
    emp_ids, ae_ids = set(), set()
    for h in alert["hits"]:
        if h["type"] == "access_anomaly":
            emp_ids.add(h["emp"]); acct_ids.add(h["account"])
            ae_ids.add(h.get("access_id"))
    # related touches on involved accounts
    rel_ae = [a for a in store["access_events"]
              if (a["account"] in acct_ids and a["emp"] in emp_ids) or a["id"] in ae_ids]
    for a in rel_ae:
        emp_ids.add(a["emp"])
    nodes, edges = [], []
    emps = {e["id"]: e for e in store["employees"]}
    accts = {a["id"]: a for a in store["accounts"]}
    for eid in emp_ids:
        e = emps.get(eid, {"id": eid, "dept": "?", "role": "?", "name": eid})
        nodes.append({"id": eid, "label": eid, "kind": "employee",
                      "title": f"{e.get('name', eid)} ({eid}) · {e.get('role')} · {e.get('dept')}"})
    for aid in acct_ids:
        a = accts.get(aid, {})
        nodes.append({"id": aid, "label": aid, "kind": "account",
                      "title": f"{a.get('label', aid)} ({aid})"})
    for t in txs:
        tid = t["id"]
        nodes.append({"id": tid, "label": f"₹{t['amount']:,.0f}", "kind": "transaction",
                      "title": f"{tid}: {t['src']}→{t['dst']} ₹{t['amount']:,.0f} @ {t['ts']}"})
        edges.append({"from": t["src"], "to": tid, "label": "IN",
                      "title": f"{t['src']} sent ₹{t['amount']:,.0f}"})
        edges.append({"from": tid, "to": t["dst"], "label": f"₹{t['amount']:,.0f}",
                      "title": f"→ {t['dst']} @ {t['ts']}"})
    for a in rel_ae:
        edges.append({"from": a["emp"], "to": a["account"],
                      "label": "ESCALATION" if a["kind"] == "escalation" else "TOUCHED",
                      "dashes": a["kind"] != "escalation",
                      "title": f"{a['emp']} {a['kind']} {a['account']} @ {a['ts']}",
                      "color": "red" if a["kind"] == "escalation" else "orange"})
    timeline = sorted(
        [{"ts": t["ts"], "text": f"Transfer {t['id']}: {t['src']}→{t['dst']} ₹{t['amount']:,.0f}"} for t in txs] +
        [{"ts": a["ts"], "text": f"Access {a['kind']}: {a['emp']} on {a['account']}"} for a in rel_ae],
        key=lambda e: e["ts"])
    return {"nodes": nodes, "edges": edges, "timeline": timeline,
            "detectors": alert["detectors"], "hits": alert["hits"]}

# ---------- Narrative (LLM w/ grounded fallback) ----------
NARR_TMPL = ("Alert {aid} [{risk} — {reason}]. {sents} "
             "Evidence: transactions {txs}; accounts {accts}; employees {emps}. "
             "Recommended next step: {nxt}.")

def template_narrative(alert, ev) -> str:
    sents = []
    for h in alert["hits"]:
        sents.append(h["detail"] + ".")
    txs = sorted({t for h in alert["hits"] for t in h.get("tx_ids", [])})
    accts = sorted({n["id"] for n in ev["nodes"] if n["kind"] == "account"})
    emps = sorted({n["id"] for n in ev["nodes"] if n["kind"] == "employee"})
    nxt = ("freeze and review the escalated employee's access immediately"
           if "access_anomaly" in alert["detectors"] else "review the full transaction chain with compliance")
    return NARR_TMPL.format(aid=alert["id"], risk=alert["risk"], reason=alert["risk_reason"],
                            sents=" ".join(sents), txs=", ".join(txs[:8]),
                            accts=", ".join(accts[:6]) or "—", emps=", ".join(emps) or "—", nxt=nxt)

def llm_narrative(alert, ev) -> tuple[str, str]:
    """Try Anthropic API; fall back to grounded template. Returns (text, source)."""
    import os
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return template_narrative(alert, ev), "template-grounded (no API key)"
    try:
        import json as _j, urllib.request
        nodes = "; ".join(f"{n['id']}({n['kind']})" for n in ev["nodes"][:30])
        edges = "; ".join(f"{e['from']}-{e['label']}->{e['to']}" for e in ev["edges"][:30])
        dets = "; ".join(h["detail"] for h in alert["hits"])
        prompt = (f"Write a 3-5 sentence investigator summary citing exact entity IDs. "
                  f"Risk {alert['risk']} ({alert['risk_reason']}). Detectors: {alert['detectors']}. "
                  f"Details: {dets}. Nodes: {nodes}. Edges: {edges}.")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=_j.dumps({"model": "claude-3-5-sonnet-latest", "max_tokens": 300,
                           "system": "You are a financial-crime investigator. Cite entity IDs exactly.",
                           "messages": [{"role": "user", "content": prompt}]}).encode(),
            headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=25) as r:
            body = _j.loads(r.read().decode())
        txt = "".join(b.get("text", "") for b in body["content"] if b.get("type") == "text")
        return txt or template_narrative(alert, ev), "anthropic-llm"
    except Exception as ex:
        return template_narrative(alert, ev) + f" [LLM fallback: {ex}]", "template-grounded (LLM error)"

# ---------- Metrics ----------
def compute_metrics(store) -> dict:
    flagged_tx = set()
    for a in store["alerts"]:
        flagged_tx.update(a.get("tx_ids", []))
    fraud = [t for t in store["transactions"] if t.get("ground_truth_fraud")]
    legit = [t for t in store["transactions"] if not t.get("ground_truth_fraud")]
    tp = sum(1 for t in fraud if t["id"] in flagged_tx)
    fn = len(fraud) - tp
    fp = sum(1 for t in legit if t["id"] in flagged_tx)
    tn = len(legit) - fp
    acc = (tp + tn) / max(1, len(store["transactions"]))
    fpr = fp / max(1, fp + tn)
    rec = tp / max(1, tp + fn)
    return {"accuracy": round(acc, 4), "false_positive_rate": round(fpr, 4),
            "recall": round(rec, 4), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "n_tx": len(store["transactions"]), "n_fraud_gt": len(fraud),
            "n_alerts": len(store["alerts"])}

# ---------- NLQ (scoped classifier over 5 query shapes) ----------
SHAPES = ["touched_before_transfer", "employee_neighborhood", "cycles", "structuring_pairs", "large_transfers"]

def nl_query(store, q: str) -> dict:
    from .detectors import detect_circular, detect_structuring
    ql = q.lower()
    hours = int((re.search(r"(\d+)\s*hours?", ql) or [None, 48])[1])
    hops = int((re.search(r"(\d+)\s*hops?", ql) or [None, 2])[1])
    amt_m = re.search(r"₹?\s*([\d,]+)\s*(l|lakh|k)?", ql)
    amt = 50000.0
    if amt_m:
        v = float(amt_m.group(1).replace(",", ""))
        if amt_m.group(2) in ("l", "lakh"): v *= 100000
        elif amt_m.group(2) == "k": v *= 1000
        amt = v
    emp_m = re.search(r"e-?(\d+)", ql)
    emp = f"E-{emp_m.group(1)}" if emp_m else None
    shape = "large_transfers"
    if "cycl" in ql or "ring" in ql or "layering" in ql: shape = "cycles"
    elif "split" in ql or "structur" in ql or "sub-threshold" in ql or "under report" in ql: shape = "structuring_pairs"
    elif emp or ("neighbor" in ql or "hop" in ql or "connected" in ql): shape = "employee_neighborhood"
    elif "access" in ql or "touch" in ql or "before" in ql or "escalat" in ql: shape = "touched_before_transfer"
    out = {"shape": shape, "params": {"hours": hours, "hops": hops, "amount": amt, "employee": emp}}
    if shape == "cycles":
        out["answer"] = detect_circular(store)[:5]
    elif shape == "structuring_pairs":
        out["answer"] = detect_structuring(store)[:5]
    elif shape == "large_transfers":
        out["answer"] = [t for t in store["transactions"] if t["amount"] >= amt][:20]
    elif shape == "employee_neighborhood":
        acct = {a["account"] for a in store["access_events"] if not emp or a["emp"] == emp}
        out["answer"] = [t for t in store["transactions"]
                         if t["src"] in acct or t["dst"] in acct][:20]
    else:
        from datetime import datetime as _dt
        hits = []
        for t in store["transactions"]:
            tt = _dt.fromisoformat(t["ts"])
            for a in store["access_events"]:
                if a["account"] in (t["src"], t["dst"]):
                    dt = (tt - _dt.fromisoformat(a["ts"])).total_seconds() / 3600
                    if 0 <= dt <= hours:
                        hits.append({"tx": t["id"], "emp": a["emp"], "account": a["account"],
                                     "hours_before": round(dt, 1), "amount": t["amount"]})
                        break
            if len(hits) >= 25: break
        out["answer"] = hits
    return out

# ---------- Risk propagation (decaying BFS from flagged nodes) ----------
def risk_neighbors(store, alert, decay=0.5, max_hops=2) -> list[dict]:
    import networkx as nx
    from .detectors import build_tx_digraph
    G = build_tx_digraph(store).to_undirected()
    # add employee nodes via touches
    for a in store["access_events"]:
        G.add_edge(a["emp"], a["account"])
    seeds = {n["id"] for n in evidence_for_alert(store, alert)["nodes"]
             if n["kind"] in ("account", "employee")}
    scored = {}
    frontier = [(s, 1.0, 0) for s in seeds if s in G]
    seen = set()
    from collections import deque
    dq = deque(frontier)
    while dq:
        node, risk, hop = dq.popleft()
        if node in seen or hop > max_hops: continue
        seen.add(node)
        if node not in seeds:
            scored[node] = round(risk, 3)
        if hop < max_hops:
            for nb in G.neighbors(node):
                dq.append((nb, risk * decay, hop + 1))
    return sorted(({"id": k, "assoc_risk": v} for k, v in scored.items()),
                  key=lambda d: -d["assoc_risk"])[:15]
