"""Graph detectors operating on the fused graph (NetworkX), not flat features."""
from __future__ import annotations
from datetime import datetime, timedelta
from collections import defaultdict
import networkx as nx

def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s)

CONF_RANK = {"high": 3, "medium": 2, "low": 1}

def build_tx_digraph(store) -> nx.DiGraph:
    G = nx.DiGraph()
    for t in store["transactions"]:
        G.add_node(t["src"], kind="account"); G.add_node(t["dst"], kind="account")
        if G.has_edge(t["src"], t["dst"]):
            G[t["src"]][t["dst"]]["txs"].append(t)
        else:
            G.add_edge(t["src"], t["dst"], txs=[t])
    return G

def detect_circular(store, max_cycle_len=5, window_h=72, min_leg=3000.0):
    """Bounded DFS cycle detection with graduated confidence (no hard binary cutoff):
    len<=3 within window -> high; len 4-5 within window -> medium;
    any len within 1.5x window -> low. Amount floor prunes DFS expansion to stay tractable."""
    from datetime import datetime as _dt
    adj = defaultdict(list)  # src -> list of tx
    for t in store["transactions"]:
        if t["amount"] >= min_leg:
            adj[t["src"]].append(t)
    for v in adj.values():
        v.sort(key=lambda t: t["ts"])
    hits = []
    nodes = list(adj.keys())
    for start in nodes:
        # depth-limited DFS paths start -> ... -> start
        stack = [(start, [start], [])]  # node, path, txs used
        while stack:
            node, path, used = stack.pop()
            if len(path) > max_cycle_len + 1:
                continue
            for t in adj.get(node, []):
                nxt = t["dst"]
                if nxt == start and 2 <= len(path) <= max_cycle_len:
                    cyc = path[:]  # start..node, closes to start
                    ev = used + [t]
                    tmin = min(_dt.fromisoformat(x["ts"]) for x in ev)
                    tmax = max(_dt.fromisoformat(x["ts"]) for x in ev)
                    span_h = (tmax - tmin).total_seconds() / 3600
                    if span_h <= window_h:
                        conf = "high" if len(cyc) <= 3 else "medium"
                    elif span_h <= window_h * 1.5:
                        conf = "low"
                    else:
                        continue
                    hits.append({"type": "circular", "cycle": cyc,
                                 "confidence": conf,
                                 "tx_ids": [x["id"] for x in ev],
                                 "total_amount": round(sum(x["amount"] for x in ev), 2),
                                 "detail": f"Cycle {'→'.join(cyc)}→{start} spanning {span_h:.0f}h ({len(cyc)}-node, {conf} confidence)"})
                elif nxt not in path and len(path) < max_cycle_len:
                    stack.append((nxt, path + [nxt], used + [t]))
            if len(hits) > 80:
                break
        if len(hits) > 80:
            break
    # dedupe by cycle set, keeping the highest-confidence hit
    best = {}
    for h in hits:
        k = tuple(sorted(h["cycle"]))
        if k not in best or CONF_RANK[h["confidence"]] > CONF_RANK[best[k]["confidence"]]:
            best[k] = h
    return list(best.values())

def detect_structuring(store, threshold=10000.0, window_h=48, min_parts=3):
    """Same-pair splits individually < threshold but summing above it, in window."""
    by_pair = defaultdict(list)
    for t in store["transactions"]:
        by_pair[(t["src"], t["dst"])].append(t)
    hits = []
    for (src, dst), txs in by_pair.items():
        txs = sorted(txs, key=lambda t: t["ts"])
        for i in range(len(txs)):
            win = [t for t in txs[i:] if (_ts(t["ts"]) - _ts(txs[i]["ts"])).total_seconds() <= window_h*3600]
            under = [t for t in win if t["amount"] < threshold]
            if len(under) >= min_parts and sum(t["amount"] for t in under) >= threshold:
                hits.append({"type": "structuring", "src": src, "dst": dst,
                    "tx_ids": [t["id"] for t in under],
                    "parts": len(under), "total_amount": round(sum(t["amount"] for t in under), 2),
                    "detail": f"{len(under)} sub-threshold transfers {src}→{dst} sum ₹{sum(t['amount'] for t in under):,.0f} in {window_h}h"})
                break
    return hits

def detect_access_anomaly(store, esc_window_h=72, grant_window_h=24,
                            esc_min_amt=10000.0, grant_min_amt=50000.0):
    """Transfer where the account was touched by an employee with a recent escalation/grant.
    Escalations are strong signals (72h window); ordinary grants only count when very
    fresh (24h) AND the transfer is very large — keeping the false-positive rate low."""
    esc = [a for a in store["access_events"] if a["kind"] in ("escalation", "grant")]
    touch_by_acct = defaultdict(list)
    for a in store["access_events"]:
        if a["kind"] == "touch":
            touch_by_acct[a["account"]].append(a)
    hits = []
    for t in store["transactions"]:
        tt = _ts(t["ts"])
        for ae in esc:
            if ae["account"] not in (t["src"], t["dst"]):
                continue
            dt = (tt - _ts(ae["ts"])).total_seconds() / 3600
            if ae["kind"] == "escalation":
                # graduated: <=72h high, 72-120h medium (hard floor at 120h to protect FPR)
                if 0 <= dt <= esc_window_h and t["amount"] >= esc_min_amt:
                    conf = "high"
                elif esc_window_h < dt <= 120 and t["amount"] >= esc_min_amt:
                    conf = "medium"
                else:
                    continue
            else:
                if not (0 <= dt <= grant_window_h and t["amount"] >= grant_min_amt):
                    continue
                conf = "high"
            hits.append({"type": "access_anomaly", "emp": ae["emp"], "account": ae["account"],
                "tx_ids": [t["id"]], "access_id": ae["id"], "kind": ae["kind"],
                "total_amount": t["amount"], "confidence": conf,
                "hours_before": round(dt, 1),
                "detail": f"Employee {ae['emp']} {ae['kind']} on {ae['account']} {dt:.1f}h before transfer {t['id']} (₹{t['amount']:,.0f}, {conf} confidence)"})
            break
    return hits

def detect_hub_shift(store, window_days=7, min_fanout=6):
    """Degree burst with graduated confidence: fan-out within window_days -> high,
    within 1.5x the window -> medium. The extended window uses a stricter fanout
    bar (min_fanout+2): a wider net over more days would otherwise catch ordinary
    active accounts by chance (verified: 4 FPs at exactly 6 counterparties)."""
    txs = sorted(store["transactions"], key=lambda t: t["ts"])
    for t in txs:
        t["_dt"] = _ts(t["ts"])
    hits, seen = [], set()
    by_src = defaultdict(list)
    for t in txs:
        by_src[t["src"]].append(t)
    for src, lst in by_src.items():
        for i, t0 in enumerate(lst):
            win = [t for t in lst[i:] if (t["_dt"] - t0["_dt"]).total_seconds() <= window_days*86400]
            cps = {t["dst"] for t in win}
            conf = "high" if len(cps) >= min_fanout else None
            if conf is None:
                wide = [t for t in lst[i:] if (t["_dt"] - t0["_dt"]).total_seconds() <= window_days*1.5*86400]
                if len({t["dst"] for t in wide}) >= min_fanout + 2:
                    conf, win, cps = "medium", wide, {t["dst"] for t in wide}
            if conf and t0["src"] not in seen:
                seen.add(t0["src"])
                hits.append({"type": "hub_shift", "account": t0["src"],
                    "confidence": conf, "fanout": len(cps),
                    "tx_ids": [t["id"] for t in win[:12]],
                    "total_amount": round(sum(t["amount"] for t in win), 2),
                    "detail": f"Account {t0['src']} fanned out to {len(cps)} counterparties in ~{window_days if conf=='high' else window_days*1.5:.0f}d (burst hub, {conf} confidence)"})
                break
    for t in txs:
        t.pop("_dt", None)
    return hits

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

def risk_from_hits(hit_types: list[str], confidences: list[str] | None = None) -> tuple[str, str]:
    """Transparent risk mapping (no opaque score). Critical/High require at least one
    high-confidence hit; cases built only of medium/low-confidence hits cap at Medium."""
    s = set(hit_types)
    n = len(s)
    confs = confidences or ["high"] * len(hit_types)
    best = max((CONF_RANK.get(c, 3) for c in confs), default=3)
    tier = {v: k for k, v in CONF_RANK.items()}[best]
    multi = ("circular" in s and "access_anomaly" in s) or n >= 3
    if multi and best == 3:
        return "Critical", f"≥3 independent detectors (or layering + insider access) corroborate at {tier} confidence"
    if n == 2 and best == 3:
        return "High", f"2 independent detectors corroborate at {tier} confidence"
    if ("access_anomaly" in s or "circular" in s) and n == 1 and best == 3:
        return "High", f"single strong detector (layering or insider escalation) at {tier} confidence"
    if n >= 1 and best <= 2:
        return "Medium", f"capped at Medium: {n} detector(s) fired but all at {tier} confidence — treat as a lead, not a finding"
    if n == 1:
        return "Medium", f"single detector fired at {tier} confidence"
    return "Low", "no detector fired"

def run_all_detectors(store) -> list[dict]:
    circ = detect_circular(store); struct = detect_structuring(store)
    acc = detect_access_anomaly(store); hub = detect_hub_shift(store)
    # group hits into alerts: group circular/struct/hub by entity, access hits standalone+merge
    alerts = []
    for h in circ:
        alerts.append({"detectors": ["circular"], "hits": [h],
                       "anchor": "cycle:" + "-".join(sorted(h["cycle"])),
                       "tx_ids": h["tx_ids"]})
    for h in struct:
        alerts.append({"detectors": ["structuring"], "hits": [h],
                       "anchor": f"pair:{h['src']}->{h['dst']}", "tx_ids": h["tx_ids"]})
    for h in hub:
        # merge with existing alert on same account if overlap
        alerts.append({"detectors": ["hub_shift"], "hits": [h],
                       "anchor": f"hub:{h['account']}", "tx_ids": h["tx_ids"]})
    for h in acc:
        # attach to an existing alert sharing the tx if present (fusion!), else standalone
        target = next((a for a in alerts if h["tx_ids"][0] in a["tx_ids"]), None)
        if target:
            if "access_anomaly" not in target["detectors"]:
                target["detectors"].append("access_anomaly")
                target["hits"].append(h)
        else:
            alerts.append({"detectors": ["access_anomaly"], "hits": [h],
                           "anchor": f"acc:{h['emp']}:{h['account']}", "tx_ids": h["tx_ids"]})
    # risk + dedupe (confidence-aware: pass each hit's tier through)
    for a in alerts:
        lvl, why = risk_from_hits(a["detectors"], [h.get("confidence", "high") for h in a["hits"]])
        a["risk"], a["risk_reason"] = lvl, why
    alerts.sort(key=lambda a: RISK_ORDER[a["risk"]], reverse=True)
    return alerts
