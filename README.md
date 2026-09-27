# Sentinel Graph — Financial Crime & Insider Risk Intelligence Platform (FIN-04)

Fuses employee/access activity with financial transactions into one graph, detects
laundering patterns with graph algorithms, and explains every alert with an evidence
subgraph + timeline + grounded narrative.

## Quickstart

```bash
pip install -r requirements.txt
uvicorn backend.app:app --reload
# open http://127.0.0.1:8000
```

Data auto-bootstraps on first run (PaySim-calibrated generator; drop a real
`data/PS_*.csv` PaySim file to use sampled real transactions instead).
Set `ANTHROPIC_API_KEY` for LLM narratives; otherwise grounded templates are used
(every narrative still cites exact entity IDs from the evidence subgraph).

## What maps to the brief

| Brief requirement | Where |
|---|---|
| Money-flow graph + activity timeline | `/` alert detail: vis-network evidence graph + timeline strip |
| Explainable risk (no opaque score) | `backend/detectors.py::risk_from_hits` — Low/Med/High/Critical from which detectors fired |
| Case assignment + evidence export | PATCH `/api/alerts/{id}`, GET `/api/alerts/{id}/export` |
| Accuracy + false-positive on legit & suspicious | GET `/api/metrics` — **known-pattern acc 0.988, FPR 0.012, recall 1.0** on ~950 tx (52 fraud) **plus** an out-of-window stress test (**13/18 = 72.2%**; the 5 misses are documented-correct: 2-part pair is definitional, 60h structuring spread exceeds the 48h window by design) |
| Mandatory evidence panel per alert | narrative + evidence subgraph on every alert |

## Wow features
1. **Live Red-Team Simulator** — Red-Team tab: inject circular/structuring/escalation/hub attacks live, alert appears with evidence, then **Replay the attack**: step-by-step animated reconstruction of the crime on the graph with timestamps.
2. **LLM investigator narrative** — every alert; Anthropic API w/ grounded fallback.
3. **Natural-language graph query** — NL Query tab (5 scoped shapes: touched-before-transfer, neighborhoods, cycles, structuring pairs, large transfers).
4. **Risk propagation** — at-risk neighbors by decaying BFS on each alert.
5. **SAR-style export** — evidence JSON export per case (LLM SAR draft: extend `intel.llm_narrative`).
6. **Employee notice & response** — per-case right-to-reply: HR/Legal-gated notification stating the
   noted facts and investigation status, Sent→Acknowledged→Responded→Closed tracking, and the
   employee's verbatim statement attached to the case file and exports.
7. **Employee view (role switch)** — top-bar "View as" switcher plus a personal inbox: employees see
   and answer only their own notices (`X-Actor` identity, server-enforced: no cross-employee reads,
   no self-closing, no case edits, no simulations).
8. **Explainability layer** — hover/click any jargon term for a plain-English definition; every alert
   opens its Explanation tab with a story-style summary, a "why this level (and what would change it)"
   box, and per-detector graph highlighting (dim everything a detector didn't fire on).

## Demo script (5 min)
1. Dashboard: 14 pre-existing alerts at mixed risk. 2. Open AL-001: evidence graph + timeline + narrative ("exact evidence, not a score").
3. **Red-Team centerpiece**: inject structuring live → new alert with explanation in seconds.
4. NL query: "show employees who accessed an account within 48 hours before a transfer".
5. Metrics: accuracy/FPR panel. 6. Assign + export case.

## Layout
`backend/` app.py (API) · data_gen.py (hybrid dataset) · detectors.py (4 graph detectors + risk) ·
intel.py (evidence, narrative, metrics, NLQ, contagion) · redteam.py (injector) · graph_store.py
`frontend/index.html` — **FraudSight** enterprise app (white SaaS theme, sidebar shell:
Home dashboard, Investigations, Alerts queue, Alert Detail workspace, Red Team
Simulator, Cases, Graph Explorer, Reports, Settings). All charts hand-drawn SVG and the
graph library vendored — zero CDN/network dependencies. Edit `frontend/src.html`, then
regenerate with: `python build_frontend.py`.
