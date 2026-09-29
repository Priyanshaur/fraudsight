# FraudSight — Financial Crime & Insider Risk Intelligence Platform

> One graph for money and the people who touch it.

---

## 1. Problem Statement

### The blind spot inside every bank

Modern banks operate two separate watchtowers:

- **Fraud / transaction-monitoring teams** watch money flows — transfers, amounts, frequencies, destinations.
- **HR / security / access-management teams** watch people — who was granted access to what, when, and whether it was normal.

These live in different systems (core banking vs. Active Directory/IAM/HRIS), owned by different teams, that rarely join their data. **Insider financial fraud lives exactly in the gap between them**: access granted on Monday, money gone by Friday. Each team sees half an innocent picture; nobody sees the whole guilty one.

### Why this matters (real stakes)

- The 2018 Punjab National Bank fraud (~$2 billion) was insider access abuse: bank employees issued fraudulent SWIFT guarantees (LoUs) bypassing core-banking controls. No break-in — legitimate internal access, used illegitimately.
- RBI fraud reporting consistently shows most large-value bank frauds involve insider collusion or control gaps (dormant-account siphoning, maker-checker violations, backdated entries).
- Employees never need customer passwords or OTPs. They operate internal terminals connected directly to core banking — viewing accounts, initiating transfers, approving requests is their job. Fraud is using that authorized access for an unauthorized purpose.

### Who feels the pain

Financial-crime investigators, compliance officers, fraud analysts, internal security teams, and risk teams — all of whom today reconstruct cross-domain cases manually across disconnected tools.

---

## 2. Solution Overview

**FraudSight fuses employee/access activity and financial transactions into a single investigation graph**, then runs transparent graph-pattern detectors over it. Every alert carries:

1. The **exact evidence subgraph** (people, accounts, transactions involved — nothing else),
2. A **plain-language explanation** grounded only in that evidence,
3. A **transparent risk level** derived from which detectors fired and their confidence — never an opaque score,
4. A full **case workflow**: assignment, status tracking, evidence export, and a two-sided **employee notice & response** process.

A live **Red Team Simulator** lets anyone inject a synthetic attack and watch detection happen in seconds — followed by an animated **attack replay** that reconstructs the crime step by step.

---

## 3. System Architecture

```
Transaction sources (CBS / UPI / SWIFT logs) ─┐
                                              ├─► Fusion Graph ─► Detectors ─► Alerts + Evidence
HR / IAM / access logs (AD, HRIS, SIEM) ──────┘                         │
                                                                        ▼
                                   Investigator UI ◄── Cases ◄── Notices ◄── Employee inbox
```

- **Backend:** Python + FastAPI, NetworkX for graph algorithms, in-memory store (SQLite-ready schema).
- **Frontend:** Single self-contained page (no CDN, no build step, works fully offline); visualization library vendored locally; charts hand-drawn SVG.
- **LLM use:** Optional narrative generation via Anthropic API, strictly grounded in evidence fields, with a template fallback. The system never depends on the LLM to detect anything.

---

## 4. Detection Engine

Four independent graph detectors (plus cross-domain fusion when they converge):

| Detector | Pattern | Method |
|---|---|---|
| Circular transfer | Money looping A→B→C→A (layering) | Bounded DFS cycle detection, ≤5 nodes, time-windowed |
| Structuring | Split transfers under reporting threshold | Same-pair clustering: ≥3 sub-threshold parts summing above threshold in 48h |
| Access anomaly | Access change → large transfer | Escalation-to-transfer gap analysis (72h high / 120h medium confidence) |
| Hub shift | Sudden fan-out | Distinct-counterparty burst detection (7d high / 10.5d medium, stricter bar) |

**Graduated confidence, not binary cutoffs.** Each finding carries high/medium/low confidence based on how closely it matches the textbook pattern (cycle length, time gaps, fan-out size). Out-of-window variants still fire at reduced confidence instead of silently missing.

**Transparent risk mapping.** Critical/High requires at least one high-confidence hit; medium/low-only evidence caps at Medium — and the reason string states exactly why (e.g. *"capped at Medium: all medium confidence"*).

**Measured performance (seeded demo dataset, ~950 transactions, 52 labeled frauds):**
- Known-pattern accuracy **98.8%**, false-positive rate **~1.2%**, recall **100%**
- Adversarial stress test (patterns deliberately outside tuned parameters): **13/18 = 72.2%** caught; the 5 misses are documented-correct behavior (definitional boundaries), reported alongside — not hidden.

---

## 5. Explainability Layer

Explainability is the product's core claim, implemented four ways:

1. **Jargon buster** — every technical term (structuring, layering, confidence…) defines itself on hover/click, everywhere in the app.
2. **Story summary** — each alert opens with a plain-language narrative paragraph generated strictly from evidence fields.
3. **Why-this-level box** — counterfactual transparency: what the verdict is *and what would change it* ("a second independent detector would escalate this to Critical").
4. **Per-detector highlight** — isolate what each detector fired on; everything else fades. Converging patterns on shared entities become visible in one click.

Supporting: confidence badges on every finding, key-risk-factor tags, full event timelines, and per-detector contribution lists on cases.

---

## 6. Investigation Workflow (both sides)

- **Alert queue → investigation workspace** with filters, triage, and full evidence review.
- **Cases**: assignment, status (Open → Investigating → Resolved), investigator notes, JSON/print reports, detector-contribution breakdowns.
- **Watchlist verdicts**: per-person findings (Suspect / Guilty / Cleared) recorded from any case's Linked People card; everyone Guilty collects on a dedicated Watchlist.
- **Graph Explorer**: zoom out from one case to 1,000+ entities — search, focus mode, subgraph export.

---

## 7. Red Team Simulator & Attack Replay

Three scenario templates (financial fraud / insider threat / combined), live staged timeline (injecting → analyzing → detected in measured milliseconds), matched-alert panel, and the signature feature: **attack replay** — the detected crime reconstructed event-by-event on the graph with timestamped narration. Detection proves engineering; replay proves understanding.

---

## 8. Data & Methodology (honest)

- **Transactions:** PaySim-calibrated generator (same schema and fraud behavior as the public PaySim set); a real `data/PS_*.csv` file is auto-detected and sampled instead when present.
- **HR/access layer:** synthetic by necessity — labeled insider-access-fraud data is not published anywhere. Generated with restraint (90%+ ordinary activity) so detectors earn their accuracy.
- **Identities:** realistic demo names/accounts; recent rolling dates.
- No black-box model anywhere in the detection path — by design, so every alert is defensible to a regulator.

---

## 9. Uniqueness — Why This Wins

1. **The fusion is the product.** Most fraud demos watch money *or* people. FraudSight's core detection (access-then-transfer) is literally uncomputable without both — the PNB pattern, not a toy.
2. **Explainability as architecture, not copy.** Four independent mechanisms (evidence subgraphs, counterfactual risk box, confidence tiers, grounded narratives) instead of one "explanation panel" checkbox.
3. **Adversarial honesty.** A permanent stress test that attacks outside tuned parameters, with misses documented. Judges trust numbers that admit weakness.
4. **Two-sided justice.** The employee inbox + gated notice workflow is something essentially no hackathon fraud project builds — it turns a detection demo into a complete compliance story.
5. **Live provability.** Red-team injection + attack replay means judges don't take our word for anything; they attack it themselves.
6. **Offline, self-contained, deployable-shaped.** Single file frontend, vendored libraries, in-perimeter design story (data-localization compatible, SSO-ready role model).

---

## 10. Future Scope (~50% runway)

1. **Real-time streaming** — score transactions as they clear; alert before settlement, not after.
2. **Real connectors** — core banking feeds, Active Directory/IAM, HRIS; graph builds itself from systems banks already run, deployed inside their perimeter.
3. **Hybrid intelligence** — transparent rules stay the auditable base; anomaly scoring layers on top for unknown-unknowns.
4. **Compliance finish line** — one-click SAR drafts, filing-deadline SLA timers, multi-investigator collaboration with audit trails, case-law search across past investigations.
5. **Scale** — distributed graph store, per-subgraph parallel detectors, live detector-health monitoring (per-detector FPR tracking already exists as the foundation).

---

## 11. Quickstart

```powershell
pip install -r requirements.txt
uvicorn backend.app:app --reload
# open http://127.0.0.1:8000
```

Data bootstraps automatically. Optional: set `ANTHROPIC_API_KEY` for live LLM narratives (grounded template fallback otherwise). Rebuild the bundled frontend after editing sources with `python build_frontend.py`.

**Repo:** github.com/Priyanshaur/fraudsight
