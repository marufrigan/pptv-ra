"""Monte Carlo evaluation of trust-gated BFT consensus for PPTV-RA.
(1) Commit latency / throughput versus validators, block size and network, using the measured
    per-transaction verification cost and size from the Rust prototype.
(2) Trust dynamics: time to exclude lazy, equivocating, disclosure-violating and crashed
    validators; false exclusions of honest nodes; Byzantine share of the eligible set.
(3) Quorum safety: conflicting-commit probability for simple-majority versus 2f+1 quorums.
"""
import json, math, sys
import numpy as np

cb = json.load(open(sys.argv[1]))
OUT = sys.argv[2]
rng = np.random.default_rng(7)

V_PPTV = cb["verify_ms"]["mean"] / 1e3          # s per tx per core
B_PPTV = cb["tx_bytes"]["mean"]
V_BASE = cb["baseline_ed25519"]["verify_ms"]["mean"] / 1e3
B_BASE = 150.0                                  # plaintext tx: ids, amount, timestamp, nonce, signature
CORES = 8                                       # validator server assumption
NETS = {"LAN": dict(mu=0.0005, sd=0.0002, bw=1e9 / 8), "WAN": dict(mu=0.040, sd=0.010, bw=100e6 / 8)}

def delays(net, size, k):
    d = rng.normal(net["mu"], net["sd"], size=size); d = np.clip(d, net["mu"] * 0.2, None); return d

def round_latency(n, B, net, v_tx, b_tx, trials=2000):
    f = (n - 1) // 3; q = 2 * f + 1
    blk = B * b_tx
    # proposal: leader sends block to all; each validator receives after delay + transmission
    tx_time = blk / net["bw"]
    recv = delays(net, (trials, n), 0) + tx_time
    verify = B * v_tx / CORES
    ready = recv + verify                                   # time each validator can send PREPARE
    # PREPARE all-to-all: validator j has prepared when q prepares arrived
    def phase(start):
        arr = start[:, None, :] + delays(net, (trials, n, n), 0)    # arr[t, recv, send]
        return np.sort(arr, axis=2)[:, :, q - 1]
    prepared = phase(ready)
    committed = phase(prepared)
    lat = np.sort(committed, axis=1)[:, q - 1]              # block final when q validators committed
    return lat

def consensus_grid():
    res = []
    for net_name, net in NETS.items():
        for n in [4, 7, 10, 13, 16, 22]:
            for B in [100, 500, 1000]:
                for name, v, b in [("PPTV-RA", V_PPTV, B_PPTV), ("Plaintext", V_BASE, B_BASE)]:
                    lat = round_latency(n, B, net, v, b, trials=400 if n > 13 else 1000)
                    res.append(dict(net=net_name, n=n, B=B, scheme=name, lat_ms=float(lat.mean() * 1e3),
                                    lat_p95_ms=float(np.percentile(lat, 95) * 1e3), tps=float(B / lat.mean())))
    return res

# ---------------- trust dynamics ----------------
W = dict(acc=0.35, lat=0.15, cons=0.20, priv=0.30)
ALPHA = 0.9; TH = 0.60; QUAR = 50

def trust_sim(rounds=600, n=16, canary=0.02, reps=50):
    types = ["H"] * 10 + ["LAZY", "EQUIV", "LEAK", "CRASH", "FALSEACC", "FALSEACC"]
    out = {t: [] for t in set(types)}; false_excl = 0; byz_share = []; byz_share_static = []; unsafe_g = []; unsafe_s = []
    for rep in range(reps):
        tau = np.full(n, 0.8); quar = np.zeros(n, int); excluded_at = [None] * n
        for r in range(rounds):
            elig = (tau >= TH) & (quar == 0)
            bad = np.array([t not in ("H",) for t in types])
            byz_share.append(float((elig & bad).sum() / max(elig.sum(), 1)))
            byz_share_static.append(float(bad.sum() / n))
            ne = int(elig.sum()); unsafe_g.append(int((elig & bad).sum()) > (ne - 1) // 3); unsafe_s.append(int(bad.sum()) > (n - 1) // 3)
            is_canary = rng.random() < canary
            for i, t in enumerate(types):
                if quar[i] > 0: quar[i] -= 1
                acc = lat = cons = priv = 1.0; proven = False
                lat = float(np.clip(rng.normal(0.85, 0.05), 0, 1))
                if t == "LAZY" and is_canary: acc = 0.0; proven = True          # signed vote for invalid canary block
                if t == "EQUIV" and rng.random() < 0.05: cons = 0.0; proven = True  # two signed votes, same height
                if t == "LEAK" and rng.random() < 0.02: priv = 0.0; proven = True   # share released with no logged request
                if t == "CRASH" and rng.random() < 0.6: cons = acc = lat = 0.0                 # missed vote
                if t == "FALSEACC" and rng.random() < 0.05: priv = 0.0; proven = True # submitted evidence failed verification
                s = W["acc"] * acc + W["lat"] * lat + W["cons"] * cons + W["priv"] * priv
                if quar[i] == 0: tau[i] = ALPHA * tau[i] + (1 - ALPHA) * s     # frozen while quarantined
                if proven: tau[i] = min(tau[i], TH - 0.05); quar[i] = QUAR
                if excluded_at[i] is None and (tau[i] < TH or quar[i] > 0): excluded_at[i] = r
        for i, t in enumerate(types):
            if t == "H":
                false_excl += excluded_at[i] is not None
            else:
                out[t].append(excluded_at[i] if excluded_at[i] is not None else rounds)
    summ = {t: dict(mean=float(np.mean(v)), p95=float(np.percentile(v, 95)), excluded_frac=float(np.mean(np.array(v) < rounds)))
            for t, v in out.items() if t != "H"}
    return dict(exclusion_round=summ, honest_false_exclusions=int(false_excl), honest_runs=reps * 10,
                byz_share_eligible_mean=float(np.mean(byz_share)), byz_share_static=float(np.mean(byz_share_static)),
                byz_share_eligible_last100=float(np.mean(byz_share[-100 * 1:])), canary=canary, rounds=rounds,
                unsafe_rounds_gated=float(np.mean(unsafe_g)), unsafe_rounds_static=float(np.mean(unsafe_s)))

def trust_trace(rounds=300, canary=0.02):
    """One run, recording tau per round for one node of each type (for plotting)."""
    types = ["H", "LAZY", "EQUIV", "LEAK", "CRASH"]; n = len(types)
    tau = np.full(n, 0.8); quar = np.zeros(n, int); trace = {t: [] for t in types}
    r2 = np.random.default_rng(11)
    for r in range(rounds):
        is_canary = r2.random() < canary
        for i, t in enumerate(types):
            if quar[i] > 0: quar[i] -= 1
            acc = cons = priv = 1.0; proven = False; lat = float(np.clip(r2.normal(0.85, 0.05), 0, 1))
            if t == "LAZY" and is_canary: acc = 0.0; proven = True
            if t == "EQUIV" and r2.random() < 0.05: cons = 0.0; proven = True
            if t == "LEAK" and r2.random() < 0.02: priv = 0.0; proven = True
            if t == "CRASH" and r2.random() < 0.6: cons = acc = lat = 0.0
            s = W["acc"] * acc + W["lat"] * lat + W["cons"] * cons + W["priv"] * priv
            if quar[i] == 0: tau[i] = ALPHA * tau[i] + (1 - ALPHA) * s
            if proven: tau[i] = min(tau[i], TH - 0.05); quar[i] = QUAR
            trace[t].append(float(tau[i]))
    return trace

def quorum_safety(trials=200000):
    """Equivocating Byzantine nodes vote for two conflicting blocks; honest nodes are split by an
    adversarial partition. Conflict occurs if both blocks reach the quorum."""
    res = []
    for n in [4, 7, 10, 13, 16]:
        for f in range(0, n // 2 + 1):
            h = n - f
            for qname, q in [("majority", n // 2 + 1), ("2f+1 (BFT)", 2 * ((n - 1) // 3) + 1)]:
                split = rng.integers(0, h + 1, size=trials)          # honest votes for block X
                conflict = ((split + f) >= q) & ((h - split + f) >= q)
                worst = any((s + f >= q) and (h - s + f >= q) for s in range(h + 1))
                res.append(dict(n=n, f=f, quorum=qname, q=q, p_conflict_random_split=float(conflict.mean()), worst_case_conflict=bool(worst)))
    return res

res = dict(inputs=dict(v_pptv_ms=V_PPTV * 1e3, bytes_pptv=B_PPTV, v_base_ms=V_BASE * 1e3, bytes_base=B_BASE, cores=CORES, nets=NETS),
           consensus=consensus_grid(), trust=trust_sim(), trust_trace=trust_trace(), quorum=quorum_safety(),
           weights=W, alpha=ALPHA, threshold=TH, quarantine=QUAR)
json.dump(res, open(OUT, "w"), indent=1)
for r in res["consensus"]:
    if r["B"] == 500: print(r)
print(json.dumps(res["trust"], indent=1))
for r in res["quorum"]:
    if r["n"] == 10: print(r)
