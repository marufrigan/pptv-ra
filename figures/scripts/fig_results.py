import json, numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams.update({"font.family": "Liberation Sans", "font.size": 7, "axes.linewidth": 0.6, "xtick.major.width": 0.6,
                     "ytick.major.width": 0.6, "legend.frameon": True, "legend.edgecolor": "black", "legend.fancybox": False,
                     "mathtext.fontset": "custom", "mathtext.rm": "Liberation Sans", "mathtext.it": "Liberation Sans:italic"})
cb = json.load(open("../../results/crypto_bench.json")); sm = json.load(open("../../results/sim.json"))
F = "../"

# ---------- Fig. 7: cryptographic costs ----------
fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(6.3, 2.05), dpi=600, gridspec_kw={"width_ratios": [1.45, 1.0, 1.0]})
ops = [("Prove Tx", cb["create_ms"]), ("Verify Tx", cb["verify_ms"]), ("Apply", cb["apply_ms"]), ("Rx decrypt", cb["receiver_decrypt_ms"]),
       ("Share + DLEQ", cb["partial_decrypt_ms"]), ("Combine 3/5", cb["combine_3of5_ms"]), ("Ed25519 sign", cb["baseline_ed25519"]["sign_ms"]), ("Ed25519 verify", cb["baseline_ed25519"]["verify_ms"])]
y = np.arange(len(ops))
a1.barh(y, [o[1]["mean"] for o in ops], color=["#595959"] * 6 + ["white"] * 2, edgecolor="black", lw=0.6, height=0.65)
a1.errorbar([o[1]["mean"] for o in ops], y, xerr=[[0] * len(ops), [o[1]["p95"] - o[1]["mean"] for o in ops]], fmt="none", ecolor="black", lw=0.6, capsize=1.5)
for yy, o in zip(y, ops): a1.text(max(o[1]["p95"], o[1]["mean"]) * 1.35, yy, f"{o[1]['mean']:.2f}" if o[1]['mean'] >= 0.1 else f"{o[1]['mean']:.3f}", va="center", fontsize=5.6)
a1.set_xscale("log"); a1.set_yticks(y); a1.set_yticklabels([o[0] for o in ops], fontsize=6.2); a1.invert_yaxis(); a1.set_xlim(0.01, 400)
a1.set_xlabel("Time per operation (ms, log scale)"); a1.set_title("(a) Operation cost (mean, whisker p95)", fontsize=7)
bd = cb["verify_breakdown_ms"]; parts = [("Range", bd["range"]), ("Validity", bd["validity"]), ("Balance", bd["balance"]), ("Signature", bd["signature"])]
left = 0; hatches = ["", "////", "....", "xxxx"]; fills = ["#595959", "white", "white", "white"]
for (n, v), h, fc in zip(parts, hatches, fills):
    a2.bar(0, v, bottom=left, color=fc, hatch=h, edgecolor="black", lw=0.6, width=0.55, label=f"{n} {v:.2f} ms"); left += v
a2.set_xlim(-0.6, 1.6); a2.set_xticks([]); a2.set_ylabel("Verification time (ms)"); a2.legend(fontsize=5.6, loc="upper right", handlelength=1.4)
a2.set_title("(b) Verify breakdown", fontsize=7)
thr = cb["disclosure_by_threshold"]; ts = [d["t"] for d in thr]; ms = [d["ms"]["mean"] for d in thr]; sd = [d["ms"]["sd"] for d in thr]
a3.errorbar(ts, ms, yerr=sd, fmt="-o", color="black", ms=3, mfc="white", lw=0.8, capsize=2)
a3.set_xticks(ts); a3.set_xticklabels([f"{d['t']}/{d['n']}" for d in thr]); a3.set_xlabel("Threshold t / committee n"); a3.set_ylabel("Disclosure time (ms)")
a3.set_ylim(0, max(ms) * 1.4); a3.set_title("(c) Logged disclosure", fontsize=7)
for a in (a1, a2, a3): a.tick_params(labelsize=6.2)
fig.tight_layout(pad=0.4, w_pad=1.0); fig.savefig(F + "fig7_crypto.png", dpi=600); plt.close(fig)

# ---------- Fig. 8: consensus latency ----------
fig, axs = plt.subplots(1, 2, figsize=(6.3, 2.15), dpi=600)
C = sm["consensus"]; marks = {100: "o", 500: "s", 1000: "^"}
for a, net in zip(axs, ["LAN", "WAN"]):
    for B in [100, 500, 1000]:
        for sch, ls, mfc in [("PPTV-RA", "-", "black"), ("Plaintext", (0, (3, 1.5)), "white")]:
            rows = sorted([r for r in C if r["net"] == net and r["B"] == B and r["scheme"] == sch], key=lambda r: r["n"])
            a.plot([r["n"] for r in rows], [r["lat_ms"] for r in rows], ls=ls, marker=marks[B], color="black", mfc=mfc, ms=3, lw=0.8,
                   label=f"{sch}, B={B}")
    a.set_yscale("log"); a.set_xlabel(r"Validators $|N'|$"); a.set_ylabel("Commit latency (ms, log)"); a.set_xticks([4, 7, 10, 13, 16, 22])
    a.set_title(f"({'a' if net == 'LAN' else 'b'}) {net}: {'0.5 ms, 1 Gbit/s' if net == 'LAN' else '40 ms, 100 Mbit/s'}", fontsize=7)
    a.tick_params(labelsize=6.2); a.grid(axis="y", lw=0.3, ls=":")
    from matplotlib.ticker import ScalarFormatter, NullFormatter
    a.yaxis.set_major_formatter(ScalarFormatter()); a.yaxis.set_minor_formatter(NullFormatter())
axs[1].legend(fontsize=5.4, ncol=2, loc="upper center", bbox_to_anchor=(-0.12, -0.24), handlelength=2.4, columnspacing=1.0)
fig.tight_layout(pad=0.4, w_pad=1.2); fig.subplots_adjust(bottom=0.33); fig.savefig(F + "fig8_consensus.png", dpi=600); plt.close(fig)

# ---------- Fig. 9: trust dynamics ----------
fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.3, 2.0), dpi=600, gridspec_kw={"width_ratios": [1.5, 1]})
tr = sm["trust_trace"]; sty = {"H": ("-", 1.1), "LAZY": ((0, (4, 1.5)), 0.9), "EQUIV": ((0, (1, 1)), 0.9), "LEAK": ((0, (5, 1.5, 1, 1.5)), 0.9), "CRASH": ((0, (2, 2)), 0.7)}
names = {"H": "honest", "LAZY": "lazy", "EQUIV": "equivocating", "LEAK": "unlogged share", "CRASH": "crash (60%)"}
for k, (ls, lw) in sty.items(): a1.plot(tr[k], ls=ls, lw=lw, color="black", label=names[k])
a1.axhline(sm["threshold"], color="black", lw=0.5); a1.text(302, sm["threshold"], r"$\theta$", va="center", fontsize=7)
a1.set_xlabel("Consensus round"); a1.set_ylabel(r"Trust score $\tau_n$"); a1.set_ylim(0.3, 1.0); a1.set_xlim(0, 300)
a1.legend(fontsize=5.4, ncol=3, loc="lower right", handlelength=2.4); a1.set_title("(a) Trust trajectories (one run)", fontsize=7)
ex = sm["trust"]["exclusion_round"]; order = ["EQUIV", "FALSEACC", "CRASH", "LEAK", "LAZY"]
lab = {"EQUIV": "equivocating", "FALSEACC": "false accuser", "CRASH": "crash", "LEAK": "unlogged share", "LAZY": "lazy"}
yy = np.arange(len(order))
a2.barh(yy, [ex[k]["mean"] for k in order], color="#A6A6A6", edgecolor="black", lw=0.6, height=0.6)
a2.errorbar([ex[k]["mean"] for k in order], yy, xerr=[[0] * 5, [ex[k]["p95"] - ex[k]["mean"] for k in order]], fmt="none", ecolor="black", lw=0.6, capsize=1.5)
a2.set_yticks(yy); a2.set_yticklabels([lab[k] for k in order], fontsize=6.2); a2.invert_yaxis()
a2.set_xlabel("Rounds to first exclusion (mean, p95)"); a2.set_title("(b) Detection (50 runs, canary 2%)", fontsize=7)
for a in (a1, a2): a.tick_params(labelsize=6.2)
fig.tight_layout(pad=0.4, w_pad=1.0); fig.savefig(F + "fig9_trust.png", dpi=600); plt.close(fig)
print("ok")
