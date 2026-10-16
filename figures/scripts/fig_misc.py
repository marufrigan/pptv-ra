from vstyle import *
import json
cb = json.load(open("../../results/crypto_bench.json"))

# ======================= Fig. 3: transaction record layout =======================
fig, ax = canvas(6.3, 1.62)
fields = [("Header", 16, "from, to, nonce"), (r"$C_{lo}, C_{hi}$", 64, "limb\ncommitments"), (r"$D_S, D_R, D_A$", 192, "6 decryption\nhandles"),
          (r"$\pi_{\mathrm{val}}$", 384, "2 validity\nproofs"), (r"$\hat C_{lo}, \hat C_{hi}$", 64, "balance\ncommitments"),
          (r"$\pi_{\mathrm{bal}}$", 288, "balance\nequality proof"), (r"$\pi_{\mathrm{rng}}$", 736, "aggregated range\nproof (4 x 32 bit)"), (r"$\sigma$", 64, "Ed25519")]
total = sum(f[1] for f in fields); assert total == int(cb["tx_bytes"]["mean"])
x0, W, y, h = 0.15, 6.0, 0.45, 0.34
fills = ["white", G1, G2, G1, G2, G1, G2, G1]
xs = []
x = x0
for (name, b, desc), fc in zip(fields, fills):
    w = max(W * b / total, 0.62)
    xs.append((x, w))
    x += w
scale = W / (x - x0)
x = x0; pos = []
for (name, b, desc), fc in zip(fields, fills):
    w = max(W * b / total, 0.62) * scale
    rect(ax, x, y, w, h, fc=fc, lw=0.7, z=3)
    text(ax, x + w / 2, y + h / 2, name, size=6.4)
    text(ax, x + w / 2, y - 0.1, f"{b} B", size=5.6, weight="bold")
    text(ax, x + w / 2, y + h + 0.17, desc, size=5.3)
    pos.append((x, w)); x += w
text(ax, x0, 0.12, f"PPTV-RA transaction record: {total:,} bytes (plaintext baseline: 150 bytes)", size=6.6, weight="bold", ha="left")
def brace(xa, xb, yb, s):
    ax.plot([xa, xa, xb, xb], [yb - 0.05, yb, yb, yb - 0.05], color=K, lw=0.6, zorder=4)
    ax.plot([(xa + xb) / 2] * 2, [yb, yb + 0.06], color=K, lw=0.6, zorder=4)
    text(ax, (xa + xb) / 2, yb + 0.15, s, size=5.8, style="italic")
yb = y + h + 0.42
brace(pos[1][0] + 0.02, pos[1][0] + pos[1][1] + pos[2][1] - 0.02, yb, r"receiver uses $C$, $D_R$; committee uses $D_A$")
brace(pos[3][0] + 0.02, pos[7][0] + pos[7][1] - 0.02, yb, "checked by every validator in Algorithm 2 (no plaintext)")
save(fig, "fig3_record")

# ======================= Fig. 5: trust state machine =======================
fig, ax = canvas(6.3, 2.75)
def state(x, y, w, h, t, sub):
    rect(ax, x, y, w, h, fc=G1, lw=0.8, round_=0.1, z=3)
    text(ax, x + w / 2, y + h * 0.38, t, size=6.8, weight="bold"); text(ax, x + w / 2, y + h * 0.68, sub, size=5.8)
ax.add_patch(Circle((0.22, 0.62), 0.06, fc=K, zorder=4)); arrow(ax, [(0.28, 0.62), (0.5, 0.62)]); text(ax, 0.38, 0.5, "admit", size=5.6)
state(0.5, 0.4, 1.15, 0.44, "Eligible", r"$\tau_n \geq \theta$, votes count")
state(2.55, 0.4, 1.15, 0.44, "Ineligible", r"$\tau_n < \theta$, observer only")
state(0.5, 1.75, 1.15, 0.44, "Quarantined", r"$K$ rounds, $\tau_n \leq \theta-\epsilon$")
state(2.55, 1.75, 1.15, 0.44, "Revoked", "membership removed")
arrow(ax, [(1.65, 0.52), (2.55, 0.52)]); text(ax, 2.1, 0.44, r"score decay, $\tau_n < \theta$", size=5.6)
arrow(ax, [(2.55, 0.72), (1.65, 0.72)]); text(ax, 2.1, 0.8, r"recovery, $\tau_n \geq \theta$", size=5.6)
arrow(ax, [(0.9, 0.84), (0.9, 1.75)]); text(ax, 0.86, 1.3, "proven\nevidence\nE1 to E5", size=5.6, ha="right")
arrow(ax, [(3.12, 0.84), (3.12, 1.25), (1.45, 1.25), (1.45, 1.75)]); text(ax, 2.3, 1.17, "proven evidence while ineligible", size=5.6)
arrow(ax, [(1.25, 1.75), (1.25, 1.5), (2.75, 1.5), (2.75, 0.84)], ls=(0, (3, 1.5))); text(ax, 2.3, 1.58, r"$K$ rounds elapsed", size=5.6, style="italic")
arrow(ax, [(1.65, 1.97), (2.55, 1.97)]); text(ax, 2.1, 1.89, r"3rd offence in $W$ rounds", size=5.6); text(ax, 2.1, 2.08, "(governance vote)", size=5.4, style="italic")
ax.add_patch(Circle((3.12, 2.45), 0.07, fc="white", ec=K, lw=0.8, zorder=4)); ax.add_patch(Circle((3.12, 2.45), 0.04, fc=K, zorder=5))
arrow(ax, [(3.12, 2.19), (3.12, 2.38)])
# evidence table
tx0, ty0 = 3.95, 0.22; cw = [0.32, 1.1, 0.88]; rh = 0.3
rows = [("Id", "Evidence object", "Check by any node"),
        ("E1", "two signed votes, same height", "signatures, hashes differ"),
        ("E2", "signed vote on invalid block", "re-run Algorithm 2"),
        ("E3", "signed share, no ReqLogged", "log lookup, DLEQ"),
        ("E4", "ReqLogged past deadline", "absence of share receipt"),
        ("E5", "accusation that fails E1 to E4", "re-run the check")]
for i, r in enumerate(rows):
    xx = tx0
    for j, wd in enumerate(cw):
        rect(ax, xx, ty0 + i * rh, wd, rh, fc=G2 if i == 0 else "white", lw=0.5, z=3)
        text(ax, xx + wd / 2, ty0 + i * rh + rh / 2, r[j], size=5.4, weight="bold" if i == 0 else "normal")
        xx += wd
text(ax, tx0 + sum(cw) / 2, ty0 + 6 * rh + 0.14, "Evidence is self-verifying: it carries the offender's signature", size=5.6, style="italic")
save(fig, "fig5_trust_fsm")

# ======================= Fig. 6: threat model =======================
fig, ax = canvas(6.3, 3.45)
def zone(x, y, w, h, t):
    rect(ax, x, y, w, h, fc="none", lw=0.9, ls=(0, (6, 3)), z=1); text(ax, x + 0.06, y + 0.11, t, size=6.2, weight="bold", ha="left")
def comp(x, y, w, h, t):
    rect(ax, x, y, w, h, fc=G1, lw=0.7, round_=0.04, z=3); text(ax, x + w / 2, y + h / 2, t, size=6.2, weight="bold")
def adv(cx, cy, t):
    r = 0.16; ang = np.linspace(0, 2 * np.pi, 9)[:-1] + np.pi / 8
    ax.add_patch(Polygon(np.c_[cx + r * np.cos(ang), cy + r * np.sin(ang)], closed=True, fc=K, ec=K, zorder=6))
    text(ax, cx, cy, t, size=6.2, weight="bold", color="white", z=7)
zone(0.1, 0.6, 1.7, 1.3, "Bank domain"); zone(2.05, 0.6, 2.2, 1.6, "Validator network (permissioned)")
zone(4.5, 0.6, 1.7, 1.3, "Regulator domain"); zone(2.05, 2.45, 2.2, 0.9, "Replicated ledger")
comp(0.3, 0.85, 1.3, 0.34, "Receiver wallet"); comp(0.3, 1.32, 1.3, 0.38, "Sender wallet / prover")
comp(2.3, 0.92, 1.7, 0.38, "Validators / proposer"); comp(2.3, 1.55, 1.7, 0.34, "Trust engine")
comp(4.7, 0.85, 1.3, 0.34, "Requester"); comp(4.7, 1.32, 1.3, 0.38, "Key-share holders")
comp(2.3, 2.72, 1.7, 0.4, "Blocks, state, audit log")
arrow(ax, [(1.6, 1.51), (1.92, 1.51), (1.92, 1.11), (2.3, 1.11)]); text(ax, 1.92, 1.62, "TLS", size=5.4)
arrow(ax, [(4.0, 1.11), (4.38, 1.11), (4.38, 1.51), (4.7, 1.51)], both=True); text(ax, 4.38, 1.62, "TLS", size=5.4)
arrow(ax, [(3.15, 1.3), (3.15, 1.55)]); arrow(ax, [(3.15, 1.89), (3.15, 2.72)])
for cx, cy, t, tgt in [(1.92, 0.27, "A5", (1.92, 1.07)), (2.62, 0.27, "A1", (2.62, 0.92)), (3.15, 0.27, "A3", (3.15, 0.92)),
                       (3.68, 0.27, "A4", (3.68, 0.92)), (5.35, 0.27, "A6", (5.35, 0.85)), (0.95, 2.18, "A2", (0.95, 1.7)),
                       (5.35, 2.18, "A7", (5.35, 1.7)), (4.85, 2.92, "A8", (4.0, 2.92))]:
    adv(cx, cy, t)
    if abs(tgt[0] - cx) < 1e-6: arrow(ax, [(cx, cy + (0.16 if tgt[1] > cy else -0.16)), tgt], lw=0.9, ls=(0, (2, 1.2)))
    else: arrow(ax, [(cx - 0.16, cy), tgt], lw=0.9, ls=(0, (2, 1.2)))
legend = ["A1 curious validator", "A2 malicious sender", "A3 malicious validator / proposer", "A4 coalition below n/3",
          "A5 network attacker", "A6 overreaching regulator", "A7 key-share compromise below t", "A8 traffic analysis"]
rect(ax, 0.1, 2.45, 1.75, 0.9, fc="white", lw=0.6, z=2)
for k, l in enumerate(legend): text(ax, 0.18, 2.55 + k * 0.1, l, size=5.4, ha="left")
save(fig, "fig6_threats")
print("ok")
