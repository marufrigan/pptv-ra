from vstyle import *

def lifelines(ax, xs, names, top, bottom, w=0.92):
    for x, n in zip(xs, names):
        rect(ax, x - w / 2, top, w, 0.32, fc=G2, lw=0.7, z=3)
        text(ax, x, top + 0.16, n, size=6.3, weight="bold")
        ax.plot([x, x], [top + 0.32, bottom], color=K, lw=0.5, ls=(0, (4, 2)), zorder=1)

def act(ax, x, y0, y1, w=0.07):
    rect(ax, x - w / 2, y0, w, y1 - y0, fc="white", lw=0.6, z=3.5)

def msg(ax, x0, x1, y, s, num=None, dashed=False, above=True, size=5.8):
    off = 0.035 if x1 > x0 else -0.035
    arrow(ax, [(x0 + off, y), (x1 - off, y)], ls=(0, (3, 1.5)) if dashed else "-", lw=0.6)
    t = (f"{num}: " if num else "") + s
    text(ax, (x0 + x1) / 2, y - 0.07 if above else y + 0.07, t, size=size)

def selfmsg(ax, x, y, s, num=None, h=0.14, size=5.8):
    pts = [(x + 0.035, y), (x + 0.22, y), (x + 0.22, y + h), (x + 0.035, y + h)]
    arrow(ax, pts, lw=0.6)
    text(ax, x + 0.27, y + h / 2, (f"{num}: " if num else "") + s, size=size, ha="left")

def frame(ax, x, y, w, h, kind, guard=None, divs=()):
    rect(ax, x, y, w, h, fc="none", lw=0.7, z=2.5)
    pw = 0.07 * len(kind) + 0.14
    ax.add_patch(Polygon([(x, y), (x + pw, y), (x + pw, y + 0.1), (x + pw - 0.05, y + 0.16), (x, y + 0.16)], closed=True, fc=G1, ec=K, lw=0.6, zorder=2.6))
    text(ax, x + 0.05, y + 0.08, kind, size=6, weight="bold", ha="left")
    if guard: text(ax, x + pw + 0.06, y + 0.09, guard, size=5.8, style="italic", ha="left")
    for dy, g in divs:
        ax.plot([x, x + w], [y + dy, y + dy], color=K, lw=0.6, ls=(0, (4, 2)), zorder=2.6)
        text(ax, x + 0.06, y + dy + 0.09, g, size=5.8, style="italic", ha="left")

# ======================= Fig. 2: transaction lifecycle =======================
fig, ax = canvas(6.3, 4.65)
X = [0.55, 1.62, 2.69, 3.76, 4.83, 5.82]
lifelines(ax, X, ["Sender bank S", r"Validator $i \in N^{\prime}$", "Proposer", "Ledger / contracts", "Receiver bank R", "Trust engine"], 0.05, 4.6)
S, V, P, L, R, T = X
act(ax, S, 0.5, 0.95); selfmsg(ax, S, 0.55, "build, sign Tx (Alg. 1)", 1)
msg(ax, S, V, 0.92, "broadcast Tx", 2)
act(ax, V, 0.92, 2.2); selfmsg(ax, V, 1.0, "Verify (Alg. 2)", 3)
frame(ax, 1.25, 1.22, 3.15, 0.66, "alt", "[Verify = True]", divs=[(0.38, "[Verify = False]")])
msg(ax, V, P, 1.5, "add to pool", 4)
msg(ax, V, T, 1.79, "reject, record sender event", "4′", dashed=True)
act(ax, P, 1.45, 2.05)
msg(ax, P, V, 2.0, "PRE-PREPARE(h, B, root)", 5)
frame(ax, 1.25, 2.12, 3.15, 0.86, "loop", "[until 2f+1 matching votes]")
selfmsg(ax, V, 2.33, "re-verify every proof in B", 6)
msg(ax, V, P, 2.66, "PREPARE(h, H(B))", 7)
msg(ax, V, P, 2.9, "COMMIT(h, H(B))", 8)
act(ax, V, 2.3, 3.3)
msg(ax, V, L, 3.18, "append B", 9)
act(ax, L, 3.18, 4.2)
selfmsg(ax, L, 3.27, r"$\mathrm{avail}_S \leftarrow \mathrm{avail}_S - (C, D_S)$", 10, size=5.6)
text(ax, L + 0.27, 3.51, r"$\mathrm{pending}_R \leftarrow \mathrm{pending}_R + (C, D_R)$", size=5.6, ha="left")
msg(ax, L, R, 3.72, "credit event", 11)
act(ax, R, 3.72, 4.25); selfmsg(ax, R, 3.8, "decrypt limbs (BSGS),", 12)
text(ax, R + 0.27, 4.04, "then rollover", size=5.6, ha="left")
msg(ax, L, T, 4.38, "signed votes of round h", 13, size=5.4)
act(ax, T, 4.38, 4.58)
save(fig, "fig2_lifecycle")

# ======================= Fig. 4: logged threshold disclosure =======================
fig, ax = canvas(6.3, 4.2)
X = [0.6, 1.85, 3.1, 4.4, 5.65]
lifelines(ax, X, ["Regulator (requester)", "Audit contract", "Ledger", "Key-share holder i", "Trust engine"], 0.05, 4.15, w=1.05)
Q, A, L, H, T = X
act(ax, Q, 0.5, 0.7)
msg(ax, Q, A, 0.62, r"Request($q$), $\sigma_{\mathrm{reg}}$", 1)
act(ax, A, 0.62, 1.95); selfmsg(ax, A, 0.7, "check role, purpose, quota", 2)
frame(ax, 0.2, 1.0, 5.0, 2.32, "alt", "[authorised]", divs=[(1.98, "[denied]")])
msg(ax, A, L, 1.38, "log ReqLogged(q)", 3)
msg(ax, L, H, 1.62, "event ReqLogged(q)", 4)
act(ax, H, 1.62, 2.6)
selfmsg(ax, H, 1.7, "check log entry exists", 5)
text(ax, H + 0.27, 1.94, r"$S_i = w_i D_A$, DLEQ proof", size=5.6, ha="left")
msg(ax, H, L, 2.2, "ShareReleased(q, i)", 6)
msg(ax, H, Q, 2.47, r"$S_i$ + DLEQ (encrypted to requester)", 7, dashed=True)
act(ax, Q, 2.47, 2.95)
selfmsg(ax, Q, 2.55, "verify t DLEQ proofs, Lagrange combine,", 8, size=5.5)
text(ax, Q + 0.27, 2.79, "BSGS, assert C = aG + rH", size=5.5, ha="left")
msg(ax, A, L, 3.23, "log RequestDenied(q)", "3′", dashed=True)
frame(ax, 0.2, 3.42, 6.02, 0.68, "opt", "[share without ReqLogged, or no share by deadline]")
msg(ax, L, T, 3.8, "evidence E3 / E4", 9)
act(ax, T, 3.8, 4.08)
msg(ax, T, H, 4.0, r"quarantine, update $\tau$", 10, dashed=True)
save(fig, "fig4_disclosure")
print("ok")
