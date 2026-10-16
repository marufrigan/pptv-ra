"""Visio-like drawing helpers: flat shapes, thin outlines, orthogonal connectors, Arial-metric font."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch, Ellipse, Polygon, Circle, FancyArrowPatch
import numpy as np

plt.rcParams.update({"font.family": "Liberation Sans", "font.size": 7, "mathtext.fontset": "custom",
                     "mathtext.rm": "Liberation Sans", "mathtext.it": "Liberation Sans:italic", "mathtext.bf": "Liberation Sans:bold"})
K = "#000000"; G1 = "#F2F2F2"; G2 = "#D9D9D9"; G3 = "#A6A6A6"; G4 = "#595959"

def canvas(w, h):
    fig = plt.figure(figsize=(w, h), dpi=600)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, w); ax.set_ylim(0, h); ax.axis("off"); ax.invert_yaxis()
    return fig, ax

def rect(ax, x, y, w, h, fc="white", lw=0.6, ls="-", round_=0.0, z=2, ec=K):
    if round_:
        p = FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={round_}", fc=fc, ec=ec, lw=lw, ls=ls, zorder=z)
    else:
        p = Rectangle((x, y), w, h, fc=fc, ec=ec, lw=lw, ls=ls, zorder=z)
    ax.add_patch(p); return p

def text(ax, x, y, s, size=7, weight="normal", style="normal", ha="center", va="center", z=6, color=K, rot=0, ls=1.15):
    ax.text(x, y, s, fontsize=size, weight=weight, style=style, ha=ha, va=va, zorder=z, color=color, rotation=rot, linespacing=ls)

def box(ax, x, y, w, h, title, lines=None, fc="white", tsize=7, lsize=6.2, round_=0.04, lw=0.6, ls="-"):
    rect(ax, x, y, w, h, fc=fc, round_=round_, lw=lw, ls=ls)
    th = tsize / 72 * 1.3; lh = lsize / 72 * 1.28
    n = len(lines) if lines else 0
    y0 = y + (h - th - n * lh) / 2
    text(ax, x + w / 2, y0 + th / 2, title, size=tsize, weight="bold")
    for i, l in enumerate(lines or []):
        text(ax, x + w / 2, y0 + th + lh * (i + 0.5), l, size=lsize)

def container(ax, x, y, w, h, title, fc=G1, hfc=G2, hh=0.2, tsize=7.2):
    rect(ax, x, y, w, h, fc=fc, lw=0.8, z=1)
    rect(ax, x, y, w, hh, fc=hfc, lw=0.8, z=1.5)
    text(ax, x + 0.08, y + hh / 2, title, size=tsize, weight="bold", ha="left")

def arrow(ax, pts, lw=0.7, ls="-", head=True, both=False, z=4, color=K):
    xs, ys = zip(*pts)
    ax.plot(xs, ys, color=color, lw=lw, ls=ls, zorder=z, solid_capstyle="butt", dash_capstyle="butt")
    def tip(p0, p1):
        v = np.array(p1) - np.array(p0); L = np.hypot(*v)
        if L == 0: return
        u = v / L; n = np.array([-u[1], u[0]]); hl, hw = 0.075, 0.032
        b = np.array(p1) - u * hl
        ax.add_patch(Polygon([p1, b + n * hw, b - n * hw], closed=True, fc=color, ec=color, lw=0.3, zorder=z + 0.1))
    if head: tip(pts[-2], pts[-1])
    if both: tip(pts[1], pts[0])

def label(ax, x, y, s, size=5.8, ha="center", va="center", bg="white", style="normal", z=7):
    ax.text(x, y, s, fontsize=size, ha=ha, va=va, zorder=z, style=style,
            bbox=dict(fc=bg, ec="none", pad=0.6) if bg else None)

def cylinder(ax, x, y, w, h, title=None, fc="white", sub=None):
    e = h * 0.18
    rect(ax, x, y + e / 2, w, h - e, fc=fc, lw=0, z=2)
    ax.plot([x, x], [y + e / 2, y + h - e / 2], color=K, lw=0.6, zorder=3)
    ax.plot([x + w, x + w], [y + e / 2, y + h - e / 2], color=K, lw=0.6, zorder=3)
    ax.add_patch(Ellipse((x + w / 2, y + h - e / 2), w, e, fc=fc, ec=K, lw=0.6, zorder=2.5))
    ax.add_patch(Ellipse((x + w / 2, y + e / 2), w, e, fc=fc, ec=K, lw=0.6, zorder=3.5))
    if title: text(ax, x + w / 2, y + h / 2 + 0.03, title, size=6.5, weight="bold")
    if sub: text(ax, x + w / 2, y + h / 2 + 0.17, sub, size=5.6)

def server(ax, cx, cy, s=1.0):
    w, h = 0.16 * s, 0.22 * s
    for k in range(3):
        rect(ax, cx - w / 2, cy - h / 2 + k * h / 3, w, h / 3, fc="white", lw=0.5, z=6)
        ax.add_patch(Circle((cx + w / 2 - 0.025 * s, cy - h / 2 + k * h / 3 + h / 6), 0.008 * s, fc=K, zorder=7))
        ax.plot([cx - w / 2 + 0.02 * s, cx + 0.01 * s], [cy - h / 2 + k * h / 3 + h / 6] * 2, color=K, lw=0.4, zorder=7)

def bank(ax, cx, cy, s=1.0):
    w = 0.22 * s
    ax.add_patch(Polygon([(cx - w / 2 - 0.02 * s, cy - 0.04 * s), (cx + w / 2 + 0.02 * s, cy - 0.04 * s), (cx, cy - 0.13 * s)], closed=True, fc=G2, ec=K, lw=0.5, zorder=6))
    for k in range(4):
        xx = cx - w / 2 + 0.025 * s + k * (w - 0.05 * s) / 3
        rect(ax, xx - 0.012 * s, cy - 0.03 * s, 0.024 * s, 0.11 * s, fc="white", lw=0.4, z=6)
    rect(ax, cx - w / 2 - 0.02 * s, cy + 0.08 * s, w + 0.04 * s, 0.025 * s, fc=G2, lw=0.5, z=6)

def person(ax, cx, cy, s=1.0):
    ax.add_patch(Circle((cx, cy - 0.06 * s), 0.035 * s, fc="white", ec=K, lw=0.5, zorder=6))
    ax.add_patch(FancyBboxPatch((cx - 0.06 * s, cy - 0.015 * s), 0.12 * s, 0.1 * s, boxstyle=f"round,pad=0,rounding_size={0.04*s}", fc=G2, ec=K, lw=0.5, zorder=6))

def keyicon(ax, cx, cy, s=1.0):
    ax.add_patch(Circle((cx - 0.04 * s, cy), 0.025 * s, fc="white", ec=K, lw=0.5, zorder=7))
    ax.plot([cx - 0.015 * s, cx + 0.06 * s], [cy, cy], color=K, lw=0.6, zorder=7)
    ax.plot([cx + 0.04 * s, cx + 0.04 * s], [cy, cy + 0.02 * s], color=K, lw=0.6, zorder=7)
    ax.plot([cx + 0.06 * s, cx + 0.06 * s], [cy, cy + 0.025 * s], color=K, lw=0.6, zorder=7)

def lock(ax, cx, cy, s=1.0):
    t = np.linspace(0, np.pi, 30)
    ax.plot(cx + 0.03 * s * np.cos(t), cy - 0.02 * s - 0.035 * s * np.sin(t), color=K, lw=0.6, zorder=7)
    rect(ax, cx - 0.045 * s, cy - 0.02 * s, 0.09 * s, 0.07 * s, fc=G3, lw=0.5, z=7)

def blocks(ax, x, y, n=4, w=0.22, h=0.16, gap=0.08):
    for i in range(n):
        xx = x + i * (w + gap)
        rect(ax, xx, y, w, h, fc="white", lw=0.5, z=5)
        rect(ax, xx, y, w, h * 0.3, fc=G2, lw=0.5, z=5.5)
        if i < n - 1: arrow(ax, [(xx + w + gap, y + h / 2), (xx + w, y + h / 2)], lw=0.5)

def save(fig, name):
    fig.savefig(f"../{name}.png", dpi=600)
    fig.savefig(f"../{name}.pdf")
    plt.close(fig)
