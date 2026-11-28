"""Locksmith vault mark (v3): outer dial ring in six segments, six bolts, inner ring in three
segments, keyhole hub. `locked` = ring gaps aligned with the bolts and bolts thrown out;
`unlocked` = ring turned 30 degrees, bolts withdrawn. Run: python3 gen.py <outdir>."""
import math, sys, os
C = 60.0

def arc(r, a0, a1):
    p = lambda a: (C + r * math.cos(math.radians(a)), C + r * math.sin(math.radians(a)))
    (x0, y0), (x1, y1) = p(a0), p(a1)
    large = 1 if (a1 - a0) % 360 > 180 else 0
    return f"M{x0:.2f} {y0:.2f}A{r} {r} 0 {large} 1 {x1:.2f} {y1:.2f}"

def ring(r, n, gap, offset):
    seg = 360 / n
    return "".join(arc(r, offset + i * seg + gap / 2, offset + (i + 1) * seg - gap / 2) for i in range(n))

def bolts(r0, r1, n, offset):
    out = []
    for i in range(n):
        a = math.radians(offset + i * 360 / n)
        out.append(f"M{C + r0 * math.cos(a):.2f} {C + r0 * math.sin(a):.2f}L{C + r1 * math.cos(a):.2f} {C + r1 * math.sin(a):.2f}")
    return "".join(out)

KEYHOLE = (f'<circle cx="{C}" cy="{C - 4}" r="8.5"/>'
           f'<path d="M{C - 4.5} {C - 1}L{C - 7} {C + 14}H{C + 7}L{C + 4.5} {C - 1}Z"/>')

def mark(state, sw=7.0, small=False, outer=True):
    """state: locked | unlocked. small: simplified for 16-18 px (no inner ring, heavier)."""
    locked = state == "locked"
    turn = 0 if locked else 30
    if small:
        r_out, r_in, w, gap = 40, 26, 10, 30
        bolt = bolts(r_in, 53 if locked else 30, 6, -90)
        inner = ""
    else:
        r_out, r_in, w, gap = 42, 25, sw, 20
        # bolts start on the inner ring and are thrown out through the outer ring's gaps
        bolt = bolts(r_in, 52 if locked else 33, 6, -90)
        inner = f'<path d="{ring(r_in, 6, 22, -60)}"/>'
    parts = [f'<g class="ring" style="transform-origin:60px 60px;transform:rotate({turn}deg)">'
             f'<path d="{ring(r_out, 6, gap, -90)}"/></g>',
             f'<path class="bolts" d="{bolt}"/>', inner]
    return (f'<g fill="none" stroke="currentColor" stroke-width="{w}" stroke-linecap="butt">'
            + "".join(parts) + f'</g><g fill="currentColor">{KEYHOLE}</g>')

def svg(body, size=None, extra=""):
    wh = f' width="{size}" height="{size}"' if size else ""
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120"{wh}{extra}>{body}</svg>\n'

def icon(theme):
    bg, fg, acc = ("#1b1a18", "#f1eee8", "#6cc3bd") if theme == "dark" else ("#f4f4f2", "#1c1b19", "#0e6e70")
    body = (f'<rect width="120" height="120" rx="27" fill="{bg}"/>'
            f'<g transform="translate(60 60) scale(.92) translate(-60 -60)" color="{fg}">{mark("locked")}</g>')
    # spruce on the bolts only: the part that "throws" when the vault locks
    body = body.replace('<path class="bolts"', f'<path class="bolts" stroke="{acc}"', 1)
    return svg(body)

out = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(out, exist_ok=True)
files = {
    "locksmith-mark.svg": svg(mark("locked")),
    "locksmith-mark-unlocked.svg": svg(mark("unlocked")),
    "app-icon-dark.svg": icon("dark"),
    "app-icon-light.svg": icon("light"),
    "tray-locked.svg": svg(mark("locked", small=True), 18).replace("currentColor", "#000"),
    "tray-unlocked.svg": svg(mark("unlocked", small=True), 18).replace("currentColor", "#000"),
}
for n, s in files.items():
    open(os.path.join(out, n), "w").write(s)
print("\n".join(files))
