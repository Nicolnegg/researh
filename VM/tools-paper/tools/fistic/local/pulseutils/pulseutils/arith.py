# --------------------
def percentify(v, maxv):
    r"""Returns $100*\frac{v}{maxv}$, rounded until the first non-0 digit."""
    res = 100*v/maxv
    if res != 0:
        dec = 0
        while round(res, dec) == 0:
            dec += 1
        res = round(res, dec)
    return res
# --------------------
