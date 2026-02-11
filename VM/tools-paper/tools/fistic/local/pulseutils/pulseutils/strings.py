# --------------------
def unparen(data):
    """Removes a pair of parentheses around `data`, skipping trailing whitespaces."""
    sdata = data.strip()
    if sdata.startswith('(') and sdata.endswith(')'):
        return sdata[1:-1]
    return sdata
# --------------------
def stringify(it):
    """Builds the set of the strings of the elements iterated by `it`."""
    return { str(e) for e in it }
# --------------------
# --------------------
# --------------------
# --------------------
