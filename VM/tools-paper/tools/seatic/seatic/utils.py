# --------------------
import os
import random
# --------------------
COLOR_LIST = [

]

def new_color():
    global COLOR_LIST
    color = '#{:02x}{:02x}{:02x}'.format(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    COLOR_LIST.append(color)
    return COLOR_LIST[-1]
# --------------------
def extract_optimization(filename):
    if 'O0' in filename:
        return 0
    if 'O1' in filename:
        return 1
    if 'O2' in filename:
        return 2
    if 'O3' in filename:
        return 3
    if 'Os' in filename:
        return 4
    return -1
# --------------------
def pad_list(l, size):
    return l + [None] * max(0, (size - len(l)))
# --------------------
def rotate_table(t):
    res = [[]]*max((len(e) for e in t))
    for l in t:
        for i in range(len(l)):
            res[i].append(l[i])
    return res
# --------------------
