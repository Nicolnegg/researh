# --------------------
import os.path
import time
import math
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.pyplot as plt
import matplotlib.markers as markers
from .utils import pad_list, rotate_table
from . import pprinters as pp
# --------------------
plt.rc('font', size=30)
# --------------------
LINE_STYLES = [
    '--',
    '-.',
    '-',
    ':',
    (1, (8, 2, 5, 2)),
    (1, (11, 2, 5, 2)),
    (1, (5, 3, 1, 2)),
    (1, (8, 5, 1, 2)),
    (1, (11, 8, 1, 2)),
]
MARKERS = ['o'
# https://matplotlib.org/stable/gallery/lines_bars_and_markers/marker_reference.html#filled-markers
           , '^'
           , '*'
           , 'd'
           , 'P'
           , '>'
           , '8'
           , 's'
           , 'p'
           , 'v'
           , 'h'
           , '<'
           , 'H'
           , 'D'
           , 'X'
           , '.'
]
# --------------------
def get_table_dims(nelem, offset=0):
    vcount = nelem - offset
    lx = round(math.sqrt(vcount))
    ly = lx + max(0, vcount - lx*lx)
    return vcount, lx, ly
# --------------------
def get_bins_counts(nelem):
    values = set()
    values.add(math.ceil(math.sqrt(nelem)))
    values.add(math.ceil(math.log2(nelem)) + 1)
    return values
# --------------------
def get_hatch(color):
    table = {
        'r': '//',
        'y': '\\\\',
        'g': '..',
    }
    return table[color] if color in table else None
# --------------------
def generate_barplot(elems, title, target, labels=None, xlabels=None):
    plt.rc('font', size=10)
    fig = plt.figure(figsize=(12,1.5))
    ax = fig.add_subplot(1, 1, 1)
    width = 0.25
    erange = list(range(len(elems[0])))
    for index in range(len(elems)):
        vlist = elems[index]
        offset = [-width, 0, width][index]
        offsetl = [ e+offset for e in erange ]
        ax.bar(offsetl , vlist, width, label=labels[index])
    if title:
        ax.set_title(title)
    if xlabels:
        ax.set_xticks(erange)
        ax.set_xticklabels(xlabels)
        ax.set_yticks([0, 15, 30, 45])
        ax.set_yticklabels(['0%', '15%', '30%', '45%'])
        ax.set_ylabel('vulnerabilities')
    if labels:
        ax.legend()
    plt.tight_layout()
    plt.savefig(target)
    plt.close()
    plt.rc('font', size=12)
# --------------------
def generate_histograms(elems, title, target_template, colors=None, color_labels=None):
    for nbins in get_bins_counts(len(elems)):
        generate_histogram(elems, title, target_template.format(nbins), nbins, colors, color_labels)
# --------------------
def generate_histogram(elems, title, target, nbins, colors=None, color_labels=None):
    fig = plt.figure(figsize=(7, 7))
    index = 1
    ax = fig.add_subplot(1, 1, index)
    values = { c : [] for c in set(colors) } if colors else { None : [] }
    for i in range(len(elems)):
        if colors:
            values[colors[i]].append(elems[i])
        else:
            values[None].append(elems[i])
    xs = ([], [], [], [])
    for c, x in values.items():
        xs[0].append(x)
        xs[1].append(c)
        xs[2].append(color_labels[c] if color_labels is not None and c in color_labels else '')
        xs[3].append(get_hatch(c))
    if len(xs[0]) > 1:
        hn, hbins, hpatches = ax.hist(xs[0], bins=nbins, histtype='barstacked', color=xs[1], label=xs[2])
        for patch_set, hatch in zip(hpatches, xs[3]):
            for patch in patch_set.patches:
                patch.set_hatch(hatch)
    else:
        ax.hist(xs[0], bins=nbins, histtype='bar')
    if title:
        ax.set_title('Histogram of {} ({} bins)'.format(title, nbins))
    if color_labels is not None:
        ax.legend()
    plt.tight_layout()
    plt.savefig(target)
    plt.close()
# --------------------
def cumsum(l):
    res = []
    val = 0
    for e in l:
        val += e
        res.append(val)
    return res
# --------------------
def generate_tsplot_generic(elems, title, target, labels=None, cummulative=True, inverted=True, figsize=(1,1), exlegend=None):
    tseries = [cumsum(sorted(l)) for l in elems] if cummulative else [sorted(l) for l in elems]
    fig = plt.figure(figsize=figsize, constrained_layout=True)
    ax = fig.add_subplot(1, 1, 1)
    series = [[l, list(range(1, len(l) + 1))] for l in tseries]
    lhd, llb = None, None
    for i in range(len(series)):
        series[i].append(labels[i] if labels is not None else None)
        series[i].append(LINE_STYLES[i % len(LINE_STYLES)])
        series[i].append(MARKERS[i])
    mkspace = int(max([len(series[i][0]) for i in range(len(series))])/8) #TODO: parameterize marker counter
    if not inverted:
        for l in series:
            ax.plot(l[0], l[1], label=l[2], linestyle=l[3], marker=l[4])
        if labels is not None:
            if exlegend is None:
                ax.legend(shadow=False)
            else:
                lhd, llb = ax.get_legend_handles_labels()
        if title:
            ax.set_title('{} - {}'.format(title, 'survival' if cummulative else 'CDF'))
        if cummulative:
            ax.set_xscale('log')
        ax.set_xlabel('time (s)')
        ax.set_ylabel('# of examples')
    else:
        for l in series:
            #ax.plot(l[1], l[0], label=l[2], linestyle=l[3], marker=l[4], linewidth=0.5, markevery=mkspace)
            ax.plot(l[1], l[0], label=l[2], linestyle=l[3], marker=l[4], linewidth=2, markersize=15, markevery=mkspace)
        if labels is not None:
            if exlegend is None:
                #ax.legend(shadow=False)
                ax.legend(shadow=False, fontsize="15")
            else:
                lhd, llb = ax.get_legend_handles_labels()
        if title:
            ax.set_title('{} - {}'.format(title, 'cactus' if cummulative else 'CDF (reverse)'))
        if cummulative:
            ax.set_yscale('log')
        ax.set_xlabel('# of examples')
        ax.set_ylabel('time (s)')
    plt.savefig(target)
    plt.close()
    if exlegend is not None:
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        lplot = ax.legend(lhd, llb, frameon=False, ncol=len(labels))
        #ax.xaxis.set_visible(False)
        #ax.yaxis.set_visible(False)
        plt.axis('off')
        lfig = lplot.figure
        lfig.canvas.draw()
        bbox = lplot.get_window_extent()
        bbox = bbox.transformed(lfig.dpi_scale_trans.inverted())
        #plt.tight_layout()
        plt.savefig(exlegend, dpi='figure', bbox_inches=bbox)
        plt.close()
# --------------------
def generate_survival_plot(elems, title, target, labels=None, figsize=(7, 7), exlegend=None):
    generate_tsplot_generic(elems, title, target, labels=labels, cummulative=True, inverted=True, figsize=figsize, exlegend=exlegend)
# --------------------
def generate_cdf_plot(elems, title, target, labels=None):
    generate_tsplot_generic(elems, title, target, labels=labels, cummulative=False, inverted=False)
# --------------------
def cumstat(l, stat, step):
    res = []
    xs = []
    iv = 0
    imax = max(l)
    while iv <= imax:
        nval = stat([ min(iv, e) for e in l ])
        res.append(nval)
        xs.append(iv)
        iv += step
    return [xs, res]
# --------------------
def generate_cummulative_timeplots(elems, title, target, step, stat, labels=None, cummulative=False):
    tseries = [ cumstat(l, stat, step) for l in elems ]
    fig = plt.figure(figsize=(7,7))
    ax = fig.add_subplot(1, 1, 1)
    for i in range(len(tseries)):
        tseries[i].append(labels[i] if labels is not None else None)
    for serie in tseries:
        ax.plot(serie[0], serie[1], label=serie[2])
    if labels is not None:
        ax.legend()
    if cummulative:
        ax.set_yscale('log')
    ax.set_xlabel('timeout (s)')
    ax.set_ylabel('{} mutant computation time'.format(stat.__name__))
    if title:
        ax.set_title('Variating {} {} mutant computation time'.format(title, stat.__name__))
    plt.tight_layout()
    plt.savefig(target)
    plt.close()
# --------------------
