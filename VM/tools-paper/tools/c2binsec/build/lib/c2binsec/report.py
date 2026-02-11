# ----------------------------------------
import os.path
from .core import TaskStatus, TaskException
# ----------------------------------------
class ReportTemplates:

    ReportHeader = """
\\documentclass[aspectratio=1610,12pt]{beamer}
\\usepackage[english]{babel}
\\usepackage[T1]{fontenc}
\\usepackage[utf8]{inputenc}
\\usetheme{Antibes}
\\addtobeamertemplate{navigation symbols}{}{%
    \\usebeamerfont{footline}%
    \\usebeamercolor[fg]{footline}%
    \\hspace{1em}%
    \\insertframenumber/\\inserttotalframenumber
}
\\usepackage{tikz}
\\usetikzlibrary{patterns}
\\usepackage{rotating}
\\usepackage{listings}
\\lstset{extendedchars=\\true, inputencoding=utf8, literate={-}{{-}}1}
\\usepackage{pifont}
\\newcommand{\\cmark}{\\ding{51}}%
\\newcommand{\\xmark}{\\ding{55}}%
%\\usepackage[ruled,vlined]{algorithm2e}
\\usepackage{xifthen}
\\usepackage{cancel}
%\\usepackage{stmaryrd}
\\newcommand{\\backupbegin}{\\newcounter{finalframe}\\setcounter{finalframe}{\\value{framenumber}}}
\\newcommand{\\backupend}{\\setcounter{framenumber}{\\value{finalframe}}}
%\\renewcommand{\\thealgocf}{}
\\usepackage{colortbl}
\\newcommand{\\placeoverframe}[3]{
\\begin{frame}
	\\frametitle{#1}
	\\framesubtitle{#2}
	\\begin{block}{Expected Content}
		#3
	\\end{block}
\\end{frame}
}
\\setbeamertemplate{caption}[numbered]
\\title{\\texttt{c2ba} Report}
\\date{\\today}
\\begin{document}
\\begin{frame}\\maketitle\\end{frame}
\\begin{frame}\\tableofcontents\\end{frame}
"""

    ReportFooter = """
\\end{document}
"""
# ----------------------------------------
class ReportData:

    def __init__(self, filename, stack=[]):
        self.filename = filename
        stack.append('load logged result data from {}'.format(self.filename))
        self.data = self._parse_file(filename)

    def __getitem__(self, k):
        return self.data[k]

    def _parse_file(self, filename):
        data = dict()
        with open(filename) as stream:
            for line in stream:
                if line.startswith('[binsec:run]') or line.startswith('[robust-binsec:run]'):
                    ldata = line.replace('[binsec:run]', '').replace('[robust-binsec:run]', '').replace('seconds', '').strip()
                    lpart = [ ld.strip() for ld in ldata.split(' in ') ]
                    data['results'] = lpart[0].split('+')
                    data['time'] = float(lpart[1])
                if line.startswith('[source]'):
                    ldata = line.replace('[source]', '').strip()
                    data['directory'] = os.path.dirname(ldata)
                    data['problem'] = os.path.basename(ldata)
                if line.startswith('[c2bc]'):
                    ldata = line.replace('[c2bc]', '').replace('expect', '').strip()
                    data['targets'] = ldata.split('+')
        return data
# ----------------------------------------
class ReportTask:

    def __init__(self, args):
        self.args = args
        self._atpr = False
        self.debug_stack = []
        self.rdata = [ ReportData(filename, self.debug_stack) for filename in args.input_files if filename.endswith('.binsec.log') ]
        self.sdata = [ ReportData(filename, self.debug_stack) for filename in args.input_files if filename.endswith('.robust-binsec.log') ]
        self.outfile = args.output_file

    def __call__(self):
        with open(self.args.output_file, 'w') as stream:
            stream.write(ReportTemplates.ReportHeader)
            self._write_global_frame(stream)
            self._write_repos_frames(stream)
            self._write_interest_frame(stream)
            self._write_maxinterest_frame(stream)
            stream.write(ReportTemplates.ReportFooter)
        with open(self.outfile + '.interest.pyl', 'w') as stream:
            stream.write(str(list(self._list_interesting_examples(maxi=True))))
        with open(self.outfile + '.rse.data', 'w') as stream:
            for sdat in self.sdata:
                print(sdat)
                robust = '+'.join(sdat['results'])
                if 'model' in robust:
                    stream.write('{}\n'.format(sdat['time']))

    def _list_interesting_examples(self, maxi=False, repo=None):
        interest = set()
        for dat in self.rdata:
            if repo is not None and dat['directory'] != repo:
                continue
            problem = os.path.join(dat['directory'], dat['problem'])
            target = '+'.join(dat['targets'])
            result = '+'.join(dat['results'])
            robust = ''
            for sdat in self.sdata:
                if sdat['directory'] == dat['directory'] and sdat['problem'] == dat['problem']:
                    robust = '+'.join(sdat['results'])
            if 'model' in result and ((not maxi) or 'unreachable' in robust or 'model' in robust):
                interest.add(problem)
            if not self._atpr and 'model' in robust:
                print('{}'.format(problem))
        if not self._atpr:
            self._atpr = True
        return interest

    def _write_interest_frame(self, stream):
        stream.write('\\begin{frame}\n')
        stream.write('\\tiny\n')
        stream.write('\\frametitle{{{}}}\n'.format('Examples of interest'))
        stream.write('\\begin{block}{List}\n')
        stream.write('\\begin{itemize}\n')
        for example in self._list_interesting_examples():
            stream.write('\\item {} \n'.format(example.replace('_', '\\_')))
        stream.write('\\end{itemize}\n')
        stream.write('\\end{block}\n')
        stream.write('\\end{frame}\n')

    def _write_maxinterest_frame(self, stream):
        stream.write('\\begin{frame}\n')
        stream.write('\\tiny\n')
        stream.write('\\frametitle{{{}}}\n'.format('Examples of maximal interest'))
        stream.write('\\begin{block}{List}\n')
        stream.write('\\begin{itemize}\n')
        for example in self._list_interesting_examples(maxi=True):
            stream.write('\\item {} \n'.format(example.replace('_', '\\_')))
        stream.write('\\end{itemize}\n')
        stream.write('\\end{block}\n')
        stream.write('\\end{frame}\n')

    def _write_computation_time_graph(self, stream, data, repo=None):
        tserie = []
        for dat in data:
            if repo is not None and dat['directory'] != repo:
                continue
            tserie.append((dat['results'], dat['time']))
        def rcolor(r):
            if 'ok' in r:
                return 'blue'
            if 'unreachable' in r:
                return 'red'
            return 'black'
        stream.write('\\begin{tikzpicture}[xscale=6.5]')
        stream.write('\\draw (0,0.5) -- (0,0) -- (1,0) -- (1,0.5);\n')
        stream.write('\\draw (0.5,0) -- (0.5,0.5);\n')
        stream.write('\\draw (0.25,0) -- (0.25,0.25);\n')
        stream.write('\\draw (0.75,0) -- (0.75,0.25);\n')
        stream.write('\\node at (0,-0.25) {0s};\n')
        stream.write('\\node at (0.25,-0.25) {15s};\n')
        stream.write('\\node at (0.5,-0.25) {30s};\n')
        stream.write('\\node at (0.75,-0.25) {45s};\n')
        stream.write('\\node at (1,-0.25) {60s};\n')
        for telem, ttime in tserie:
            tcolor = rcolor(telem)
            stream.write('\\draw [color={0}] ({1},0.05) -- ({1},0.45);\n'.format(tcolor, ttime/60))
        stream.write('\\end{tikzpicture}')

    def _write_global_frame(self, stream, repo=None):
        cat_exp = dict()
        cat_exe = dict()
        cat_rob = dict()
        for dat in self.rdata:
            if repo is not None and dat['directory'] != repo:
                continue
            target = '+'.join(dat['targets'])
            result = '+'.join(dat['results'])
            if not target in cat_exp:
                cat_exp[target] = 0
            if not result in cat_exe:
                cat_exe[result] = 0
            cat_exp[target] += 1
            cat_exe[result] += 1
        for dat in self.sdata:
            if repo is not None and dat['directory'] != repo:
                continue
            result = '+'.join(dat['results'])
            if not result in cat_rob:
                cat_rob[result] = 0
            cat_rob[result] += 1
        stream.write('\\begin{frame}\n')
        stream.write('\\tiny\n')
        stream.write('\\frametitle{{{}}}\n'.format(repo if repo is not None else 'Global'))


        stream.write('\\begin{columns}\n')

        stream.write('\\begin{column}{0.5\\textwidth}\n')
        stream.write('\\begin{block}{Expected}\n')
        stream.write('\\begin{itemize}\n')
        for cat in sorted(cat_exp.keys(), key=lambda k : -cat_exp[k]):
            stream.write('\\item {} : {}\n'.format(cat, cat_exp[cat]))
        stream.write('\\end{itemize}\n')
        stream.write('\\end{block}\n')

        stream.write('\\begin{block}{Got}\n')
        if len(cat_exe) > 0:
            stream.write('\\begin{itemize}\n')
            for cat in sorted(cat_exe.keys(), key=lambda k : -cat_exe[k]):
                if 'model' in cat or 'unreachable' in cat:
                    color = 'blue' if 'model' in cat else 'red'
                    stream.write('\\item \\textbf{{\\color{{{}}}{{{} : {}}}}}\n'.format(color, cat, cat_exe[cat]))
                else:
                    stream.write('\\item {} : {}\n'.format(cat, cat_exe[cat]))
            stream.write('\\end{itemize}\n')
        stream.write('\\end{block}\n')

        if repo is not None:
            stream.write('\\begin{block}{Standard Computation Time}\n')
            self._write_computation_time_graph(stream, self.rdata, repo)
            stream.write('\\end{block}\n')

        stream.write('\\end{column}\n')

        stream.write('\\begin{column}{0.5\\textwidth}\n')

        stream.write('\\begin{block}{Robust}\n')
        if len(cat_rob) > 0:
            stream.write('\\begin{itemize}\n')
            for cat in sorted(cat_rob.keys(), key=lambda k : -cat_rob[k]):
                if 'model' in cat or 'unreachable' in cat:
                    color = 'blue' if 'model' in cat else 'red'
                    stream.write('\\item \\textbf{{\\color{{{}}}{{{} : {}}}}}\n'.format(color, cat, cat_rob[cat]))
                else:
                    stream.write('\\item {} : {}\n'.format(cat, cat_rob[cat]))
            stream.write('\\end{itemize}\n')
        stream.write('\\end{block}\n')

        if repo is not None:
            stream.write('\\begin{block}{Robust Computation Time}\n')
            self._write_computation_time_graph(stream, self.sdata, repo)
            stream.write('\\end{block}\n')

        stream.write('\\end{column}\n')

        stream.write('\\end{columns}\n')

        stream.write('\\end{frame}\n')

    def _write_repos_frames(self, stream):
        repos = set()
        for dat in self.rdata:
            repos.add(dat['directory'])
        for repo in sorted(repos):
            self._write_global_frame(stream, repo)
# ----------------------------------------
