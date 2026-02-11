# ----------------------------------------
from pycparser import parse_file, c_parser, c_ast
# ----------------------------------------
class UFDDetectGeneric(c_ast.NodeVisitor):

    def __init__(self, rules, stack=[]):
        super().__init__()
        self.rules = rules
        self.stack = stack
        self.symbols = set()
        self.declared = set()
        self.declaredptr = set()
        self.rawdeclared = set()
        self.defined = set()
        self.called = set()
        self.called.add('main')
        self.in_def = False
        self.in_ptr = False
        self.skip_decl_flag = False
        self.in_decl = None

    def _dependencies(self, ids):
        deps = { i for i in ids }
        for i in ids:
            if i in self.rules.stubs:
                for dep in self.rules.stubs[i].depends:
                    self.stack.append('add stub dependency {} (from {})'.format(dep, i))
                    deps.update(self.rules.dependencies({ dep }, stack=self.stack))
                    # TODO: Handle ciruclar dependencies correctly
        return deps

    @property
    def undeclared(self):
        return self._dependencies(self.called - self.declared)

    @property
    def undefined(self):
        return self._dependencies(self.called - self.defined)
        # return (self.called | self.declared) - self.defined

    def nodeNameReplace(self, node, depth):
        if (isinstance(node.name, c_ast.UnaryOp)) or (depth != 1 and isinstance(node.name.name, c_ast.UnaryOp)):
            return
        nvalue = node.name if depth == 1 else node.name.name
        if nvalue in self.rules.replace:
            #newname, missing = self.rules.replace[nvalue]
            newname = self.rules.replace[nvalue]
            self.stack.append('replace funcid {} with {}'.format(nvalue, newname))
            if depth == 1:
                node.name = newname
                try:
                    node.type.type.declname = newname
                except AttributeError:
                    node.type.type.type.declname = newname
            else:
                node.name.name = newname
            #for name in missing:
            #    self.called.add(name)

    def visit_ID(self, node):
        self.symbols.add(node.name)
        if node.name in self.rules.idstubs and not node.name in self.rawdeclared:
            self.stack.append('flag id decl {} for replacement'.format(node.name))
            self.called.add(node.name)

    def visit_FileAST(self, node):
        skip = []
        for idx in range(len(node.ext)):
            self.visit(node.ext[idx])
            if self.skip_decl_flag:
                self.skip_decl_flag = False
                self.stack.append('flag external id {} for deletion'.format(idx))
                skip.append(idx)
        skip.reverse()
        for idx in skip:
            self.stack.append('delete external id {}'.format(idx))
            node.ext.pop(idx)

    def visit_PtrDecl(self, node):
        self.in_ptr = True
        self.generic_visit(node)
        self.in_ptr = False

    def visit_FuncDecl(self, node):
        if not self.in_ptr:
            self.declared.add(self.in_decl)
            self.stack.append('found func decl for {}'.format(self.in_decl))
        else:
            self.declaredptr.add(self.in_decl)
            self.stack.append('found ptr func decl for {} (skipped)'.format(self.in_decl))
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        self.generic_visit(node)
        self.nodeNameReplace(node, 2)
        if not isinstance(node.name, c_ast.UnaryOp):
            callname = node.name.name
            self.called.add(callname)

    def visit_Decl(self, node):
        self.symbols.add(node.name)
        self.nodeNameReplace(node, 1)
        if self.in_def:
            if node.name in self.rules.delete_defs:
                self.skip_decl_flag = True
                self.stack.append('falg func {} for deletion'.format(node.name))
                return
            else:
                self.defined.add(node.name)
                self.stack.append('found func def for {}'.format(node.name))
        self.rawdeclared.add(node.name)
        self.in_decl = node.name
        self.generic_visit(node)
        self.in_decl = None

    def visit_FuncDef(self, node):
        self.in_def = True
        self.generic_visit(node)
        self.in_def = False
# ----------------------------------------
def generate_update(filename, rules, stack=[]):
    ast = parse_file(filename, use_cpp=True)
    detector = UFDDetectGeneric(rules, stack)
    detector.visit(ast)
    return ast, detector
# ----------------------------------------
