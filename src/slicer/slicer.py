import logging
import pyvex

log = logging.getLogger("slicer.Slicer")
log.setLevel('DEBUG')

class SlicerError(Exception):
    pass

class SlicerState(object):
    def __init__(self, target_tmps=None, target_regs=None, target_addrs=None, mem_reads=None, mem_writes=None):
        if not target_tmps and not target_regs and not target_addrs:
            log.error("Must specify at least one of the following:"
                      "target temps, target registers, and/or target memory addresses")

            raise SlicerError("Must specify at least one of the following:"
                              "target temps, target registers, and/or target memory addresses")
        self.targets = {
            "tmp" : set(target_tmps) if target_tmps else set(),
            "reg" : set(target_regs) if target_regs else set(),
            "addr": set(target_addrs) if target_addrs else set()
        }
        self.bbl_addr = None
        self.inst = None
        self._mem_reads_iter = reversed(mem_reads)
        self._mem_writes_iter = reversed(mem_writes)

    def concrete_write_addr(self):
         # TODO: same instuctions two write?
        mem_write = None
        try:
            while mem_write is None or mem_write['inst'] != self.inst:
                mem_write = self._mem_writes_iter.next()
        except StopIteration:
            return None

        return mem_write['addr']

    def concrete_read_addr(self):
        # TODO: same instuctions two read?
        mem_read = None
        try:
            while mem_read is None or mem_read['inst'] != self.inst:
                mem_read = self._mem_reads_iter.next()
        except StopIteration:
            return None

        return mem_read['addr']


class Slicer(object):
    def __init__(self, project, path, target_tmps=None, target_regs=None, target_addrs=None, mem_reads=None, mem_writes=None):
        self._project = project
        self._path = path

        if target_tmps is None and target_regs is None and target_addrs is None:
            target_tmps, target_regs, target_addrs = self._slice_from_last_condition()

        self._state = SlicerState(target_tmps, target_regs, target_addrs, mem_reads, mem_writes)

        # results
        self.instructions = set()


    def slice(self):
        for trace in reversed(self._path.addr_trace):
            self._state.bbl_addr = trace
            block = self._project.factory.block(trace).vex
            self._slice_block(block)

            log.debug("State after block [0x%x]" % trace)
            log.debug("Targets: %s" % self._state.targets)


    def _slice_block(self, block):
        # preprocess
        ins = []
        for stmt in block.statements:
            if isinstance(stmt, pyvex.stmt.IMark):
                ins.append(stmt.addr)

        ins_idx = len(ins)-1
        self._state.inst = ins[ins_idx]

        for stmt in reversed(block.statements):
            if isinstance(stmt, pyvex.stmt.IMark):
                ins_idx -= 1
                self._state.inst = ins[ins_idx]
            elif self._backward_handler_stmt(stmt, self._state):
                self.instructions.add(self._state.inst)


    def _backward_handler_stmt(self, stmt, state):
        funcname = "_backward_handler_stmt_%s" % type(stmt).__name__
        in_slice = False
        if hasattr(self, funcname):
            in_slice = getattr(self, funcname)(stmt, state)
        return in_slice

    def _backward_handler_stmt_WrTmp(self, stmt, state):
        tmp = stmt.tmp
        if tmp not in state.targets["tmp"]:
            return False

        state.targets["tmp"].remove(tmp)
        self._backward_handler_expr(stmt.data, state)
        return True

    def _backward_handler_stmt_Put(self, stmt, state):
        reg = stmt.offset
        if reg in state.targets["reg"]:
            state.targets["reg"].remove(reg)
            self._backward_handler_expr(stmt.data, state)
            return True

        return False

    def _backward_handler_stmt_Store(self, stmt, state):
        addr = stmt.addr
        if isinstance(addr, pyvex.IRExpr.RdTmp):
            concrete_addr = state.concrete_write_addr()
            if concrete_addr:
                log.debug("Find concrete_addr: %d", concrete_addr)
                if concrete_addr in state.targets["addr"]:
                    state.targets["addr"].remove(concrete_addr)
                    self._backward_handler_expr(addr, state)
                    self._backward_handler_expr(stmt.data, state)
                    return True
        return False

    def _backward_handler_expr(self, expr, state):
        funcname = "_backward_handler_expr_%s" % type(expr).__name__
        in_slice = False
        if hasattr(self, funcname):
            in_slice = getattr(self, funcname)(expr, state)
        return in_slice

    def _backward_handler_expr_RdTmp(self, expr, state):
        tmp = expr.tmp
        state.targets["tmp"].add(tmp)

    def _backward_handler_expr_Get(self, expr, state):
        reg = expr.offset
        if reg == self._project.arch.sp_offset or reg == self._project.arch.bp_offset:
            return
        state.targets["reg"].add(reg)


    def _backward_handler_expr_Load(self, expr, state):
        addr = expr.addr
        if isinstance(addr, pyvex.IRExpr.RdTmp):
            self._backward_handler_expr(addr, state)
            concrete_addr = state.concrete_read_addr()
            if concrete_addr:
                state.targets["addr"].add(concrete_addr)

    def _backward_handler_expr_Unop(self, expr, state):
        arg = expr.args[0]
        if isinstance(arg, pyvex.IRExpr.RdTmp):
            self._backward_handler_expr(arg, state)

    def _backward_handler_expr_Binop(self, expr, state):
        for arg in expr.args:
            if isinstance(arg, pyvex.IRExpr.RdTmp):
                self._backward_handler_expr(arg, state)

    def _backward_handler_expr_CCall(self, expr, state):
        for arg in expr.args:
            if isinstance(arg, pyvex.IRExpr.RdTmp):
                self._backward_handler_expr(arg, state)

