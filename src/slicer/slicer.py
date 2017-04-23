import logging
import subprocess

import angr
import pyvex
from trace import Trace
from collections import deque


log = logging.getLogger("slicer.Slicer")
#log.setLevel('DEBUG')

class SlicerError(Exception):
    pass

class SliceState(object):
    def __init__(self, bbl_idx, target_tmps=None, target_regs=None, target_addrs=None):

        self.bbl_idx = bbl_idx

        if not target_tmps and not target_regs and not target_addrs:
            log.error("Must specify at least one of the following:"
                      "target temps, target registers, and/or target memory addresses")
            raise SlicerError("Empty target state")

        self.targets = {
            "tmp" : set(target_tmps) if target_tmps else set(),
            "reg" : set(target_regs) if target_regs else set(),
            "addr": set(target_addrs) if target_addrs else set()
        }
        self.current_ins = None


    @property
    def num_of_targets(self):
        return len(self.targets["tmp"]) + len(self.targets["reg"]) + \
               len(self.targets["addr"])


    def remove_visited_targets(self, visited):
        ts = set()
        for t in self.targets["tmp"]:
            key = str(self.bbl_idx) + ":t" + str(t)
            if key not in visited:
                ts.add(t)
        self.targets["tmp"] = ts

        rs = set()
        for t in self.targets["reg"]:
            key = str(self.bbl_idx) + ":r" + str(t)
            if key not in visited:
                rs.add(t)
        self.targets["reg"] = rs

        ds = set()
        for t in self.targets["addr"]:
            key = str(self.bbl_idx) + ":a" + str(t)
            if key not in visited:
                ds.add(t)
        self.targets["addr"] = ds



    def add_targets_to_visited(self, visited):
        for t in self.targets["tmp"]:
            visited.add(str(self.bbl_idx) + ":t" + str(t))

        for t in self.targets["reg"]:
            visited.add(str(self.bbl_idx) + ":r" + str(t))

        for t in self.targets["addr"]:
            visited.add(str(self.bbl_idx) + ":a" + str(t))



    def __repr__(self):
        return "<SliceState bbl#%d with %d targets>" % (self.bbl_idx, self.num_of_targets)


class Slicer(object):
    def __init__(self, binary, tracefile, num_bbl=None):
        self.binary = binary
        self.tracefile = tracefile

        log.debug("Loading trace...")
        self._trace = Trace(tracefile, num_bbl)

        log.debug("Loading binary...")
        self._project = angr.Project(self.binary, load_options=dict(auto_load_libs=False))

        log.debug("Initiating target queue...")
        self._target_q = deque()
        self._set_slice_criterion()

        # results
        self._inst_in_slice = set()
        self._line_in_slice = None

    @property
    def inst_in_slice(self):
        return self._inst_in_slice

    @property
    def line_in_slice(self):
        if self._line_in_slice is None:
            self._line_in_slice = self._inst_to_line()
        return self._line_in_slice


    def _inst_to_line(self):
        args = ["addr2line", "-e", self.binary]
        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        p.stdin.write("\n".join([hex(i) for i in self._inst_in_slice]))
        p.stdin.close()
        return sorted(set(p.stdout.read().splitlines()))


    def _get_irsb(self, bbl):
        return self._project.factory.block(bbl.addr, size=bbl.size)

    def _set_slice_criterion(self):
        #TODO: other cases?

        block = self._get_irsb(self._trace.last_bbl)
        cond = block.vex.statements[-1]
        if not isinstance(cond, pyvex.stmt.Exit):
            log.error("Last statement is not a condition exit: %s", cond)
            raise SlicerError("Must slice from a conditional exit")
        if isinstance(cond.guard, pyvex.expr.RdTmp):
            self._target_q.append(SliceState(len(self._trace.bbls)-1, \
                                             target_tmps=[cond.guard.tmp]))



    def run(self):

        visited = set()

        while len(self._target_q):
            state = self._target_q.pop()
            state.add_targets_to_visited(visited)


            self._backward_slice(state)
            state.remove_visited_targets(visited)
            targets = state.targets

            if len(targets["tmp"]) + len(targets["reg"]):
                new_state = SliceState(state.bbl_idx-1, target_tmps=targets["tmp"], \
                                       target_regs=targets["reg"])
                self._target_q.append(new_state)

            if len(targets["addr"]):
                for addr in targets["addr"]:
                    idx = self._search_write_to(addr, state.bbl_idx-1)
                    log.debug("search_write_addr: addr = 0x%x, bbl_idx = %d", addr, idx)
                    if idx >= 0:
                        new_state = SliceState(idx, target_addrs=[addr])
                        self._target_q.append(new_state)


    def _address_in_taints(self, addr):
        for s, l in self._trace.taints:
            if addr >= s and addr < s + l:
                return True
        return False

    def _address_in_binary(self, addr):
        mb = self._project.loader.main_bin
        return mb.get_min_addr() <= addr and addr < mb.get_max_addr()


    def _search_write_to(self, addr, from_bbl):
        while from_bbl >= 0:
            bbl = self._trace.bbls[from_bbl]
            if bbl.has_write_to(addr):
                break
            from_bbl -= 1
        return from_bbl


    def _backward_slice(self, state):
        bbl = self._trace.bbls[state.bbl_idx]
        block = self._get_irsb(bbl)


        ins = block.instruction_addrs
        ins_idx = len(ins)-1
        state.current_ins = ins[ins_idx]

        for stmt in reversed(block.vex.statements):
            if isinstance(stmt, pyvex.stmt.IMark):
                ins_idx -= 1
                state.current_ins = ins[ins_idx]
            elif self._backward_handler_stmt(stmt, state):
                self._inst_in_slice.add(ins[ins_idx])

        log.debug("State after block #%d [0x%x], %d targets", state.bbl_idx, bbl.addr, state.num_of_targets)


    def _concrete_write_addr(self, state):
        bbl = self._trace.bbls[state.bbl_idx]
        return bbl.write_addr(state.current_ins)

    def _concrete_read_addr(self, state):
        bbl = self._trace.bbls[state.bbl_idx]
        return bbl.read_addr(state.current_ins)


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
            concrete_addr = self._concrete_write_addr(state)
            if concrete_addr and concrete_addr in state.targets["addr"]:
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
            concrete_addr = self._concrete_read_addr(state)
            if concrete_addr:
                if self._address_in_taints(concrete_addr):
                    log.info("Load from tainted input %d", concrete_addr)
                else:
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


if __name__ == "__main__":

    binary = "../../test_libressl/test_libressl"
    tracefile = "../../test_libressl/traces/valid.trace"
    num_bbls = 481972

#    binary = "../../test_slice/test"
#    tracefile = "../../test_slice/traces/1.trace"
#    num_bbls = 40

    try:
        slicer = Slicer(binary, tracefile, num_bbls)
        slicer.run()
        print "Lines in slice:"
        for line in slicer.line_in_slice:
            print line
    except SlicerError as e:
        print e

