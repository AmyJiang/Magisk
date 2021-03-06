#!/usr/bin/python

import logging
import subprocess
import sys

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
            log.debug("Must specify at least one of the following:"
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

        log.debug("Loading binary...")
        self._project = angr.Project(self.binary, load_options=dict(auto_load_libs=False))

        log.debug("Loading trace...")
        self._trace = Trace(tracefile, num_bbl)


        log.debug("Initiating target queue...")
        self._target_q = deque()
        self._set_slice_criterion()

        log.debug("Fixing lost memory loads...")
        self._fix_lost_loads()

        # results
        self._inst_in_slice = set()
        self._line_in_slice = None

    @property
    def inst_in_slice(self):
        return self._inst_in_slice

    @property
    def line_in_slice(self):
        if self._line_in_slice is None:
            self._line_in_slice = self._inst_to_line(self._inst_in_slice)
        return self._line_in_slice


    def _inst_to_line(self, inst_in_slice):
        args = ["addr2line", "-e", self.binary]
        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        p.stdin.write("\n".join([hex(i) for i in inst_in_slice]))
        p.stdin.close()
        return sorted(set(p.stdout.read().splitlines()))


    def _get_irsb(self, bbl):
        return self._project.factory.block(bbl.addr, size=bbl.size)

    def _set_slice_criterion(self):
        #TODO: other cases?
        block = self._get_irsb(self._trace.last_bbl)
        cond = block.vex.statements[-1]
        if not isinstance(cond, pyvex.stmt.Exit):
            log.debug("Last statement is not a condition exit: last_bbl %x", self._trace.last_bbl.addr)
            raise SlicerError("Must slice from a conditional exit")
        if isinstance(cond.guard, pyvex.expr.RdTmp):
            self._target_q.append(SliceState(len(self._trace.bbls)-1, \
                                             target_tmps=[cond.guard.tmp]))
        log.debug("Slice criterion: bbl=0x%x, t%d", self._trace.bbls[-1].addr, cond.guard.tmp)

        self.slice_criterion = self._inst_to_line([block.instruction_addrs[-1]])[0]



    def _fix_lost_loads(self):
        # size take into account?
        stores = set()
        for bbl in self._trace.bbls:
            stores |= set([store["addr"] for store in bbl.mem_writes])
            bbl.mem_reads = [load for load in bbl.mem_reads if load["addr"] in stores]


    def run(self):

        visited = set()

        while len(self._target_q):
            state = self._target_q.pop()
            state.add_targets_to_visited(visited)


            self._backward_slice(state)
            state.remove_visited_targets(visited)
            targets = state.targets
            log.debug("After visited: %s", targets)

            if len(targets["tmp"]) + len(targets["reg"]):
                log.debug("--> new state: bbl_idx = %d, bb=0x%x", state.bbl_idx-1, self._trace.bbls[state.bbl_idx-1].addr)
                new_state = SliceState(state.bbl_idx-1, target_tmps=targets["tmp"], \
                                       target_regs=targets["reg"])
                self._target_q.append(new_state)

            if len(targets["addr"]):
                for addr in targets["addr"]:
                    idx = self._search_write_to(addr, state.bbl_idx-1)
                    # log.debug("search_write_addr: addr = 0x%x, bbl_idx = %d, bbl=0x%x", addr, idx, self._trace.bbls[idx].addr)
                    if idx >= 0:
                        log.debug("--> new state: bbl_idx = %d, bb=0x%x, write_addr=0x%x", idx, self._trace.bbls[idx].addr, addr)
                        new_state = SliceState(idx, target_addrs=[addr])
                        self._target_q.append(new_state)


    def _address_in_taints(self, addr):
        for r in self._trace.taints:
            if addr >= r["start"] and addr < r["start"] + r["size"]:
                return True
        return False

    def _address_in_binary(self, addr):
        mb = self._project.loader.main_bin
        return mb.get_min_addr() <= addr and addr < mb.get_max_addr()

    def _address_in_plt(self, addr):
        plt = self._project.loader.main_bin.sections_map[".plt"]
        return plt.min_addr <= addr and addr < plt.max_addr

    def _search_write_to(self, addr, from_bbl):
        while from_bbl >= 0:
            bbl = self._trace.bbls[from_bbl]
            if bbl.has_write_to(addr):
                break
            from_bbl -= 1
        return from_bbl


    def _backward_slice_plt_stub_strcpy(self, bbl, state):
        state.targets["tmp"] = set()
        state.targets["reg"] = set()
        state.targets["addr"] = set(bbl.ext_calls["args"][1])
        return True

    def _backward_slice_plt_stub(self, bbl, state):
        no_trace = set(["printf", "malloc"])
        stub = self._project.loader.find_plt_stub_name(bbl.addr)
        log.info("_slice_plt_stub (%s): %s", stub, bbl.ext_call)
        assert bbl.ext_call["name"] == stub

        in_slice = False
        funcname = "_backward_slice_plt_sub_%s" % stub
        if hasattr(self, funcname):
            in_slice = getattr(self, funcname)(state)
        elif stub not in no_trace:
            # default behavior: slice all arguments
            state.targets["tmp"] = set()
            state.targets["reg"] = set()
            state.targets["addr"] = set(bbl.ext_call["args"])
            state.targets["addr"] = set()
            in_slice = True


        if in_slice:
            call = self._trace.bbls[state.bbl_idx-1].call
            assert call is not None
            self._inst_in_slice.add(call["ins"])

        return False


    def _backward_slice(self, state):
        bbl = self._trace.bbls[state.bbl_idx]
        log.debug("Slice state: block #%d [0x%x], targets: %s", state.bbl_idx, bbl.addr, state.targets)

        if self._address_in_plt(bbl.addr):
            log.debug("  bbl 0x%x in plt, state: %s", bbl.addr, state.targets)
            self._backward_slice_plt_stub(bbl, state)
            return

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

        log.debug("State after block #%d [0x%x], targets: %s", state.bbl_idx, bbl.addr, state.targets)


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

            log.debug(" Store: inst = 0x%x, addr = 0x%x", state.current_ins, concrete_addr)
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
            	log.debug(" Load: inst = 0x%x, addr = 0x%x", state.current_ins, concrete_addr)
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
    if len(sys.argv) != 5:
        print "usage: %s binary tracefile num_bbls slicefile" % sys.argv[0]
        sys.exit(1)


    binary = sys.argv[1]        # "../../test_libressl/test_libressl"
    tracefile = sys.argv[2]     # "../../test_libressl/traces/valid.trace"
    num_bbls = int(sys.argv[3]) # 481972
    slicefile = sys.argv[4]

    try:
        slicer = Slicer(binary, tracefile, num_bbls)
        slicer.run()
        with open(slicefile, 'w') as f:
            f.write(slicer.slice_criterion)
            f.write("\n")
            for line in slicer.line_in_slice:
                f.write(line)
                f.write("\n")
    except SlicerError as e:
        sys.stderr.write("Error: %s" % e)

