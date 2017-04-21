import os
import logging
import subprocess

import angr
import pyvex
import simuvex
from simuvex import s_options as so
from slicer import Slicer, SlicerError

log = logging.getLogger("slicer.Tracer")
log.setLevel('DEBUG')

class TracerError(Exception):
    pass

class Tracer(object):
    def __init__(self, binary, argv=None, trace=None):
        self.binary = binary
        self.argv = argv or [binary]
        log.debug("Command: %s", self.argv)
        self._setup()

        log.debug("Collecting basic block trace...")
        self.trace = self.concrete_trace() if trace is None else trace
        log.debug("Trace consists of %d basic block.", len(self.trace))

        self._path_group = self._prepare_paths()

        self._bb_cnt = 0
        self._path = None
        self._previous_addr = None
        self._mem_reads = []
        self._mem_writes = []


    def _setup(self):
        if not os.access(self.binary, os.X_OK):
            if os.path.isfile(self.binary):
                raise TracerError("%s is not executable", self.binary)
            else:
                raise TracerError("%s is not a valid file", self.binary)

        self._project = angr.Project(self.binary, load_options=dict(auto_load_libs=False))
        if self._project.loader.main_bin.os != "unix":
            raise TracerError("%s needs to run on unix" % self.binary)

        mb = self._project.loader.main_bin
        log.debug("main bin: 0x%x - 0x%x", mb.get_min_addr(), mb.get_max_addr())


    def _track_reads(self, state):
        read_addr = state.se.any_int(state.inspect.mem_read_address)
        inst = state.se.any_int(state.regs.ip)
        self._mem_reads.append({
            "inst": inst,
            "addr": read_addr,
            "data": state.inspect.mem_read_expr})


    def _track_writes(self, state):
        write_addr = state.se.any_int(state.inspect.mem_write_address)
        inst = state.se.any_int(state.regs.ip)
        self._mem_writes.append({
            "inst": inst,
            "addr": write_addr,
            "data": state.inspect.mem_read_expr})


    def _prepare_paths(self):
        add_options = set()
        add_options.add(so.BYPASS_UNSUPPORTED_SYSCALL)

        add_options.add(so.UNICORN_HANDLE_TRANSMIT_SYSCALL)
        add_options.add(so.UNICORN)
        # add_options.add(so.CONCRETIZE)
        # add_options.add(so.TRACK_ACTION_HISTORY)

        # fs = {self.argv[1]: simuvex.storage.file.SimFile(self.argv[1], "r")}
        entry_state = self._project.factory.entry_state(
            args=self.argv,
            add_options=add_options)
            # fs=fs,
            # concrete_fs=True,
            # chroot=True)
        entry_state.inspect.b('mem_read', when=simuvex.BP_AFTER, action=self._track_reads)
        entry_state.inspect.b('mem_write', when=simuvex.BP_AFTER, action=self._track_writes)

        pg = self._project.factory.path_group(
            entry_state,
            immutable=False,
            save_unsat=False,
            hierarchy=False)

        if pg.active[0].addr != self.trace[0]:
            log.debug("Step forward from 0x%x to the start of concrete trace", pg.active[0].addr)
            pg = pg.explore(find=self.trace[0])
            pg = pg.unstash(from_stash="found", to_stash="active")
            log.debug("Start Address %d", pg.active[0].addr)
        return pg


    def _address_in_plt(self, addr):
        plt = self._project.loader.main_bin.sections_map['.plt']
        return addr >= plt.min_addr and addr <= plt.max_addr

    def _address_in_binary(self, addr):
        mb = self._project.loader.main_bin
        return mb.get_min_addr() <= addr and addr < mb.get_max_addr()


    def concrete_trace(self):
        # TODO: call pintool
        return [], 0x0

    def next_branch(self):
        while len(self._path_group.active) == 1:
            current = self._path_group.active[0]
            # log.debug("bb: 0x%x, jumpkind: %s", current.addr, current.jumpkind)

            if self._bb_cnt >= len(self.trace):
                return self._path_group

            if current.addr == self.trace[self._bb_cnt]:
                self._bb_cnt += 1
            elif not self._address_in_binary(current.addr):
                while self._address_in_plt(self.trace[self._bb_cnt]):
                    self._bb_cnt += 1
            else:
                log.error("concrete trace and symbolic trace disagreed")
                raise TracerError("[%s] dynamic [0x%x], symbolic [0x%x]", \
                                  self.binary, self.trace[self._bb_cnt], current.addr)

            self._path = current
            self._previous_addr = current.addr
#            self._path.trim_history()
            self._path_group = self._path_group.step()

        return self._path_group


    def run(self):
        log.debug("Running symbolically on a concrete trace...")
        branches = self.next_branch()
        while len(branches.active) and self._bb_cnt < len(self.trace):
            branches = self.next_branch()

            if len(self._path_group.active) > 1:
                self._path_group = self._path_group.stash_not_addr(
                    self.trace[self._bb_cnt], to_stash="missed")
                assert len(self._path_group.active) == 1

        if len(branches.active) == 0:
            if self._bb_cnt < len(self.trace):
                if self._path.jumpkind.startswith("ju.Ijk_Exit"):
                    self._bb_cnt = len(self.trace)

        if self._bb_cnt < len(self.trace):
            log.debug("Dynamic trace does not end: next 0x%x", self.trace[self._bb_cnt])
            raise TracerError

        if len(branches.active):
            self._path = branches.active[0]
            log.debug("Last address: 0x%x", self._previous_addr)


    def _slice_from_last_condition(self):
        block = self._project.factory.block(self._previous_addr).vex
        cond = block.statements[-1]
        if not isinstance(cond, pyvex.stmt.Exit):
            log.error("Last seen statement is %s", cond)
            raise SlicerError("Must slice from a conditional exit")
        if isinstance(cond.guard, pyvex.expr.RdTmp):
            return ([cond.guard.tmp], None, None)

        # TODO (other cases?)
        return (None, None, None)


    def slice(self):
        target_tmps, target_regs, target_addrs = self._slice_from_last_condition()

        try:
            slicer = Slicer(self._project, self._path, \
                            target_tmps, target_regs, target_addrs, \
                            self._mem_reads, self._mem_writes)
            slicer.slice()
        except SlicerError:
            raise TracerError("Slicer failed")

        sources = self.insts_to_source(sorted(slicer.instructions))
        for line in sources:
            print line

    def insts_to_source(self, instructions):
        args = ["addr2line", "-e", self.binary]
        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        p.stdin.write("\n".join([hex(i) for i in instructions]))
        p.stdin.close()
        sources = sorted(set(p.stdout.read().splitlines()))
        return sources



