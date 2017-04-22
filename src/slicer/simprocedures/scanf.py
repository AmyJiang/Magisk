import simuvex
from simuvex.procedures.libc___so___6.scanf import scanf

class scanf_taint(scanf):
    taints = []
    def run(self, fmt):
        addr = self.state.se.any_int(self.arg(1))
        type(self).taints.append((addr, addr))
        return (super(scanf_taint, self)).run(fmt)

