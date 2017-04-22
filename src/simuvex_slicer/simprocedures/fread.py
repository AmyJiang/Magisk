import simuvex
from simuvex.procedures.libc___so___6.fread import fread

class fread_taint(fread):
    taints = []
    def run(self, dst, size, nm, file_ptr):
        addr = self.state.se.any_int(dst)
        ss = self.state.se.any_int(size)
        type(self).taints.append((addr, addr+ss))
        return super(fread_taint, self).run(dst, size, nm, file_ptr)

