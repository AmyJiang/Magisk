import os
class TraceError(Exception):
    pass

class BBLRecord(object):
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
        self._mem_writes = []
        self._mem_reads = []

    def __repr__(self):
        return "<BBLRecord 0x%x: %d bytes with %d mem_writes and %d mem_reads>" % \
            (self.addr, self.size, len(self._mem_writes), len(self._mem_reads))


    def has_write_to(self, addr):
        for mem in self._mem_writes:
            if mem["addr"] == addr:
                return True
        return False


    def write_addr(self, ins):
        for mem in self._mem_writes:
            if mem["ins"] == ins:
                return mem["addr"]
        return None


    def read_addr(self, ins):
        for mem in self._mem_reads:
            if mem["ins"] == ins:
                return mem["addr"]
        return None

    def add_mem_read(self, record):
        self._mem_reads.append(record)

    def add_mem_write(self, record):
        self._mem_writes.append(record)


class Trace(object):
    def __init__(self, tracefile, num_bbl=None):
        self._bbls = []
        self._taints = []

        bbl_cnt = 0
        with open(tracefile, 'r') as f:
            for line in f.readlines():
                fields = line.split()
                if fields[0] == 'B':
                    bbl_cnt += 1
                    if num_bbl and bbl_cnt > num_bbl:
                        break
                    self._bbls.append(BBLRecord(int(fields[1], 16), int(fields[2])))
                elif fields[0] == 'T':
                    start = int(fields[1])
                    size = int(fields[2])
                    self._taints.append((start, size))
                elif fields[0] == 'W' or fields[0] == 'R':
                    record = {
                        "ins": int(fields[1], 16),
                        "addr": int(fields[2], 16),
                        "size": int(fields[3])
                    }
                    if fields[0] == 'W':
                        self._bbls[bbl_cnt-1].add_mem_write(record)
                    elif fields[0] == 'R':
                        self._bbls[bbl_cnt-1].add_mem_read(record)
                else:
                    raise TraceError("Unknown record format")

    @property
    def bbls(self):
        return self._bbls


    @property
    def taints(self):
        return self._taints

    @property
    def last_bbl(self):
        assert len(self._bbls)
        return self._bbls[-1]

    def __repr__(self):
        return "<Trace with %d BBL>" % (len(self.bbls))


if __name__ == "__main__":
    # test
    num_bbl = 40
    trace = Trace("../../test_slice/traces/1.trace", num_bbl)
    print trace
    for bbl in trace.bbls:
        print bbl






