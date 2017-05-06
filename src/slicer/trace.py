import os
class TraceError(Exception):
    pass

class BBLRecord(object):
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
        self.mem_writes = []
        self.mem_reads = []
        self._ext_call = None
        self._call = None

    def __repr__(self):
        return "<BBLRecord 0x%x: %d bytes with %d mem_writes and %d mem_reads>" % \
            (self.addr, self.size, len(self.mem_writes), len(self.mem_reads))


    def has_write_to(self, addr):
        for mem in self.mem_writes:
            if mem["addr"] == addr:
                return True
        return False


    def write_addr(self, ins):
        for mem in self.mem_writes:
            if mem["ins"] == ins:
                return mem["addr"]
        return None


    def read_addr(self, ins):
        for mem in self.mem_reads:
            if mem["ins"] == ins:
                return mem["addr"]
        return None

    def add_mem_read(self, record):
        self.mem_reads.append(record)

    def add_mem_write(self, record):
        self.mem_writes.append(record)

    def add_ext_call(self, record):
        self._ext_call = record

    def add_call(self, record):
        self._call = record

    @property
    def ext_call(self):
        return self._ext_call

    @property
    def call(self):
        return self._call




class Trace(object):
    def __init__(self, tracefile, num_bbl=None):
        self._bbls = []
        self._taints = []

        bbl_cnt = 0
        with open(tracefile, 'r') as f:
            for line in f.readlines():
                fields = line.split()
                if fields[0] == 'B':
                    if int(fields[2]) == 0:
                        continue
                    bbl_cnt += 1
                    if num_bbl and bbl_cnt > num_bbl:
                        break
                    self._bbls.append(BBLRecord(int(fields[1], 16), int(fields[2])))
                elif fields[0] == 'E':
                    record = {
                        "ins": int(fields[1], 16),
                        "name": fields[2],
                        "args": [int(a, 10) for a in fields[3:]]
                    }
                    bbl_cnt += 1
                    self._bbls.append(BBLRecord(int(fields[1], 16), None))
                    self._bbls[bbl_cnt-1].add_ext_call(record)
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
                elif fields[0] == 'C':
                    record = {
                        "ins": int(fields[1], 16),
                        "target": int(fields[2], 16)
                    }
                    if bbl_cnt > 0:
                        self._bbls[bbl_cnt-1].add_call(record)
                elif fields[0] == 'T':
                    self._taints.append({
                        "ins": int(fields[1], 16),
                        "start": int(fields[2], 10),
                        "size": int(fields[3], 10)
                    })
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






