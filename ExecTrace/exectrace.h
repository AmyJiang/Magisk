#ifndef _exectrace_H
#define _exectrace_H

#include <map>
#include <string>
#include <sstream>
#include <cassert>
#include <stdint.h>
#include <iomanip>

typedef uint64_t ADDR;
const ADDR ADDR_MAX = UINT64_MAX;

typedef struct {
    ADDR base;
    unsigned int size;
    std::string filename;
} MemoryRegion;


class ExecutionTrace {
public:
    ExecutionTrace() {}

    void AddBB(ADDR bb_addr, uint32_t size) {
        trace_.push_back(std::make_pair(bb_addr, size));
    }


    void AddRegion(MemoryRegion& region) {
        regions_.push_back(region);
    }


    std::string Serialize() {
        std::stringstream str;
        str << "==== Memory Regions ====\n";
        for (unsigned int i = 0; i < regions_.size(); i++) {
            str << "Base: " << regions_[i].base << ", " << "Size: " << regions_[i].size << ", Name: " << regions_[i].filename << "\n";
        }
        str << "==== Execution Trace ====\n";
        for (unsigned int i = 0; i < trace_.size(); i++) {
            str << std::hex << trace_[i].first << ":" << std::dec << trace_[i].second;
            str << "\n";
        }
        return str.str();
    }

private:
    std::vector<std::pair<ADDR, uint32_t> > trace_;
    std::vector<MemoryRegion> regions_;
};



#endif
