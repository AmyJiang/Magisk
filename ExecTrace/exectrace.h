#ifndef _exectrace_H
#define _exectrace_H

#include <map>
#include <string>
#include <sstream>
#include <cassert>
#include <stdint.h>

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

    void AddBB(ADDR bb_addr) {
        trace_.push_back(bb_addr);
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
            for (unsigned int j = 0; j < regions_.size(); j++) {
                if (trace_[i] >= regions_[j].base) {
                    unsigned int ra = trace_[i] - regions_[j].base;
                    if (ra < regions_[j].size) {
                        str << regions_[j].filename << ":" << ra;
                        break;
                    }
                }
            }
            str << "\n";
        }
        return str.str();
    }

private:
    std::vector<ADDR> trace_;
    std::vector<MemoryRegion> regions_;
};



#endif
