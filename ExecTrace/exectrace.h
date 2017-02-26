#ifndef _exectrace_H
#define _exectrace_H

#include <map>
#include <string>
#include <sstream>
#include <cassert>
#include <stdint.h>

typedef uint32_t ADDR;
const ADDR ADDR_MAX = UINT32_MAX;

typedef struct {
    ADDR base;
    unsigned int size;
    std::string filename;
} MemoryRegion;


class ExecutionTrace {
public:
    ExecutionTrace() {}

    void AddEdge(ADDR prev, ADDR next) {
        if (trace_.size() == 0) {
            trace_.push_back(next);
        } else {
            assert(trace_.back() == prev);
            trace_.push_back(next);
        }
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
            str << trace_[i];
            for (unsigned int j = 0; i < regions_.size(); j++) {
                if (trace_[i] >= regions_[j].base
                    && trace_[i] - regions_[j].base < regions_[j].size) {
                    str << "=>" << regions_[j].filename << ":" << trace_[i] - regions_[j].base;
                    break;
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
