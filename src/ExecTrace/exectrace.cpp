#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>
#include <sys/mman.h>

#include "pin.H"

static const std::string blacklisted_imgs_[] = {
    "/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/lib/x86_64-linux-gnu/libc.so.6"
};

static std::vector<std::string>  blacklisted_imgs(blacklisted_imgs_, blacklisted_imgs_+sizeof(blacklisted_imgs_) / sizeof(std::string));
std::vector<std::pair<ADDRINT, ADDRINT> > regions;

const int kOutFd = 3;
const int kMaxOutput = 1 << 24;
uint64_t* output_data = NULL;
uint64_t* output_pos  = NULL;
uint64_t total = 0;


VOID ImageRoutine(IMG img, VOID *v) {
    std::string name = IMG_Name(img);
    if (!IMG_IsMainExecutable(img)) {
        return;
    }
    if (std::find(blacklisted_imgs.begin(), blacklisted_imgs.end(), name) != blacklisted_imgs.end()) {
        return;
    }
    regions.push_back(make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
}


BOOL ValidAddr(ADDRINT addr) {
    for (unsigned int i = 0; i < regions.size(); i++) {
        if (addr >= regions[i].first && addr <= regions[i].second) {
            return true;
        }
    }
    return false;
}


void write_output(uint64_t v) {
    if (output_pos < output_data || (char*)output_pos >= (char*)output_data + kMaxOutput) {
        std::cerr << "output overflowed" << std::endl;
        return;
    }
    *output_pos = v;
    output_pos++;
}



VOID PIN_FAST_ANALYSIS_CALL handle_bb(UINT32 num_instr, ADDRINT address) {
    write_output(address);
    total++;
}


VOID TraceRoutine(TRACE trace, VOID *v) {
    if (!ValidAddr(TRACE_Address(trace))) return;

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        BBL_InsertCall(
            bbl,
            IPOINT_BEFORE,
            (AFUNPTR)handle_bb,
            IARG_FAST_ANALYSIS_CALL,
            IARG_UINT32,
            BBL_NumIns(bbl),
            IARG_ADDRINT,
            BBL_Address(bbl),
            IARG_END
        );
    }
}

VOID Fini(INT32 code, VOID *v) {
    *output_data = total;
}


INT32 Usage() {
    std::cerr << "This Pintool prints the execution trace of the target binary\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}


void output_init() {
    output_data = (uint64_t*) mmap(NULL, kMaxOutput, PROT_WRITE, MAP_SHARED, kOutFd, 0);
    close(kOutFd);
    if (output_data == MAP_FAILED) {
        std::cerr << "mmap of output failed" << std::endl;
        exit(1);
    }
    output_pos = output_data;
    write_output(0);
}


int main(int argc, char * argv[]) {
    output_init();

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    IMG_AddInstrumentFunction(ImageRoutine, 0);

    TRACE_AddInstrumentFunction(TraceRoutine, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
