#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <string.h>

#include "exectrace.h"
#include "pin.H"

ofstream outFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "exectrace.out", "trace output");

static const std::string blacklisted_imgs_[] = {
    "/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/lib/x86_64-linux-gnu/libc.so.6"
};

static std::vector<std::string>  blacklisted_imgs(blacklisted_imgs_, blacklisted_imgs_+sizeof(blacklisted_imgs_) / sizeof(std::string));

ExecutionTrace execution_trace;
std::vector<std::pair<ADDRINT, ADDRINT>> regions;


VOID ImageRoutine(IMG img, VOID *v) {
    std::string name = IMG_Name(img);
    if (std::find(blacklisted_imgs.begin(), blacklisted_imgs.end(), name) != blacklisted_imgs.end()) {
        return;
    }

    std::cout << "[Image Routine: " << name << "]\n";
    MemoryRegion region;
    region.base = IMG_LowAddress(img);
    region.size = IMG_HighAddress(img) - IMG_LowAddress(img);
    region.filename = name;
    execution_trace.AddRegion(region);

    regions.push_back(make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
}


BOOL ValidAddr(ADDRINT bb_addr) {
    for (unsigned int i = 0; i < regions.size(); i++) {
        if (bb_addr >= regions[i].first && bb_addr < regions[i].second) {
            return true;
        }
    }
    return false;
}

VOID TraceRoutine(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT bb_current = BBL_Address(bbl);
        if (!ValidAddr(bb_current)) continue;
        execution_trace.AddBB(bb_current);
    }
}

/*
const char * StripPath(const char * path) {
    const char * file = strrchr(path,'/');
    if (file)
        return file+1;
    else
        return path;
}

typedef struct {
    string _name;
    string _image;
    ADDRINT _address;
    RTN _rtn;
} RTN_SUM;


VOID InstrRoutine(RTN rtn, VOID *v) {
    string image =  StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    if (image != "test") return;

    RTN_SUM* rc = new RTN_SUM;
    rc->_name = RTN_Name(rtn);
    rc->_image = image;
    rc->_address = RTN_Address(rtn);
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)printproc, IARG_PTR, rc, IARG_END);
    RTN_Close(rtn);

    delete rc;
}
*/

VOID Fini(INT32 code, VOID *v) {
    std::cout << "[Finished Routine]\n";
    string trace = execution_trace.Serialize();
    outFile << trace << "\n";
    outFile.close();
}


INT32 Usage() {
    cerr << "This Pintool prints the execution trace of the target binary\n";
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


int main(int argc, char * argv[]) {
    PIN_InitSymbols();

    string filename = KnobOutputFile.Value();

    outFile.open(filename.c_str());

    if (PIN_Init(argc, argv)) return Usage();

    IMG_AddInstrumentFunction(ImageRoutine, 0);

    TRACE_AddInstrumentFunction(TraceRoutine, 0);
    // ???
    // RTN_AddInstrumentFunction(InstrRoutine, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
