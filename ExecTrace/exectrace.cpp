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

static ADDRINT last_bb = ADDR_MAX;
ExecutionTrace execution_trace;

VOID ImageRoutine(IMG img, VOID *v) {
    std::string name = IMG_Name(img);
    MemoryRegion region;
    region.base = IMG_LowAddress(img);
    region.size = IMG_HighAddress(img) - IMG_LowAddress(img);
    region.filename = name;
    execution_trace.AddRegion(region);
}


VOID TraceRoutine(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT bb_current = BBL_Address(bbl);
        // filter out libc.so.6?
        execution_trace.AddEdge(last_bb, bb_current);
        last_bb = bb_current;
    }
}


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


VOID printproc(RTN_SUM* rs) {
    std::cout << rs->_name << ":" << rs->_image << std::endl;
}


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

VOID Fini(INT32 code, VOID *v) {
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
    RTN_AddInstrumentFunction(InstrRoutine, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
