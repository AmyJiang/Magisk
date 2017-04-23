#include <asm/unistd.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <string>
#include <vector>

#include "exectrace.h"
#include "pin.H"

ofstream outFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o",
                            "exectrace.out", "trace output");

KNOB<BOOL> KnobMem(KNOB_MODE_WRITEONCE, "pintool", "mem", "0",
                   "output memory access trace");

static const std::string blacklisted_imgs_[] = {
    "/lib64/ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/lib/x86_64-linux-gnu/libc.so.6"};

static std::vector<std::string> blacklisted_imgs(blacklisted_imgs_,
                                                 blacklisted_imgs_ +
                                                     sizeof(blacklisted_imgs_) /
                                                         sizeof(std::string));

std::vector<std::pair<ADDRINT, ADDRINT>> regions;

static VOID RecordMem(VOID *ip, CHAR r, VOID *addr, INT32 size) {
  outFile << r << " " << ip << " " << addr << " " << size << endl;
}

static VOID *WriteAddr;
static INT32 WriteSize;

static VOID RecordWriteAddrSize(VOID *addr, INT32 size) {
  WriteAddr = addr;
  WriteSize = size;
}

static VOID RecordMemWrite(VOID *ip) {
  RecordMem(ip, 'W', WriteAddr, WriteSize);
}

static VOID RecordTaint(UINT64 start, UINT64 size) {
  outFile << "T"
          << " " << start << " " << size << endl;
}

static VOID PIN_FAST_ANALYSIS_CALL RecordBBL(VOID *ip, UINT32 size) {
  outFile << "B"
          << " " << ip << " " << size << endl;
}

VOID ImageRoutine(IMG img, VOID *v) {
  std::string name = IMG_Name(img);
  if (!IMG_IsMainExecutable(img)) {
    return;
  }
  if (std::find(blacklisted_imgs.begin(), blacklisted_imgs.end(), name) !=
      blacklisted_imgs.end()) {
    return;
  }

  std::cout << "[Image Routine: " << name << "]\n";
  MemoryRegion region;
  region.base = IMG_LowAddress(img);
  region.size = IMG_HighAddress(img) - IMG_LowAddress(img);
  region.filename = name;
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

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std,
                   void *v) {
  UINT64 start, size;
  if (!KnobMem) return;
  if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
    start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
    size =  static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
    RecordTaint(start, size);
  }
}

VOID TraceRoutine(TRACE trace, VOID *v) {
  if (!ValidAddr(TRACE_Address(trace))) {
    return;
  }

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)RecordBBL,
                   IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR,
                   IARG_UINT32, BBL_Size(bbl), IARG_END);

    if (!KnobMem)
      continue;

    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

      // instruments loads using a predicated call, i.e.
      // the call happens iff the load will be actually executed

      if (INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordMem, IARG_INST_PTR, IARG_UINT32,
            'R', IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
      }

      if (INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordMem, IARG_INST_PTR, IARG_UINT32,
            'R', IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
      }

      // instruments stores using a predicated call, i.e.
      // the call happens iff the store will be actually executed
      if (INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins)) {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize,
            IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);

        if (INS_HasFallThrough(ins)) {
          INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite,
                         IARG_INST_PTR, IARG_END);
        }
        if (INS_IsBranchOrCall(ins)) {
          INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite,
                         IARG_INST_PTR, IARG_END);
        }
      }
    }
  }
}

VOID Fini(INT32 code, VOID *v) {
  std::cout << "[Finished Routine]\n";
  outFile.close();
}

INT32 Usage() {
  cerr << "This Pintool prints the execution trace of the target binary\n";
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

int main(int argc, char *argv[]) {
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();

  string filename = KnobOutputFile.Value();
  outFile.open(filename.c_str());

  IMG_AddInstrumentFunction(ImageRoutine, 0);

  TRACE_AddInstrumentFunction(TraceRoutine, 0);

  PIN_AddSyscallEntryFunction(Syscall_entry, 0);
  PIN_AddFiniFunction(Fini, 0);

  PIN_StartProgram();

  return 0;
}
