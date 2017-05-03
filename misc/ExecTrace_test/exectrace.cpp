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
    "/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "[vdso]"};

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

VOID MallocBefore(VOID *ip, ADDRINT size) {
  outFile << "E"
          << " " << ip << " "
          << "malloc " << size << endl;
}

VOID MemcpyBefore(VOID *ip, ADDRINT dest, ADDRINT src, ADDRINT size) {
  outFile << "E"
          << " " << ip << " "
          << "memcpy"
          << " " << dest << "," << src << "," << size << endl;
  outFile << "R"
          << " " << ip << " "
          << "0x" << hex << src << " " << dec << size << " #memcpy" << endl;
  outFile << "W"
          << " " << ip << " "
          << "0x" << hex << dest << " " << dec << size << " #memcpy" << endl;
}

VOID StrcpyBefore(VOID *ip, ADDRINT dest, ADDRINT src) {
  outFile << "E"
          << " " << ip << " "
          << "strcpy"
          << " " << dest << "," << src << endl;
  INT32 size = strlen((const char *)src);
  outFile << "R"
          << " " << ip << " "
          << "0x" << hex << src << " " << dec << size << " #strcpy" << endl;
  outFile << "W"
          << " " << ip << " "
          << "0x" << hex << dest << " " << dec << size << " #strcpy" << endl;
}

VOID StrlenBefore(VOID *ip, ADDRINT src) {
  outFile << "E"
          << " " << ip << " "
          << "strlen"
          << " " << src << endl;
}

VOID ImageRoutine(IMG img, VOID *v) {
  std::string name = IMG_Name(img);
  std::cout << "[Image Routine: " << name << "(" << hex << IMG_HighAddress(img)
            << "-" << IMG_LowAddress(img) << dec << ")]\n";

  if (std::find(blacklisted_imgs.begin(), blacklisted_imgs.end(), name) !=
          blacklisted_imgs.end() ||
      !IMG_IsMainExecutable(img)) {
    return;
  }

  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    if (SEC_IsExecutable(sec) && SEC_Name(sec) != ".plt") {
      regions.push_back(
          make_pair(SEC_Address(sec), SEC_Address(sec) + SEC_Size(sec)));
    }
  }

  // hook special external functions
  RTN mallocRtn = RTN_FindByName(img, "malloc@plt");
  if (RTN_Valid(mallocRtn)) {
    RTN_Open(mallocRtn);
    RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                   IARG_INST_PTR, IARG_UINT32, RTN_Size(mallocRtn),
                   IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
    RTN_Close(mallocRtn);
  }

  RTN strlenRtn = RTN_FindByName(img, "strlen@plt");
  if (RTN_Valid(strlenRtn)) {
    RTN_Open(strlenRtn);
    RTN_InsertCall(strlenRtn, IPOINT_BEFORE, (AFUNPTR)StrlenBefore,
                   IARG_INST_PTR, IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
    RTN_Close(strlenRtn);
  }

  RTN memcpyRtn = RTN_FindByName(img, "memcpy@plt");
  if (RTN_Valid(memcpyRtn)) {
    RTN_Open(memcpyRtn);
    RTN_InsertCall(memcpyRtn, IPOINT_BEFORE, (AFUNPTR)MemcpyBefore,
                   IARG_INST_PTR, IARG_FUNCARG_CALLSITE_VALUE, 0,
                   IARG_FUNCARG_CALLSITE_VALUE, 1, IARG_FUNCARG_CALLSITE_VALUE,
                   2, IARG_END);
    RTN_Close(memcpyRtn);
  }

  RTN strcpyRtn = RTN_FindByName(img, "strcpy@plt");
  if (RTN_Valid(strcpyRtn)) {
    RTN_Open(strcpyRtn);
    RTN_InsertCall(strcpyRtn, IPOINT_BEFORE, (AFUNPTR)StrcpyBefore,
                   IARG_INST_PTR, IARG_FUNCARG_CALLSITE_VALUE, 0,
                   IARG_FUNCARG_CALLSITE_VALUE, 1, IARG_FUNCARG_CALLSITE_VALUE,
                   2, IARG_END);
    RTN_Close(strcpyRtn);
  }
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
  if (!KnobMem)
    return;
  if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
    start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
    size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
    RecordTaint(start, size);
  }
}

const string *Target2String(ADDRINT target) {
  string name = RTN_FindNameByAddress(target);
  if (name == "")
    return new string("???");
  else
    return new string(name);
}

VOID RecordCall(VOID *ip, ADDRINT target) {
  outFile << "C"
          << " " << ip << " "
          << "0x" << hex << target << dec << endl;
}

VOID TraceRoutine(TRACE trace, VOID *v) {
  if (!ValidAddr(TRACE_Address(trace))) {
    return;
  }

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)RecordBBL,
                   IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_UINT32,
                   BBL_Size(bbl), IARG_END);

    if (!KnobMem)
      continue;

    // instruments function call
    INS tail = BBL_InsTail(bbl);
    if (INS_IsCall(tail)) {
      if (INS_IsDirectBranchOrCall(tail)) {
        const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
        INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)RecordCall, IARG_INST_PTR,
                       IARG_UINT32, target, IARG_END);
      } else {
        INS_InsertCall(tail, IPOINT_BEFORE, (AFUNPTR)RecordCall, IARG_INST_PTR,
                       IARG_BRANCH_TARGET_ADDR, IARG_END);
      }
    }

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
