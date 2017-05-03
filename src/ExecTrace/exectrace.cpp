#include "func.h"
#include "hooks.h"

extern std::ofstream TraceFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o",
                            "exectrace.out",
                            "specify trace (memory access) file name");

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
std::vector<std::pair<ADDRINT, ADDRINT> > regions;

const int kOutFd = 3;

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

  HookImage(img);
}

BOOL ValidAddr(ADDRINT addr) {
  for (unsigned int i = 0; i < regions.size(); i++) {
    if (addr >= regions[i].first && addr <= regions[i].second) {
      return true;
    }
  }
  return false;
}

VOID TraceRoutine(TRACE trace, VOID *v) {
  if (!ValidAddr(TRACE_Address(trace)))
    return;

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
  *output_data = total;
  TraceFile.close();
}

INT32 Usage() {
  std::cerr << "This Pintool prints the execution trace of the target binary\n";
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

void output_init() {
  output_data =
      (uint64_t *)mmap(NULL, kMaxOutput, PROT_WRITE, MAP_SHARED, kOutFd, 0);
  close(kOutFd);
  if (output_data == MAP_FAILED) {
    std::cerr << "mmap of output failed" << std::endl;
    exit(1);
  }
  output_pos = output_data;
  write_output(0);
}

int main(int argc, char *argv[]) {
  output_init();

  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();

  if (KnobMem) {
    TraceFile.open(KnobOutputFile.Value().c_str());
  }

  IMG_AddInstrumentFunction(ImageRoutine, 0);

  TRACE_AddInstrumentFunction(TraceRoutine, 0);

  PIN_AddFiniFunction(Fini, 0);

  PIN_StartProgram();

  return 0;
}
