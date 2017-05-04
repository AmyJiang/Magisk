#ifndef __FUNC_H
#define __FUNC_H

#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#include "pin.H"

std::ofstream TraceFile;

const int kMaxOutput = 1 << 24;
uint64_t *output_data = NULL;
uint64_t *output_pos = NULL;
uint64_t total = 0;


void write_output(uint64_t v) {
  if (output_pos < output_data ||
      (char *)output_pos >= (char *)output_data + kMaxOutput) {
    std::cerr << "output overflowed" << std::endl;
    return;
  }
  *output_pos = v;
  output_pos++;
}

static VOID RecordMem(VOID *ip, CHAR r, VOID *addr, INT32 size) {
  TraceFile << r << " " << ip << " " << addr << " " << size << endl;
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

static VOID PIN_FAST_ANALYSIS_CALL RecordBBL(VOID *ip, UINT32 size) {
  write_output((uint64_t)ip);
  total++;
  TraceFile << "B"
          << " " << ip << " " << size << endl;
}

static VOID RecordExtCall(VOID *ip, const char* name, int count, ...) {
  va_list args;
  va_start(args, count);
  TraceFile << "E" << " " << ip << " " << name;
  for (int i = 0; i <  count; i++) {
    TraceFile << " " << va_arg(args, ADDRINT);
  }
  va_end(args);
  TraceFile << "\n";
}

static VOID RecordCall(VOID *ip, UINT32 target) {
  TraceFile << "C" << " " << ip << " " << "0x" << hex << target << dec << endl;
}


static VOID RecordTaint(VOID *ip, UINT64 start, UINT64 size) {
  TraceFile << "T" << " "  << ip << " " << start << " " << size << endl;
}


#endif

