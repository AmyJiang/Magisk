#ifndef __FUNC_H
#define __FUNC_H

#include <assert.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#include "pin.H"

//#define DEBUG
#ifdef DEBUG
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_printf(...)
#endif

// std::ofstream TraceFile;
std::FILE *TraceFile;

const int kMaxOutput = 1 << 24;
uint64_t *output_data = NULL;
uint64_t *output_pos = NULL;
uint64_t total = 0;

void inline write_output(uint64_t v) {
  if (output_pos < output_data ||
      (char *)output_pos >= (char *)output_data + kMaxOutput) {
    std::cerr << "output overflowed" << std::endl;
    return;
  }
  *output_pos = v;
  output_pos++;
}

static VOID PIN_FAST_ANALYSIS_CALL RecordMem(VOID *ip, CHAR r, VOID *addr,
                                             UINT32 size) {
  fprintf(TraceFile, "%c %lx %lx %d\n", r, (uint64_t)ip, (uint64_t)addr, size);
}

static VOID *WriteAddr;
static UINT32 WriteSize;

static VOID PIN_FAST_ANALYSIS_CALL RecordWriteAddrSize(VOID *addr,
                                                       UINT32 size) {
  WriteAddr = addr;
  WriteSize = size;
}

static VOID PIN_FAST_ANALYSIS_CALL RecordMemWrite(VOID *ip) {
  fprintf(TraceFile, "%c %lx %lx %d\n", 'W', (uint64_t)ip, (uint64_t)WriteAddr,
          WriteSize);
}

static VOID PIN_FAST_ANALYSIS_CALL WriteOutput(VOID *ip, UINT32 size) {
  write_output((uint64_t)ip);
  total++;
  fprintf(TraceFile, "%c %lx %d\n", 'B', (uint64_t)ip, size);
}

static VOID PIN_FAST_ANALYSIS_CALL RecordBBL(VOID *ip, UINT32 size) {
  fprintf(TraceFile, "%c %lx %d\n", 'B', (uint64_t)ip, size);
}

/*
static VOID PIN_FAST_ANALYSIS_CALL RecordCall(VOID *ip, UINT32 target) {
  fprintf(TraceFile, "%c %lx %x\n", 'C', (uint64_t)ip, target);
}
*/

static VOID RecordExtCall(VOID *ip, const char *name, int count, ...) {
  va_list args;
  va_start(args, count);

  fprintf(TraceFile, "%c %lx %s", 'E', (uint64_t)ip, name);
  for (int i = 0; i < count; i++) {
    fprintf(TraceFile, "  %ld", va_arg(args, uint64_t));
  }
  va_end(args);
  fprintf(TraceFile, "\n");
}

static inline VOID RecordTaint(VOID *ip, UINT64 start, UINT64 size) {
  fprintf(TraceFile, "%c %lx %ld %ld\n", 'T', (uint64_t)ip, start, size);
}

#endif
