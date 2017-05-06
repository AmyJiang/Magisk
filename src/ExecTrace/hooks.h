#ifndef __HOOKS_H
#define __HOOKS_H

#include "func.h"

VOID MallocBefore(VOID *ip, ADDRINT size) {
  RecordBBL(ip, 0);
  RecordExtCall(ip, "malloc", 1, size);
}

VOID MemcpyBefore(VOID *ip, ADDRINT dest, ADDRINT src, ADDRINT size) {
  RecordBBL(ip, 0);
  RecordExtCall(ip, "memcpy", 3, dest, src, size);
  RecordMem(ip, 'R', (VOID *)src, size);
  RecordMem(ip, 'W', (VOID *)dest, size);
}

VOID StrcpyBefore(VOID *ip, ADDRINT dest, ADDRINT src) {
  INT32 size = strlen((const char *)src);

  RecordBBL(ip, 0);
  RecordExtCall(ip, "strcpy", 2, dest, src);
  RecordMem(ip, 'R', (VOID *)src, size);
  RecordMem(ip, 'W', (VOID *)dest, size);
}

VOID StrlenBefore(VOID *ip, ADDRINT src) {
  RecordBBL(ip, 0);
  RecordExtCall(ip, "strlen", 1, src);
}

VOID FreadBefore(VOID *ip, ADDRINT ptr, ADDRINT size, ADDRINT nmemb) {
  RecordTaint(ip, ptr, size * nmemb);
}

VOID HookImage(IMG img) {
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

  RTN freadRtn = RTN_FindByName(img, "fread@plt");
  if (RTN_Valid(freadRtn)) {
    RTN_Open(freadRtn);
    RTN_InsertCall(freadRtn, IPOINT_BEFORE, (AFUNPTR)FreadBefore, IARG_INST_PTR,
                   IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_FUNCARG_CALLSITE_VALUE,
                   1, IARG_FUNCARG_CALLSITE_VALUE, 2, IARG_END);
    RTN_Close(freadRtn);
  }
}

VOID HookImage_bblonly(IMG img) {
  // hook special external functions
  RTN mallocRtn = RTN_FindByName(img, "malloc@plt");
  if (RTN_Valid(mallocRtn)) {
    RTN_Open(mallocRtn);
    RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)WriteOutput,
                   IARG_INST_PTR, IARG_UINT32, 0, IARG_END);
    RTN_Close(mallocRtn);
  }

  RTN strlenRtn = RTN_FindByName(img, "strlen@plt");
  if (RTN_Valid(strlenRtn)) {
    RTN_Open(strlenRtn);
    RTN_InsertCall(strlenRtn, IPOINT_BEFORE, (AFUNPTR)WriteOutput,
                   IARG_INST_PTR, IARG_UINT32, 0, IARG_END);
    RTN_Close(strlenRtn);
  }

  RTN memcpyRtn = RTN_FindByName(img, "memcpy@plt");
  if (RTN_Valid(memcpyRtn)) {
    RTN_Open(memcpyRtn);
    RTN_InsertCall(memcpyRtn, IPOINT_BEFORE, (AFUNPTR)WriteOutput,
                   IARG_INST_PTR, IARG_UINT32, 0, IARG_END);
    RTN_Close(memcpyRtn);
  }

  RTN strcpyRtn = RTN_FindByName(img, "strcpy@plt");
  if (RTN_Valid(strcpyRtn)) {
    RTN_Open(strcpyRtn);
    RTN_InsertCall(strcpyRtn, IPOINT_BEFORE, (AFUNPTR)WriteOutput,
                   IARG_INST_PTR, IARG_UINT32, 0, IARG_END);
    RTN_Close(strcpyRtn);
  }

  RTN freadRtn = RTN_FindByName(img, "fread@plt");
  if (RTN_Valid(freadRtn)) {
    RTN_Open(freadRtn);
    RTN_InsertCall(freadRtn, IPOINT_BEFORE, (AFUNPTR)WriteOutput,
                   IARG_INST_PTR, IARG_UINT32, 0, IARG_END);
    RTN_Close(freadRtn);
  }
}



#endif
