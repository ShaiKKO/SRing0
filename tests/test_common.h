/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_common.h
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Summary:
 *   SafeRing0 Test Suite - Common Definitions
 *   Shared macros, helpers, and declarations for all test modules.
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <windows.h>

/*--------------------------------------------------------------------------*/
/* WinRing0 DLL Function Declarations                                       */
/*--------------------------------------------------------------------------*/

/* Initialization */
typedef BOOL(WINAPI* PFN_InitializeOls)(void);
typedef void(WINAPI* PFN_DeinitializeOls)(void);

/* Status */
typedef DWORD(WINAPI* PFN_GetDllStatus)(void);
typedef DWORD(WINAPI* PFN_GetDriverVersion)(void);

/* MSR */
typedef BOOL(WINAPI* PFN_Rdmsr)(DWORD index, PDWORD eax, PDWORD edx);
typedef BOOL(WINAPI* PFN_RdmsrEx)(DWORD index, PDWORD eax, PDWORD edx,
                                  DWORD_PTR affinity);
typedef BOOL(WINAPI* PFN_Wrmsr)(DWORD index, DWORD eax, DWORD edx);
typedef BOOL(WINAPI* PFN_WrmsrEx)(DWORD index, DWORD eax, DWORD edx,
                                  DWORD_PTR affinity);

/* I/O Port */
typedef BYTE(WINAPI* PFN_ReadIoPortByte)(WORD port);
typedef WORD(WINAPI* PFN_ReadIoPortWord)(WORD port);
typedef DWORD(WINAPI* PFN_ReadIoPortDword)(WORD port);
typedef void(WINAPI* PFN_WriteIoPortByte)(WORD port, BYTE value);
typedef void(WINAPI* PFN_WriteIoPortWord)(WORD port, WORD value);
typedef void(WINAPI* PFN_WriteIoPortDword)(WORD port, DWORD value);

/* Physical Memory */
typedef DWORD(WINAPI* PFN_ReadMemory)(DWORD_PTR address, PBYTE buffer,
                                      DWORD count, DWORD unitSize);
typedef DWORD(WINAPI* PFN_WriteMemory)(DWORD_PTR address, PBYTE buffer,
                                       DWORD count, DWORD unitSize);

/* PCI */
typedef BYTE(WINAPI* PFN_ReadPciConfigByte)(DWORD pciAddress, BYTE regAddress);
typedef WORD(WINAPI* PFN_ReadPciConfigWord)(DWORD pciAddress, BYTE regAddress);
typedef DWORD(WINAPI* PFN_ReadPciConfigDword)(DWORD pciAddress,
                                              BYTE regAddress);
typedef void(WINAPI* PFN_WritePciConfigByte)(DWORD pciAddress, BYTE regAddress,
                                             BYTE value);
typedef void(WINAPI* PFN_WritePciConfigWord)(DWORD pciAddress, BYTE regAddress,
                                             WORD value);
typedef void(WINAPI* PFN_WritePciConfigDword)(DWORD pciAddress, BYTE regAddress,
                                              DWORD value);

/* HLT */
typedef BOOL(WINAPI* PFN_Hlt)(void);

/*--------------------------------------------------------------------------*/
/* Global Function Pointers                                                 */
/*--------------------------------------------------------------------------*/

extern PFN_InitializeOls pfnInitializeOls;
extern PFN_DeinitializeOls pfnDeinitializeOls;
extern PFN_GetDllStatus pfnGetDllStatus;
extern PFN_GetDriverVersion pfnGetDriverVersion;
extern PFN_Rdmsr pfnRdmsr;
extern PFN_RdmsrEx pfnRdmsrEx;
extern PFN_Wrmsr pfnWrmsr;
extern PFN_WrmsrEx pfnWrmsrEx;
extern PFN_ReadIoPortByte pfnReadIoPortByte;
extern PFN_ReadIoPortWord pfnReadIoPortWord;
extern PFN_ReadIoPortDword pfnReadIoPortDword;
extern PFN_WriteIoPortByte pfnWriteIoPortByte;
extern PFN_WriteIoPortWord pfnWriteIoPortWord;
extern PFN_WriteIoPortDword pfnWriteIoPortDword;
extern PFN_ReadMemory pfnReadMemory;
extern PFN_WriteMemory pfnWriteMemory;
extern PFN_ReadPciConfigByte pfnReadPciConfigByte;
extern PFN_ReadPciConfigWord pfnReadPciConfigWord;
extern PFN_ReadPciConfigDword pfnReadPciConfigDword;
extern PFN_WritePciConfigByte pfnWritePciConfigByte;
extern PFN_WritePciConfigWord pfnWritePciConfigWord;
extern PFN_WritePciConfigDword pfnWritePciConfigDword;
extern PFN_Hlt pfnHlt;

/*--------------------------------------------------------------------------*/
/* Global Test Counters                                                     */
/*--------------------------------------------------------------------------*/

extern int g_TestCount;
extern int g_PassCount;
extern int g_FailCount;

/*--------------------------------------------------------------------------*/
/* Test Output Macros                                                       */
/*--------------------------------------------------------------------------*/

#define TEST_PASS(name)            \
  do {                             \
    printf("  [PASS] %s\n", name); \
    g_PassCount++;                 \
  } while (0)

#define TEST_FAIL(name, msg)                 \
  do {                                       \
    printf("  [FAIL] %s - %s\n", name, msg); \
    g_FailCount++;                           \
  } while (0)

#define TEST_SKIP(name, reason)                 \
  do {                                          \
    printf("  [SKIP] %s - %s\n", name, reason); \
  } while (0)

/*--------------------------------------------------------------------------*/
/* Test Assertion Macros                                                    */
/*--------------------------------------------------------------------------*/

#define TEST_ASSERT(cond, name, msg) \
  do {                               \
    g_TestCount++;                   \
    if (cond) {                      \
      TEST_PASS(name);               \
    } else {                         \
      TEST_FAIL(name, msg);          \
    }                                \
  } while (0)

#define TEST_ASSERT_TRUE(cond, name) TEST_ASSERT((cond), name, "Expected TRUE")

#define TEST_ASSERT_FALSE(cond, name) \
  TEST_ASSERT(!(cond), name, "Expected FALSE")

#define TEST_ASSERT_EQ(actual, expected, name)                                 \
  do {                                                                         \
    g_TestCount++;                                                             \
    if ((actual) == (expected)) {                                              \
      TEST_PASS(name);                                                         \
    } else {                                                                   \
      char _msg[256];                                                          \
      sprintf_s(_msg, sizeof(_msg), "Expected 0x%llX, got 0x%llX",             \
                (unsigned long long)(expected), (unsigned long long)(actual)); \
      TEST_FAIL(name, _msg);                                                   \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_NE(actual, notexpected, name)          \
  do {                                                     \
    g_TestCount++;                                         \
    if ((actual) != (notexpected)) {                       \
      TEST_PASS(name);                                     \
    } else {                                               \
      char _msg[256];                                      \
      sprintf_s(_msg, sizeof(_msg), "Expected NOT 0x%llX", \
                (unsigned long long)(notexpected));        \
      TEST_FAIL(name, _msg);                               \
    }                                                      \
  } while (0)

/*--------------------------------------------------------------------------*/
/* Test Category Macros                                                     */
/*--------------------------------------------------------------------------*/

#define TEST_CATEGORY(name)         \
  do {                              \
    printf("\n=== %s ===\n", name); \
  } while (0)

/*--------------------------------------------------------------------------*/
/* MSR Constants for Testing                                                */
/*--------------------------------------------------------------------------*/

/* Security-critical MSRs (should ALWAYS be blocked for writes) */
#define MSR_IA32_LSTAR 0xC0000082
#define MSR_IA32_CSTAR 0xC0000083
#define MSR_IA32_STAR 0xC0000081
#define MSR_IA32_SFMASK 0xC0000084
#define MSR_IA32_SYSENTER_CS 0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_EFER 0xC0000080
#define MSR_IA32_VMX_BASIC 0x480
#define MSR_AMD_SYSCFG 0xC0010010

/* Safe MSRs for reading */
#define MSR_IA32_TSC 0x10
#define MSR_IA32_PLATFORM_INFO 0xCE
#define MSR_IA32_MPERF 0xE7
#define MSR_IA32_APERF 0xE8

/* Whitelisted MSRs (writable with opt-in) */
#define MSR_IA32_PERFEVTSEL0 0x186
#define MSR_IA32_PMC0 0xC1
#define MSR_IA32_PERF_CTL 0x199

/* Invalid MSR for exception testing */
#define MSR_INVALID 0xDEADBEEF

/*--------------------------------------------------------------------------*/
/* Memory Constants                                                         */
/*--------------------------------------------------------------------------*/

#define PHYS_BIOS_START 0xF0000
#define PHYS_BIOS_SIZE 0x10000
#define PHYS_KERNEL_START 0xFFFF800000000000ULL

/*--------------------------------------------------------------------------*/
/* PCI Constants                                                            */
/*--------------------------------------------------------------------------*/

#define PCI_CONFIG_ADDRESS(bus, dev, func, reg)                    \
  (0x80000000UL | (((DWORD)(bus) & 0xFF) << 16) |                  \
   (((DWORD)(dev) & 0x1F) << 11) | (((DWORD)(func) & 0x07) << 8) | \
   ((DWORD)(reg) & 0xFC))

/*--------------------------------------------------------------------------*/
/* Test Function Declarations                                               */
/*--------------------------------------------------------------------------*/

/* test_security.c */
void RunSecurityTests(void);

/* test_msr.c */
void RunMsrTests(void);

/* test_memory.c */
void RunMemoryTests(void);

/* test_ioport.c */
void RunIoPortTests(void);

/* test_pci.c */
void RunPciTests(void);

/* test_ratelimit.c */
void RunRateLimitTests(void);

/*--------------------------------------------------------------------------*/
/* Helper Functions                                                         */
/*--------------------------------------------------------------------------*/

/* Load DLL and resolve function pointers */
BOOL LoadTestDll(void);
void UnloadTestDll(void);

/* Print test summary */
void PrintTestSummary(void);

#endif /* TEST_COMMON_H */
