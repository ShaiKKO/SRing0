/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_runner.c
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Summary:
 *   SafeRing0 Test Suite - Main Test Runner
 *   Loads the WinRing0x64.dll, runs all test categories, and reports results.
 */

#include "test_common.h"

/*--------------------------------------------------------------------------*/
/* Global State                                                             */
/*--------------------------------------------------------------------------*/

int g_TestCount = 0;
int g_PassCount = 0;
int g_FailCount = 0;

static HMODULE g_hDll = NULL;

/*--------------------------------------------------------------------------*/
/* Global Function Pointers                                                 */
/*--------------------------------------------------------------------------*/

PFN_InitializeOls pfnInitializeOls = NULL;
PFN_DeinitializeOls pfnDeinitializeOls = NULL;
PFN_GetDllStatus pfnGetDllStatus = NULL;
PFN_GetDriverVersion pfnGetDriverVersion = NULL;
PFN_Rdmsr pfnRdmsr = NULL;
PFN_RdmsrEx pfnRdmsrEx = NULL;
PFN_Wrmsr pfnWrmsr = NULL;
PFN_WrmsrEx pfnWrmsrEx = NULL;
PFN_ReadIoPortByte pfnReadIoPortByte = NULL;
PFN_ReadIoPortWord pfnReadIoPortWord = NULL;
PFN_ReadIoPortDword pfnReadIoPortDword = NULL;
PFN_WriteIoPortByte pfnWriteIoPortByte = NULL;
PFN_WriteIoPortWord pfnWriteIoPortWord = NULL;
PFN_WriteIoPortDword pfnWriteIoPortDword = NULL;
PFN_ReadMemory pfnReadMemory = NULL;
PFN_WriteMemory pfnWriteMemory = NULL;
PFN_ReadPciConfigByte pfnReadPciConfigByte = NULL;
PFN_ReadPciConfigWord pfnReadPciConfigWord = NULL;
PFN_ReadPciConfigDword pfnReadPciConfigDword = NULL;
PFN_WritePciConfigByte pfnWritePciConfigByte = NULL;
PFN_WritePciConfigWord pfnWritePciConfigWord = NULL;
PFN_WritePciConfigDword pfnWritePciConfigDword = NULL;
PFN_Hlt pfnHlt = NULL;

/*--------------------------------------------------------------------------*/
/* DLL Loading                                                              */
/*--------------------------------------------------------------------------*/

BOOL LoadTestDll(void) {
  /* Try loading from current directory first, then system path */
  g_hDll = LoadLibraryW(L"WinRing0x64.dll");
  if (g_hDll == NULL) {
    g_hDll = LoadLibraryW(L".\\WinRing0x64.dll");
  }
  if (g_hDll == NULL) {
    printf("ERROR: Failed to load WinRing0x64.dll (error %lu)\n",
           GetLastError());
    return FALSE;
  }

  /* Resolve required function pointers */
#define RESOLVE(name)                                          \
  pfn##name = (PFN_##name)GetProcAddress(g_hDll, #name);       \
  if (pfn##name == NULL) {                                     \
    printf("ERROR: Failed to resolve " #name " (error %lu)\n", \
           GetLastError());                                    \
    FreeLibrary(g_hDll);                                       \
    g_hDll = NULL;                                             \
    return FALSE;                                              \
  }

  RESOLVE(InitializeOls);
  RESOLVE(DeinitializeOls);
  RESOLVE(GetDllStatus);
  RESOLVE(GetDriverVersion);
  RESOLVE(Rdmsr);
  RESOLVE(RdmsrEx);
  RESOLVE(Wrmsr);
  RESOLVE(WrmsrEx);
  RESOLVE(ReadIoPortByte);
  RESOLVE(ReadIoPortWord);
  RESOLVE(ReadIoPortDword);
  RESOLVE(WriteIoPortByte);
  RESOLVE(WriteIoPortWord);
  RESOLVE(WriteIoPortDword);
  RESOLVE(ReadMemory);
  RESOLVE(WriteMemory);
  RESOLVE(ReadPciConfigByte);
  RESOLVE(ReadPciConfigWord);
  RESOLVE(ReadPciConfigDword);
  RESOLVE(WritePciConfigByte);
  RESOLVE(WritePciConfigWord);
  RESOLVE(WritePciConfigDword);
  RESOLVE(Hlt);

#undef RESOLVE

  printf("DLL loaded successfully.\n");
  return TRUE;
}

void UnloadTestDll(void) {
  if (g_hDll != NULL) {
    FreeLibrary(g_hDll);
    g_hDll = NULL;
  }
}

/*--------------------------------------------------------------------------*/
/* Test Summary                                                             */
/*--------------------------------------------------------------------------*/

void PrintTestSummary(void) {
  printf("\n");
  printf("============================================\n");
  printf("            TEST RESULTS SUMMARY\n");
  printf("============================================\n");
  printf("  Total tests:  %d\n", g_TestCount);
  printf("  Passed:       %d\n", g_PassCount);
  printf("  Failed:       %d\n", g_FailCount);
  printf("============================================\n");

  if (g_FailCount == 0) {
    printf("  STATUS: ALL TESTS PASSED\n");
  } else {
    printf("  STATUS: %d TEST(S) FAILED\n", g_FailCount);
  }
  printf("============================================\n");
}

/*--------------------------------------------------------------------------*/
/* Main Entry Point                                                         */
/*--------------------------------------------------------------------------*/

int main(int argc, char* argv[]) {
  BOOL skipSecurityTests = FALSE;
  BOOL skipRateLimitTests = FALSE;
  int i;

  (void)argc;

  printf("\n");
  printf("============================================\n");
  printf("       SafeRing0 Test Suite v1.0\n");
  printf("       (c) 2025 ziX Performance Labs\n");
  printf("============================================\n");
  printf("\n");

  /* Parse command line arguments */
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--skip-security") == 0) {
      skipSecurityTests = TRUE;
      printf("Note: Skipping security tests\n");
    }
    if (strcmp(argv[i], "--skip-ratelimit") == 0) {
      skipRateLimitTests = TRUE;
      printf("Note: Skipping rate limit tests\n");
    }
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      printf("Usage: SafeRing0Tests.exe [options]\n");
      printf("Options:\n");
      printf("  --skip-security    Skip security tests\n");
      printf("  --skip-ratelimit   Skip rate limit tests\n");
      printf("  --help, -h         Show this help\n");
      return 0;
    }
  }

  /* Load DLL */
  printf("Loading WinRing0x64.dll...\n");
  if (!LoadTestDll()) {
    return 1;
  }

  /* Initialize driver connection */
  printf("Initializing driver connection...\n");
  if (!pfnInitializeOls()) {
    DWORD status = pfnGetDllStatus();
    printf("ERROR: Failed to initialize driver (status %lu)\n", status);
    printf("  Possible causes:\n");
    printf("  - Driver not loaded (run: sc start SafeRing0)\n");
    printf("  - Not running as Administrator\n");
    printf("  - Driver file not found\n");
    UnloadTestDll();
    return 1;
  }

  printf("Driver initialized successfully.\n");
  printf("Driver version: 0x%08X\n", pfnGetDriverVersion());
  printf("\n");

  /* Run test categories */

  /* Security tests are most critical - run first */
  if (!skipSecurityTests) {
    RunSecurityTests();
  }

  /* Functional tests */
  RunMsrTests();
  RunMemoryTests();
  RunIoPortTests();
  RunPciTests();

  /* Rate limit tests (may take time) */
  if (!skipRateLimitTests) {
    RunRateLimitTests();
  }

  /* Print summary */
  PrintTestSummary();

  /* Cleanup */
  pfnDeinitializeOls();
  UnloadTestDll();

  return (g_FailCount > 0) ? 1 : 0;
}
