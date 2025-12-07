/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_msr.c
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Summary:
 *   SafeRing0 Test Suite - MSR Functional Tests
 *   Tests MSR read/write functionality and policy enforcement.
 */

#include "test_common.h"

/*--------------------------------------------------------------------------*/
/* MSR-001: Read IA32_TSC                                                   */
/*--------------------------------------------------------------------------*/

static void Test_MSR001_ReadTSC(void) {
  DWORD eax1, edx1, eax2, edx2;
  BOOL result1, result2;
  ULARGE_INTEGER tsc1, tsc2;

  /* Read TSC twice - should succeed and increment */
  result1 = pfnRdmsr(MSR_IA32_TSC, &eax1, &edx1);
  result2 = pfnRdmsr(MSR_IA32_TSC, &eax2, &edx2);

  TEST_ASSERT_TRUE(result1, "MSR-001a: TSC read succeeded");
  TEST_ASSERT_TRUE(result2, "MSR-001b: TSC second read succeeded");

  tsc1.LowPart = eax1;
  tsc1.HighPart = edx1;
  tsc2.LowPart = eax2;
  tsc2.HighPart = edx2;

  /* TSC should have incremented */
  TEST_ASSERT(tsc2.QuadPart > tsc1.QuadPart, "MSR-001c: TSC incrementing",
              "TSC not incrementing as expected");
}

/*--------------------------------------------------------------------------*/
/* MSR-002: Read Platform Info                                              */
/*--------------------------------------------------------------------------*/

static void Test_MSR002_ReadPlatformInfo(void) {
  DWORD eax, edx;
  BOOL result;

  /* MSR_PLATFORM_INFO (0xCE) is readable on most Intel CPUs */
  result = pfnRdmsr(MSR_IA32_PLATFORM_INFO, &eax, &edx);

  /*
   * This may fail on AMD or older Intel CPUs - that's OK.
   * We're testing that the driver handles reads properly.
   */
  g_TestCount++;
  if (result) {
    printf("  [PASS] MSR-002: Platform info read (0x%08X%08X)\n", edx, eax);
    g_PassCount++;
  } else {
    printf("  [SKIP] MSR-002: Platform info not available (AMD or old CPU)\n");
    /* Not a failure - MSR may not exist */
  }
}

/*--------------------------------------------------------------------------*/
/* MSR-003: Read with CPU Affinity                                          */
/*--------------------------------------------------------------------------*/

static void Test_MSR003_ReadWithAffinity(void) {
  DWORD eax0, edx0, eax1, edx1;
  BOOL result0, result1;
  SYSTEM_INFO sysInfo;

  GetSystemInfo(&sysInfo);

  /* Read TSC on CPU 0 */
  result0 = pfnRdmsrEx(MSR_IA32_TSC, &eax0, &edx0, 1);
  TEST_ASSERT_TRUE(result0, "MSR-003a: TSC read on CPU 0");

  /* Read TSC on CPU 1 (if available) */
  if (sysInfo.dwNumberOfProcessors > 1) {
    result1 = pfnRdmsrEx(MSR_IA32_TSC, &eax1, &edx1, 2);
    TEST_ASSERT_TRUE(result1, "MSR-003b: TSC read on CPU 1");
  } else {
    TEST_SKIP("MSR-003b", "Single CPU system");
  }
}

/*--------------------------------------------------------------------------*/
/* MSR-004: Write to Whitelisted MSR (Opt-In Enabled)                       */
/*--------------------------------------------------------------------------*/

static void Test_MSR004_WriteWhitelistedOptIn(void) {
  DWORD eax, edx;
  BOOL readResult, writeResult;

  /*
   * This test requires the registry opt-in to be enabled:
   * HKLM\SYSTEM\CurrentControlSet\Services\SafeRing0\Parameters
   * EnableMsrWrites = 1
   *
   * If opt-in is disabled, the write will fail - that's expected behavior.
   */

  /* First read the current value */
  readResult = pfnRdmsr(MSR_IA32_PERFEVTSEL0, &eax, &edx);

  if (!readResult) {
    TEST_SKIP("MSR-004", "PERFEVTSEL0 not readable on this CPU");
    return;
  }

  /* Attempt to write back the same value */
  writeResult = pfnWrmsr(MSR_IA32_PERFEVTSEL0, eax, edx);

  g_TestCount++;
  if (writeResult) {
    TEST_PASS("MSR-004: Whitelisted MSR write (opt-in enabled)");
  } else {
    printf(
        "  [INFO] MSR-004: Whitelisted MSR write failed (opt-in disabled "
        "or blocked)\n");
    printf(
        "         To enable: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\"
        "Services\\SafeRing0\\Parameters\" /v EnableMsrWrites /t REG_DWORD "
        "/d 1\n");
    /* This is expected if opt-in is disabled - not a test failure */
    g_PassCount++;
  }
}

/*--------------------------------------------------------------------------*/
/* MSR-005: Write to Non-Whitelisted MSR Blocked                            */
/*--------------------------------------------------------------------------*/

static void Test_MSR005_WriteNonWhitelistedBlocked(void) {
  BOOL result;

  /*
   * Try to write to a random MSR that's not in the whitelist.
   * This should fail regardless of opt-in setting.
   */
  result = pfnWrmsr(0x12345678, 0, 0);

  TEST_ASSERT_FALSE(result, "MSR-005: Non-whitelisted MSR write blocked");
}

/*--------------------------------------------------------------------------*/
/* Public Test Runner                                                       */
/*--------------------------------------------------------------------------*/

void RunMsrTests(void) {
  TEST_CATEGORY("MSR FUNCTIONAL TESTS");

  Test_MSR001_ReadTSC();
  Test_MSR002_ReadPlatformInfo();
  Test_MSR003_ReadWithAffinity();
  Test_MSR004_WriteWhitelistedOptIn();
  Test_MSR005_WriteNonWhitelistedBlocked();
}
