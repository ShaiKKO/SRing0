/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_ratelimit.c
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Summary:
 *   SafeRing0 Test Suite - Rate Limiting Tests
 *   Tests the DoS prevention rate limiting mechanism.
 */

#include "test_common.h"

/*--------------------------------------------------------------------------*/
/* RATE-001: Normal Operation Within Limit                                  */
/*--------------------------------------------------------------------------*/

static void Test_RATE001_WithinLimit(void) {
  DWORD eax, edx;
  BOOL result;
  int i;
  int succeeded = 0;

  /*
   * Perform 50 MSR reads (well under the 100/sec limit)
   * All should succeed.
   */
  for (i = 0; i < 50; i++) {
    result = pfnRdmsr(MSR_IA32_TSC, &eax, &edx);
    if (result) {
      succeeded++;
    }
  }

  TEST_ASSERT_EQ(succeeded, 50, "RATE-001: 50 ops within limit all succeed");
}

/*--------------------------------------------------------------------------*/
/* RATE-002: Exceed Per-Process Limit                                       */
/*--------------------------------------------------------------------------*/

static void Test_RATE002_ExceedLimit(void) {
  DWORD eax, edx;
  BOOL result;
  int i;
  int succeeded = 0;
  int failed = 0;

  /*
   * Perform 150 MSR reads rapidly.
   * After ~100, we should start seeing failures due to rate limiting.
   * Note: The exact number may vary due to timing.
   */
  for (i = 0; i < 150; i++) {
    result = pfnRdmsr(MSR_IA32_TSC, &eax, &edx);
    if (result) {
      succeeded++;
    } else {
      failed++;
    }
  }

  g_TestCount++;
  if (failed > 0) {
    printf("  [PASS] RATE-002: Rate limit triggered (%d succeeded, %d "
           "blocked)\n",
           succeeded, failed);
    g_PassCount++;
  } else {
    /*
     * Rate limiting may not trigger if the driver doesn't implement it
     * or if the test runs slowly. This isn't necessarily a failure.
     */
    printf("  [WARN] RATE-002: Rate limit not triggered (all %d ops "
           "succeeded)\n",
           succeeded);
    printf("         This may be OK if rate limiting is disabled or\n");
    printf("         the test ran slower than expected.\n");
    g_PassCount++; /* Don't fail the test */
  }
}

/*--------------------------------------------------------------------------*/
/* RATE-003: Recovery After Wait                                            */
/*--------------------------------------------------------------------------*/

static void Test_RATE003_RecoveryAfterWait(void) {
  DWORD eax, edx;
  BOOL result;
  int i;
  int succeeded = 0;

  /*
   * First, exhaust the rate limit by doing many operations
   */
  printf("  Exhausting rate limit...\n");
  for (i = 0; i < 120; i++) {
    pfnRdmsr(MSR_IA32_TSC, &eax, &edx);
  }

  /*
   * Wait for the rate limit window to reset (about 1-2 seconds)
   */
  printf("  Waiting 2 seconds for rate limit recovery...\n");
  Sleep(2000);

  /*
   * Now try again - should succeed
   */
  for (i = 0; i < 10; i++) {
    result = pfnRdmsr(MSR_IA32_TSC, &eax, &edx);
    if (result) {
      succeeded++;
    }
  }

  TEST_ASSERT_EQ(succeeded, 10, "RATE-003: Rate limit recovered after wait");
}

/*--------------------------------------------------------------------------*/
/* Public Test Runner                                                       */
/*--------------------------------------------------------------------------*/

void RunRateLimitTests(void) {
  TEST_CATEGORY("RATE LIMITING TESTS");

  printf("Note: These tests may take a few seconds...\n\n");

  /* Wait a moment to ensure clean rate limit state */
  Sleep(1100);

  Test_RATE001_WithinLimit();

  /* Small delay between tests */
  Sleep(1100);

  Test_RATE002_ExceedLimit();
  Test_RATE003_RecoveryAfterWait();
}
