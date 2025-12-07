/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_security.c
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Summary:
 *   SafeRing0 Test Suite - Security Tests
 *   Validates all security controls that protect against CVE-2020-14979
 *   and related attack vectors.
 *
 * Security Tests:
 *   SEC-001: Write to IA32_LSTAR blocked (syscall hook prevention)
 *   SEC-002: Write to IA32_EFER blocked (NX bypass prevention)
 *   SEC-003: Write to SYSENTER_EIP blocked (legacy syscall protection)
 *   SEC-004: Write to VMX MSR blocked (virtualization protection)
 *   SEC-005: Write to AMD_SYSCFG blocked (SME/SEV protection)
 *   SEC-006: Kernel memory access blocked
 *   SEC-007: Invalid MSR handled without crash
 *   SEC-008: HALT IOCTL blocked
 *   SEC-009: All never-writable MSRs blocked
 */

#include "test_common.h"

/*--------------------------------------------------------------------------*/
/* SEC-001: IA32_LSTAR Write Blocked                                        */
/*--------------------------------------------------------------------------*/

static void Test_SEC001_LSTAR_WriteBlocked(void) {
  BOOL result;

  /* Attempt to write to IA32_LSTAR - this should ALWAYS fail */
  result = pfnWrmsr(MSR_IA32_LSTAR, 0x41414141, 0x41414141);

  TEST_ASSERT_FALSE(result, "SEC-001: IA32_LSTAR write blocked");
}

/*--------------------------------------------------------------------------*/
/* SEC-002: IA32_EFER Write Blocked                                         */
/*--------------------------------------------------------------------------*/

static void Test_SEC002_EFER_WriteBlocked(void) {
  BOOL result;

  /* Attempt to write to IA32_EFER - this should ALWAYS fail */
  result = pfnWrmsr(MSR_IA32_EFER, 0, 0);

  TEST_ASSERT_FALSE(result, "SEC-002: IA32_EFER write blocked");
}

/*--------------------------------------------------------------------------*/
/* SEC-003: SYSENTER_EIP Write Blocked                                      */
/*--------------------------------------------------------------------------*/

static void Test_SEC003_SYSENTER_WriteBlocked(void) {
  BOOL result;

  /* Test all three SYSENTER MSRs */
  result = pfnWrmsr(MSR_IA32_SYSENTER_CS, 0, 0);
  TEST_ASSERT_FALSE(result, "SEC-003a: SYSENTER_CS write blocked");

  result = pfnWrmsr(MSR_IA32_SYSENTER_ESP, 0, 0);
  TEST_ASSERT_FALSE(result, "SEC-003b: SYSENTER_ESP write blocked");

  result = pfnWrmsr(MSR_IA32_SYSENTER_EIP, 0, 0);
  TEST_ASSERT_FALSE(result, "SEC-003c: SYSENTER_EIP write blocked");
}

/*--------------------------------------------------------------------------*/
/* SEC-004: VMX MSR Write Blocked                                           */
/*--------------------------------------------------------------------------*/

static void Test_SEC004_VMX_WriteBlocked(void) {
  BOOL result;

  /* Test VMX_BASIC and several MSRs in the VMX range */
  result = pfnWrmsr(MSR_IA32_VMX_BASIC, 0, 0);
  TEST_ASSERT_FALSE(result, "SEC-004a: VMX_BASIC write blocked");

  result = pfnWrmsr(0x481, 0, 0); /* VMX_PINBASED_CTLS */
  TEST_ASSERT_FALSE(result, "SEC-004b: VMX range 0x481 write blocked");

  result = pfnWrmsr(0x48F, 0, 0); /* End of VMX range */
  TEST_ASSERT_FALSE(result, "SEC-004c: VMX range 0x48F write blocked");
}

/*--------------------------------------------------------------------------*/
/* SEC-005: AMD_SYSCFG Write Blocked                                        */
/*--------------------------------------------------------------------------*/

static void Test_SEC005_AMD_SYSCFG_WriteBlocked(void) {
  BOOL result;

  /* Attempt to write to AMD_SYSCFG - this should ALWAYS fail */
  result = pfnWrmsr(MSR_AMD_SYSCFG, 0, 0);

  TEST_ASSERT_FALSE(result, "SEC-005: AMD_SYSCFG write blocked");
}

/*--------------------------------------------------------------------------*/
/* SEC-006: Kernel Memory Access Blocked                                    */
/*--------------------------------------------------------------------------*/

static void Test_SEC006_KernelMemoryBlocked(void) {
  BYTE buffer[16];
  DWORD bytesRead;

  /* Attempt to read from kernel address space */
  bytesRead = pfnReadMemory(PHYS_KERNEL_START, buffer, sizeof(buffer), 1);

  TEST_ASSERT_EQ(bytesRead, 0, "SEC-006: Kernel memory read blocked");
}

/*--------------------------------------------------------------------------*/
/* SEC-007: Invalid MSR Handled Gracefully                                  */
/*--------------------------------------------------------------------------*/

static void Test_SEC007_InvalidMSR_NoCrash(void) {
  DWORD eax, edx;
  BOOL result;

  /*
   * Reading an invalid MSR should return FALSE, not crash.
   * If this test runs without BSOD, the SEH handling works.
   */
  result = pfnRdmsr(MSR_INVALID, &eax, &edx);

  /*
   * We expect FALSE (failure) but the key is no crash.
   * If we reach this point, SEH is working.
   */
  g_TestCount++;
  if (!result) {
    TEST_PASS("SEC-007: Invalid MSR handled without crash");
  } else {
    /* Unlikely but technically possible on some CPUs */
    printf("  [WARN] SEC-007: MSR 0x%X unexpectedly readable\n", MSR_INVALID);
    g_PassCount++; /* Still pass - no crash is the goal */
  }
}

/*--------------------------------------------------------------------------*/
/* SEC-008: HALT IOCTL Blocked                                              */
/*--------------------------------------------------------------------------*/

static void Test_SEC008_HALT_Blocked(void) {
  BOOL result;

  /* HLT should always return FALSE in SafeRing0 */
  result = pfnHlt();

  TEST_ASSERT_FALSE(result, "SEC-008: HALT IOCTL blocked");
}

/*--------------------------------------------------------------------------*/
/* SEC-009: All Never-Writable MSRs Blocked                                 */
/*--------------------------------------------------------------------------*/

static void Test_SEC009_AllNeverWritable(void) {
  /* Test all MSRs in the never-writable list */
  static const struct {
    DWORD msr;
    const char* name;
  } neverWritable[] = {
      {MSR_IA32_LSTAR, "LSTAR"},
      {MSR_IA32_CSTAR, "CSTAR"},
      {MSR_IA32_STAR, "STAR"},
      {MSR_IA32_SFMASK, "SFMASK"},
      {MSR_IA32_SYSENTER_CS, "SYSENTER_CS"},
      {MSR_IA32_SYSENTER_ESP, "SYSENTER_ESP"},
      {MSR_IA32_SYSENTER_EIP, "SYSENTER_EIP"},
      {MSR_IA32_EFER, "EFER"},
      {0x1D9, "DEBUGCTL"},
      {0x277, "PAT"},
      {0x1A0, "MISC_ENABLE"},
      {MSR_AMD_SYSCFG, "AMD_SYSCFG"},
      {0xC0010117, "AMD_VM_HSAVE_PA"},
  };

  int i;
  int blocked = 0;
  int total = sizeof(neverWritable) / sizeof(neverWritable[0]);

  for (i = 0; i < total; i++) {
    BOOL result = pfnWrmsr(neverWritable[i].msr, 0, 0);
    if (!result) {
      blocked++;
    } else {
      printf("  [WARN] MSR 0x%X (%s) was NOT blocked!\n", neverWritable[i].msr,
             neverWritable[i].name);
    }
  }

  g_TestCount++;
  if (blocked == total) {
    char msg[64];
    sprintf_s(msg, sizeof(msg), "SEC-009: All %d never-writable MSRs blocked",
              total);
    TEST_PASS(msg);
  } else {
    char msg[64];
    sprintf_s(msg, sizeof(msg), "Only %d/%d MSRs blocked", blocked, total);
    TEST_FAIL("SEC-009: All never-writable MSRs blocked", msg);
  }
}

/*--------------------------------------------------------------------------*/
/* Public Test Runner                                                       */
/*--------------------------------------------------------------------------*/

void RunSecurityTests(void) {
  TEST_CATEGORY("SECURITY TESTS");

  printf("Testing CVE-2020-14979 mitigations...\n\n");

  /* Critical MSR protection tests */
  Test_SEC001_LSTAR_WriteBlocked();
  Test_SEC002_EFER_WriteBlocked();
  Test_SEC003_SYSENTER_WriteBlocked();
  Test_SEC004_VMX_WriteBlocked();
  Test_SEC005_AMD_SYSCFG_WriteBlocked();

  /* Memory protection */
  Test_SEC006_KernelMemoryBlocked();

  /* Exception handling */
  Test_SEC007_InvalidMSR_NoCrash();

  /* HALT blocking */
  Test_SEC008_HALT_Blocked();

  /* Comprehensive never-writable check */
  Test_SEC009_AllNeverWritable();
}
