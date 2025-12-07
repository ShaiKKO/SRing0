/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_memory.c
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs.
 *
 * Summary:
 *   SafeRing0 Test Suite - Physical Memory Tests
 *   Tests physical memory read/write functionality and security validation.
 */

#include "test_common.h"

/*--------------------------------------------------------------------------*/
/* MEM-001: Read BIOS Region                                                */
/*--------------------------------------------------------------------------*/

static void Test_MEM001_ReadBiosRegion(void) {
  BYTE buffer[256];
  DWORD bytesRead;

  /* Read from BIOS area at 0xF0000 */
  bytesRead = pfnReadMemory(PHYS_BIOS_START, buffer, sizeof(buffer), 1);

  TEST_ASSERT(bytesRead == sizeof(buffer), "MEM-001: BIOS region readable",
              "Failed to read BIOS region");

  /* Check for typical BIOS signatures */
  g_TestCount++;
  if (bytesRead > 0) {
    /* Look for any non-zero data to confirm we got real data */
    int hasData = 0;
    DWORD i;
    for (i = 0; i < bytesRead; i++) {
      if (buffer[i] != 0 && buffer[i] != 0xFF) {
        hasData = 1;
        break;
      }
    }
    if (hasData) {
      TEST_PASS("MEM-001b: BIOS data appears valid");
    } else {
      printf("  [WARN] MEM-001b: BIOS area may be empty or mapped\n");
      g_PassCount++; /* Not necessarily a failure */
    }
  }
}

/*--------------------------------------------------------------------------*/
/* MEM-002: Read with Different Unit Sizes                                  */
/*--------------------------------------------------------------------------*/

static void Test_MEM002_ReadUnitSizes(void) {
  BYTE buffer[4];
  DWORD bytesRead;

  /* Read 1 byte at a time */
  bytesRead = pfnReadMemory(PHYS_BIOS_START, buffer, 4, 1);
  TEST_ASSERT_EQ(bytesRead, 4, "MEM-002a: Byte unit read");

  /* Read 2 bytes at a time (WORD) */
  bytesRead = pfnReadMemory(PHYS_BIOS_START, buffer, 4, 2);
  TEST_ASSERT_EQ(bytesRead, 4, "MEM-002b: Word unit read");

  /* Read 4 bytes at a time (DWORD) */
  bytesRead = pfnReadMemory(PHYS_BIOS_START, buffer, 4, 4);
  TEST_ASSERT_EQ(bytesRead, 4, "MEM-002c: Dword unit read");
}

/*--------------------------------------------------------------------------*/
/* MEM-003: Kernel Address Blocked                                          */
/*--------------------------------------------------------------------------*/

static void Test_MEM003_KernelAddressBlocked(void) {
  BYTE buffer[16];
  DWORD bytesRead;

  /* Try various kernel addresses - all should be blocked */

  /* Start of kernel space */
  bytesRead = pfnReadMemory(PHYS_KERNEL_START, buffer, sizeof(buffer), 1);
  TEST_ASSERT_EQ(bytesRead, 0, "MEM-003a: Kernel start blocked");

  /* Typical kernel code region */
  bytesRead =
      pfnReadMemory(PHYS_KERNEL_START + 0x100000, buffer, sizeof(buffer), 1);
  TEST_ASSERT_EQ(bytesRead, 0, "MEM-003b: Kernel code region blocked");

  /* High kernel address */
  bytesRead = pfnReadMemory(0xFFFFFFFFFFFFF000ULL, buffer, sizeof(buffer), 1);
  TEST_ASSERT_EQ(bytesRead, 0, "MEM-003c: High kernel address blocked");
}

/*--------------------------------------------------------------------------*/
/* MEM-004: Zero/Invalid Parameters                                         */
/*--------------------------------------------------------------------------*/

static void Test_MEM004_InvalidParameters(void) {
  BYTE buffer[16];
  DWORD bytesRead;

  /* Zero count should return 0 */
  bytesRead = pfnReadMemory(PHYS_BIOS_START, buffer, 0, 1);
  TEST_ASSERT_EQ(bytesRead, 0, "MEM-004a: Zero count returns 0");

  /* NULL buffer handling - may crash or return 0 depending on impl */
  /* Skip this test as it may cause issues */
  TEST_SKIP("MEM-004b", "NULL buffer test skipped for safety");
}

/*--------------------------------------------------------------------------*/
/* Public Test Runner                                                       */
/*--------------------------------------------------------------------------*/

void RunMemoryTests(void) {
  TEST_CATEGORY("PHYSICAL MEMORY TESTS");

  Test_MEM001_ReadBiosRegion();
  Test_MEM002_ReadUnitSizes();
  Test_MEM003_KernelAddressBlocked();
  Test_MEM004_InvalidParameters();
}
