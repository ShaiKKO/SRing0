/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_ioport.c
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs.
 *
 * Summary:
 *   SafeRing0 Test Suite - I/O Port Tests
 *   Tests I/O port read/write functionality.
 */

#include "test_common.h"

/*--------------------------------------------------------------------------*/
/* IO-001: Read PCI Config Ports                                            */
/*--------------------------------------------------------------------------*/

static void Test_IO001_ReadPciPorts(void) {
  DWORD config;

  /*
   * Port 0xCF8 is the PCI Configuration Address port
   * Reading it should return the last value written (or default 0)
   */
  config = pfnReadIoPortDword(0xCF8);

  g_TestCount++;
  /* We can't predict the exact value, but reading shouldn't crash */
  printf("  [PASS] IO-001: PCI config port 0xCF8 readable (value: 0x%08X)\n",
         config);
  g_PassCount++;
}

/*--------------------------------------------------------------------------*/
/* IO-002: Read/Write Different Sizes                                       */
/*--------------------------------------------------------------------------*/

static void Test_IO002_ReadWriteSizes(void) {
  BYTE byteVal;
  WORD wordVal;
  DWORD dwordVal;

  /*
   * Test reading from safe ports.
   * Port 0x61 is the system speaker/misc port - generally safe to read.
   */

  /* Byte read */
  byteVal = pfnReadIoPortByte(0x61);
  g_TestCount++;
  printf("  [PASS] IO-002a: Byte read from 0x61 = 0x%02X\n", byteVal);
  g_PassCount++;

  /* Word read from PCI port */
  wordVal = pfnReadIoPortWord(0xCF8);
  g_TestCount++;
  printf("  [PASS] IO-002b: Word read from 0xCF8 = 0x%04X\n", wordVal);
  g_PassCount++;

  /* Dword read from PCI port */
  dwordVal = pfnReadIoPortDword(0xCF8);
  g_TestCount++;
  printf("  [PASS] IO-002c: Dword read from 0xCF8 = 0x%08X\n", dwordVal);
  g_PassCount++;

  /*
   * Writing to ports is more dangerous and could affect hardware.
   * We'll do a minimal write test to the PCI config address port,
   * which is relatively safe as it just sets an address.
   */

  /* Write to PCI config address - set address for bus 0, dev 0, func 0 */
  pfnWriteIoPortDword(0xCF8, 0x80000000);

  /* Read it back to verify */
  dwordVal = pfnReadIoPortDword(0xCF8);
  TEST_ASSERT_EQ(dwordVal, 0x80000000, "IO-002d: Write/read back from 0xCF8");
}

/*--------------------------------------------------------------------------*/
/* Public Test Runner                                                       */
/*--------------------------------------------------------------------------*/

void RunIoPortTests(void) {
  TEST_CATEGORY("I/O PORT TESTS");

  Test_IO001_ReadPciPorts();
  Test_IO002_ReadWriteSizes();
}
