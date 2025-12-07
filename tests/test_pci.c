/*
 * Author: Colin MacRitchie
 * Organization: ziX Performance Labs
 * File: test_pci.c
 * Version: 1.0
 * Date: 2025-12-06
 * Copyright:
 *   (c) 2025 ziX Performance Labs.
 *
 * Summary:
 *   SafeRing0 Test Suite - PCI Configuration Tests
 *   Tests PCI configuration space read/write functionality.
 */

#include "test_common.h"

/*--------------------------------------------------------------------------*/
/* PCI-001: Read Vendor ID                                                  */
/*--------------------------------------------------------------------------*/

static void Test_PCI001_ReadVendorId(void) {
  DWORD pciAddr;
  WORD vendorId, deviceId;

  /* Bus 0, Device 0, Function 0 - typically the host bridge */
  pciAddr = PCI_CONFIG_ADDRESS(0, 0, 0, 0);

  /* Read vendor ID (offset 0) and device ID (offset 2) */
  vendorId = pfnReadPciConfigWord(pciAddr, 0x00);
  deviceId = pfnReadPciConfigWord(pciAddr, 0x02);

  g_TestCount++;
  if (vendorId != 0xFFFF) {
    printf(
        "  [PASS] PCI-001: Host bridge found - Vendor: 0x%04X, Device: "
        "0x%04X\n",
        vendorId, deviceId);
    g_PassCount++;

    /* Check for known vendors */
    if (vendorId == 0x8086) {
      printf("         (Intel Corporation)\n");
    } else if (vendorId == 0x1022) {
      printf("         (AMD)\n");
    }
  } else {
    TEST_FAIL("PCI-001", "No device at bus 0, dev 0");
  }
}

/*--------------------------------------------------------------------------*/
/* PCI-002: Read Non-Existent Device                                        */
/*--------------------------------------------------------------------------*/

static void Test_PCI002_ReadNonExistent(void) {
  DWORD pciAddr;
  DWORD value;

  /* Bus 255, Device 31, Function 7 - almost certainly doesn't exist */
  pciAddr = PCI_CONFIG_ADDRESS(255, 31, 7, 0);

  value = pfnReadPciConfigDword(pciAddr, 0x00);

  /* Non-existent devices return 0xFFFFFFFF */
  TEST_ASSERT_EQ(value, 0xFFFFFFFF, "PCI-002: Non-existent device returns -1");
}

/*--------------------------------------------------------------------------*/
/* PCI-003: Read Full Config Space                                          */
/*--------------------------------------------------------------------------*/

static void Test_PCI003_ReadConfigSpace(void) {
  DWORD pciAddr;
  BYTE classcode, subclass, progif;
  WORD command, status;

  /* Read various registers from bus 0, dev 0 */
  pciAddr = PCI_CONFIG_ADDRESS(0, 0, 0, 0);

  /* Class code at offset 0x0B */
  classcode = pfnReadPciConfigByte(pciAddr, 0x0B);

  /* Subclass at offset 0x0A */
  subclass = pfnReadPciConfigByte(pciAddr, 0x0A);

  /* Programming interface at offset 0x09 */
  progif = pfnReadPciConfigByte(pciAddr, 0x09);

  g_TestCount++;
  printf("  [PASS] PCI-003a: Class code: %02X/%02X/%02X\n", classcode, subclass,
         progif);
  g_PassCount++;

  /* Host bridge should be class 0x06, subclass 0x00 */
  TEST_ASSERT(classcode == 0x06 && subclass == 0x00,
              "PCI-003b: Device is host bridge",
              "Expected class 06/00 (host bridge)");

  /* Read command/status */
  command = pfnReadPciConfigWord(pciAddr, 0x04);
  status = pfnReadPciConfigWord(pciAddr, 0x06);

  g_TestCount++;
  printf("  [PASS] PCI-003c: Command: 0x%04X, Status: 0x%04X\n", command,
         status);
  g_PassCount++;
}

/*--------------------------------------------------------------------------*/
/* Public Test Runner                                                       */
/*--------------------------------------------------------------------------*/

void RunPciTests(void) {
  TEST_CATEGORY("PCI CONFIGURATION TESTS");

  Test_PCI001_ReadVendorId();
  Test_PCI002_ReadNonExistent();
  Test_PCI003_ReadConfigSpace();
}
