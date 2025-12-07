# SafeRing0 API Reference

## Overview

SafeRing0 provides two interfaces:

1. **IOCTL Interface** - Direct driver communication via `DeviceIoControl()`
2. **WinRing0-Compatible DLL** - Drop-in replacement API (`WinRing0x64.dll`)

## Quick Start

### Using the DLL (Recommended)

```c
#include <windows.h>

// Declare WinRing0 functions
extern BOOL InitializeOls(void);
extern void DeinitializeOls(void);
extern BOOL Rdmsr(DWORD index, PDWORD eax, PDWORD edx);
extern BOOL Wrmsr(DWORD index, DWORD eax, DWORD edx);

int main() {
    DWORD eax, edx;

    if (!InitializeOls()) {
        printf("Failed to initialize: %u\n", GetDllStatus());
        return 1;
    }

    // Read MSR_IA32_MPERF
    if (Rdmsr(0xE7, &eax, &edx)) {
        printf("MPERF: 0x%08X%08X\n", edx, eax);
    }

    DeinitializeOls();
    return 0;
}
```

Link with: `WinRing0x64.lib` or load dynamically via `LoadLibrary()`

---

## DLL API Reference

### Initialization Functions

#### InitializeOls

```c
BOOL WINAPI InitializeOls(void);
```

Initialize connection to SafeRing0 driver.

**Returns:** `TRUE` on success, `FALSE` on failure (check `GetDllStatus()`)

**Notes:**

- Must be called before any other functions
- Reference counted - multiple calls are safe
- Requires Administrator privileges

---

#### DeinitializeOls

```c
void WINAPI DeinitializeOls(void);
```

Close connection to driver.

**Notes:**

- Call once for each successful `InitializeOls()` call
- Last call closes the driver handle

---

### Status Functions

#### GetDllStatus

```c
DWORD WINAPI GetDllStatus(void);
```

Get current DLL/driver status.

**Returns:** Status code:

| Code | Constant                            | Meaning                      |
| ---- | ----------------------------------- | ---------------------------- |
| 0    | OLS_DLL_NO_ERROR                    | Success                      |
| 1    | OLS_DLL_UNKNOWN_ERROR               | Unknown error                |
| 2    | OLS_DLL_DRIVER_NOT_LOADED           | Driver not loaded            |
| 3    | OLS_DLL_DRIVER_NOT_FOUND            | Driver file not found        |
| 7    | OLS_DLL_DRIVER_NOT_LOADED_VISTA_UAC | Access denied (run as admin) |

---

#### GetDriverVersion

```c
DWORD WINAPI GetDriverVersion(void);
```

Get driver version.

**Returns:** Version in format `0xMMmmRRBB` (Major.Minor.Revision.Build)

SafeRing0 returns `0x01020005` (1.2.0.5) for WinRing0 compatibility.

---

#### GetDllVersion

```c
DWORD WINAPI GetDllVersion(void);
```

Get DLL version.

**Returns:** Version in format `0xMMmmRRBB`

---

### MSR Functions

#### Rdmsr / RdmsrEx

```c
BOOL WINAPI Rdmsr(DWORD index, PDWORD eax, PDWORD edx);
BOOL WINAPI RdmsrEx(DWORD index, PDWORD eax, PDWORD edx, DWORD_PTR affinity);
```

Read Model-Specific Register.

**Parameters:**

- `index` - MSR index (0x00000000 - 0xFFFFFFFF)
- `eax` - Receives low 32 bits
- `edx` - Receives high 32 bits
- `affinity` - CPU affinity mask (Ex version)

**Returns:** `TRUE` on success, `FALSE` on failure

**Error Codes:**

- `STATUS_QUOTA_EXCEEDED` - Rate limit exceeded
- `STATUS_INVALID_PARAMETER` - Invalid MSR index (CPU #GP)

**Notes:**

- All MSRs are readable (security policy applies to writes only)
- Invalid MSR indices return error (no BSOD)
- Rate limited: 100 ops/sec per process, 1000 ops/sec global

---

#### Wrmsr / WrmsrEx

```c
BOOL WINAPI Wrmsr(DWORD index, DWORD eax, DWORD edx);
BOOL WINAPI WrmsrEx(DWORD index, DWORD eax, DWORD edx, DWORD_PTR affinity);
```

Write Model-Specific Register.

**Parameters:**

- `index` - MSR index
- `eax` - Low 32 bits to write
- `edx` - High 32 bits to write
- `affinity` - CPU affinity mask (Ex version)

**Returns:** `TRUE` on success, `FALSE` on failure

**Error Codes:**

- `STATUS_ACCESS_DENIED` - MSR blocked by policy
- `STATUS_QUOTA_EXCEEDED` - Rate limit exceeded
- `STATUS_INVALID_PARAMETER` - Invalid MSR index

**Security Policy:**

1. Never-writable MSRs always blocked (IA32_LSTAR, IA32_EFER, etc.)
2. Whitelist MSRs require registry opt-in
3. All other MSRs blocked by default

**Writable MSRs (with opt-in):**

| Category            | MSRs                                            |
| ------------------- | ----------------------------------------------- |
| Intel Perf Counters | 0x186-0x189, 0xC1-0xC4, 0x309-0x30B             |
| Intel Power         | 0x199, 0x1B0, 0x610, 0x638, 0x640, 0x1AD, 0x774 |
| AMD Perf Counters   | 0xC0010000-0xC0010007                           |
| AMD P-States        | 0xC0010062, 0xC0010064-0xC001006B               |

---

#### Rdpmc / RdpmcEx

```c
BOOL WINAPI Rdpmc(DWORD index, PDWORD eax, PDWORD edx);
BOOL WINAPI RdpmcEx(DWORD index, PDWORD eax, PDWORD edx, DWORD_PTR affinity);
```

Read Performance Monitor Counter.

Same behavior as `Rdmsr()`.

---

### I/O Port Functions

#### ReadIoPortByte / Word / Dword

```c
BYTE WINAPI ReadIoPortByte(WORD port);
WORD WINAPI ReadIoPortWord(WORD port);
DWORD WINAPI ReadIoPortDword(WORD port);
```

Read from I/O port.

**Parameters:**

- `port` - I/O port address (0x0000 - 0xFFFF)

**Returns:** Value read, or 0xFF/0xFFFF/0xFFFFFFFF on failure

---

#### WriteIoPortByte / Word / Dword

```c
void WINAPI WriteIoPortByte(WORD port, BYTE value);
void WINAPI WriteIoPortWord(WORD port, WORD value);
void WINAPI WriteIoPortDword(WORD port, DWORD value);
```

Write to I/O port.

**Parameters:**

- `port` - I/O port address
- `value` - Value to write

---

### Physical Memory Functions

#### ReadMemory

```c
DWORD WINAPI ReadMemory(DWORD_PTR address, PBYTE buffer,
                        DWORD count, DWORD unitSize);
```

Read from physical memory.

**Parameters:**

- `address` - Physical address
- `buffer` - Output buffer
- `count` - Bytes to read
- `unitSize` - Access unit size (1, 2, or 4)

**Returns:** Bytes read, or 0 on failure

**Security:**

- Kernel address range (>= 0xFFFF800000000000) is BLOCKED
- Returns `STATUS_ACCESS_DENIED` for kernel addresses

---

#### WriteMemory

```c
DWORD WINAPI WriteMemory(DWORD_PTR address, PBYTE buffer,
                         DWORD count, DWORD unitSize);
```

Write to physical memory.

**Parameters:**

- `address` - Physical address
- `buffer` - Input buffer
- `count` - Bytes to write
- `unitSize` - Access unit size (1, 2, or 4)

**Returns:** Bytes written, or 0 on failure

**Security:** Same kernel address blocking as `ReadMemory()`

---

### PCI Configuration Functions

#### SetPciMaxBusIndex

```c
void WINAPI SetPciMaxBusIndex(BYTE max);
```

Set maximum PCI bus index. No-op in SafeRing0 (provided for compatibility).

---

#### ReadPciConfigByte / Word / Dword

```c
BYTE WINAPI ReadPciConfigByte(DWORD pciAddress, BYTE regAddress);
WORD WINAPI ReadPciConfigWord(DWORD pciAddress, BYTE regAddress);
DWORD WINAPI ReadPciConfigDword(DWORD pciAddress, BYTE regAddress);
```

Read from PCI configuration space.

**Parameters:**

- `pciAddress` - PCI address (see encoding below)
- `regAddress` - Register offset (0-255)

**Returns:** Value read, or 0xFF/0xFFFF/0xFFFFFFFF if device not present

**PCI Address Encoding:**

```c
// Use this macro to create pciAddress:
#define PCI_CONFIG_ADDRESS(bus, dev, func, reg) \
    (0x80000000UL | ((bus & 0xFF) << 16) | \
     ((dev & 0x1F) << 11) | ((func & 0x07) << 8) | (reg & 0xFC))

// Example: Read Vendor ID from Bus 0, Device 0, Function 0
WORD vendorId = ReadPciConfigWord(PCI_CONFIG_ADDRESS(0, 0, 0, 0), 0);
```

---

#### ReadPciConfigDwordEx

```c
DWORD WINAPI ReadPciConfigDwordEx(DWORD pciAddress, WORD regAddress);
```

Read from PCIe extended configuration space (offsets 0-4095).

---

#### WritePciConfigByte / Word / Dword / DwordEx

```c
void WINAPI WritePciConfigByte(DWORD pciAddress, BYTE regAddress, BYTE value);
void WINAPI WritePciConfigWord(DWORD pciAddress, BYTE regAddress, WORD value);
void WINAPI WritePciConfigDword(DWORD pciAddress, BYTE regAddress, DWORD value);
void WINAPI WritePciConfigDwordEx(DWORD pciAddress, WORD regAddress, DWORD value);
```

Write to PCI configuration space.

---

### CPUID Functions

#### Cpuid / CpuidEx

```c
BOOL WINAPI Cpuid(DWORD index, PDWORD eax, PDWORD ebx, PDWORD ecx, PDWORD edx);
BOOL WINAPI CpuidEx(DWORD index, DWORD ecxValue,
                    PDWORD eax, PDWORD ebx, PDWORD ecx, PDWORD edx);
```

Execute CPUID instruction.

**Parameters:**

- `index` - CPUID leaf (EAX input)
- `ecxValue` - ECX input (Ex version only)
- `eax/ebx/ecx/edx` - Output registers

**Returns:** `TRUE` always (CPUID never fails)

**Note:** Executed locally in user-mode (no driver call needed)

---

### TSC Functions

#### Rdtsc / RdtscEx

```c
BOOL WINAPI Rdtsc(PDWORD eax, PDWORD edx);
BOOL WINAPI RdtscEx(PDWORD eax, PDWORD edx, DWORD_PTR affinity);
```

Read timestamp counter.

**Returns:** `TRUE` on success

**Note:** Executed locally in user-mode

---

### HLT Functions (BLOCKED)

#### Hlt / HltEx

```c
BOOL WINAPI Hlt(void);
BOOL WINAPI HltEx(DWORD_PTR affinity);
```

Execute HLT instruction.

**Returns:** `FALSE` always (blocked for security)

**Note:** SafeRing0 blocks HLT - no legitimate use case for user applications.

---

## IOCTL Interface Reference

For direct driver communication without the DLL.

### Device Path

```c
// Open device handle
HANDLE hDevice = CreateFileW(
    L"\\\\.\\SafeRing0",          // or L"\\\\.\\WinRing0_1_2_0" for compat
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);
```

### IOCTL Codes

Include `safering0_ioctl.h` for definitions:

| IOCTL                         | Code  | Input                      | Output         |
| ----------------------------- | ----- | -------------------------- | -------------- |
| IOCTL_OLS_GET_DRIVER_VERSION  | 0x800 | None                       | DWORD          |
| IOCTL_OLS_GET_REFCOUNT        | 0x801 | None                       | DWORD          |
| IOCTL_OLS_READ_MSR            | 0x821 | OLS_READ_MSR_INPUT         | ULARGE_INTEGER |
| IOCTL_OLS_WRITE_MSR           | 0x822 | OLS_WRITE_MSR_INPUT        | None           |
| IOCTL_OLS_READ_PMC            | 0x823 | OLS_READ_MSR_INPUT         | ULARGE_INTEGER |
| IOCTL_OLS_HALT                | 0x824 | None                       | **BLOCKED**    |
| IOCTL_OLS_READ_IO_PORT_BYTE   | 0x833 | OLS_READ_IO_PORT_INPUT     | DWORD          |
| IOCTL_OLS_READ_IO_PORT_WORD   | 0x834 | OLS_READ_IO_PORT_INPUT     | DWORD          |
| IOCTL_OLS_READ_IO_PORT_DWORD  | 0x835 | OLS_READ_IO_PORT_INPUT     | DWORD          |
| IOCTL_OLS_WRITE_IO_PORT_BYTE  | 0x836 | OLS_WRITE_IO_PORT_INPUT    | None           |
| IOCTL_OLS_WRITE_IO_PORT_WORD  | 0x837 | OLS_WRITE_IO_PORT_INPUT    | None           |
| IOCTL_OLS_WRITE_IO_PORT_DWORD | 0x838 | OLS_WRITE_IO_PORT_INPUT    | None           |
| IOCTL_OLS_READ_MEMORY         | 0x841 | OLS_READ_MEMORY_INPUT      | Byte array     |
| IOCTL_OLS_WRITE_MEMORY        | 0x842 | OLS_WRITE_MEMORY_INPUT     | None           |
| IOCTL_OLS_READ_PCI_CONFIG     | 0x851 | OLS_READ_PCI_CONFIG_INPUT  | DWORD          |
| IOCTL_OLS_WRITE_PCI_CONFIG    | 0x852 | OLS_WRITE_PCI_CONFIG_INPUT | None           |

### Input/Output Structures

See `include/safering0_ioctl.h` for complete structure definitions.

---

## Migration from WinRing0

### Binary Replacement

1. Replace `WinRing0x64.dll` with SafeRing0's version
2. Replace `WinRing0x64.sys` with `SafeRing0.sys`
3. No source code changes required for most applications

### Behavioral Differences

| Feature          | WinRing0             | SafeRing0               |
| ---------------- | -------------------- | ----------------------- |
| Non-admin access | Allowed (vulnerable) | Blocked                 |
| LSTAR write      | Allowed              | Blocked                 |
| Kernel memory    | Allowed              | Blocked                 |
| HLT instruction  | Allowed              | Blocked (returns FALSE) |
| Rate limiting    | None                 | 100 ops/sec per process |
| Logging          | None                 | ETW telemetry           |

### Enabling MSR Writes

Applications that need MSR write capability (ThrottleStop, Ryzen Master, etc.) must enable the registry opt-in:

```powershell
# Run as Administrator
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SafeRing0\Parameters" /v EnableMsrWrites /t REG_DWORD /d 1 /f
```

This enables writes ONLY to the whitelisted performance/power MSRs. Security-critical MSRs (syscall entry points, EFER, etc.) remain blocked.
