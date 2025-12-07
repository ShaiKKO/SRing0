# SafeRing0

A secure, drop-in replacement for the vulnerable WinRing0 driver (CVE-2020-14979).

EV Certificate Shortly.

## Overview

SafeRing0 provides WinRing0-compatible hardware access (MSR, physical memory, I/O ports, PCI config) with proper security controls that the original WinRing0 driver lacked.

### What This Fixes

The original WinRing0.sys driver (used by HWiNFO, MSI Afterburner, OpenHardwareMonitor, and many others) has a critical vulnerability: **any process can access it**, enabling local privilege escalation to SYSTEM.

SafeRing0 fixes this by:

1. **Device ACL** - Only SYSTEM and Administrators can access the driver
2. **MSR Blacklist** - Blocks writes to dangerous MSRs (IA32_LSTAR, etc.) that enable kernel code execution
3. **Memory Validation** - Blocks access to kernel address ranges
4. **Rate Limiting** - Prevents abuse/DoS (100 ops/sec per process)
5. **ETW Telemetry** - Logs all operations for security monitoring

## Compatibility

SafeRing0 is a **drop-in replacement** for WinRing0:

- Uses the same device name (`\\Device\\WinRing0_1_2_0`)
- Implements the same IOCTL codes (0x821 = READ_MSR, etc.)
- Provides a compatible `WinRing0x64.dll` replacement

Applications using WinRing0 should work without modification.

## Requirements

- Windows 10/11 x64
- Administrator privileges (by design - this is the security fix)
- Visual Studio 2022 with WDK for building

## Building

### Prerequisites

1. Install [Visual Studio 2022](https://visualstudio.microsoft.com/) with "Desktop development with C++"
2. Install [Windows Driver Kit (WDK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### Build Steps

```powershell
# Open Developer Command Prompt for VS 2022
cd d:\SafeRing0\build

# Build driver
msbuild SafeRing0.sln /p:Configuration=Release /p:Platform=x64
```

### Output

- `x64\Release\safering0.sys` - Kernel driver
- `x64\Release\WinRing0x64.dll` - Drop-in DLL replacement

## Installation

### Test Signing (Development)

```powershell
# Enable test signing (requires restart)
bcdedit /set testsigning on

# Install driver
sc create SafeRing0 type=kernel binPath="C:\path\to\safering0.sys"
sc start SafeRing0
```

### Production

For production use, the driver must be attestation-signed or WHQL-certified through Microsoft's Partner Center.

## Usage

### Migration from WinRing0

1. Stop applications using WinRing0
2. Unload WinRing0 driver: `sc stop WinRing0_1_2_0 && sc delete WinRing0_1_2_0`
3. Install SafeRing0 driver
4. Replace `WinRing0x64.dll` with SafeRing0's version
5. Restart applications

### API Compatibility

All WinRing0 exports are supported:

```c
// Initialization
InitializeOls() / DeinitializeOls()

// MSR Access
Rdmsr(index, &eax, &edx)
Wrmsr(index, eax, edx)

// I/O Ports
ReadIoPortByte/Word/Dword(port)
WriteIoPortByte/Word/Dword(port, value)

// Physical Memory
ReadPhysicalMemory(address, buffer, count)
WritePhysicalMemory(address, buffer, count)

// PCI Configuration
ReadPciConfigByte/Word/Dword(pciAddr, regAddr, &value)
WritePciConfigByte/Word/Dword(pciAddr, regAddr, value)
```

## Security Architecture

| Layer | Protection | CVE Addressed |
|-------|------------|---------------|
| Device ACL | `SDDL_DEVOBJ_SYS_ALL_ADM_ALL` | CVE-2020-14979 |
| MSR Filtering | Block IA32_LSTAR, IA32_SYSENTER_EIP, etc. | Kernel code execution |
| Memory Validation | Block kernel address mapping | Token theft |
| Rate Limiting | 100 ops/sec per process | DoS prevention |
| ETW Telemetry | Log all operations | Forensics |

### Blocked MSRs (Write)

The following MSRs are blocked from writes to prevent kernel code execution:

- `0xC0000082` - IA32_LSTAR (syscall entry point)
- `0xC0000083` - IA32_CSTAR (compat mode syscall)
- `0x00000176` - IA32_SYSENTER_EIP
- `0xC0000080` - IA32_EFER
- `0xC0000081` - IA32_STAR
- And others...

Reads are allowed for all MSRs.

## ETW Telemetry

SafeRing0 logs all operations via ETW TraceLogging:

```
Provider: SafeRing0
GUID: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}

Events:
- MSR_READ: ProcessId, MsrIndex
- MSR_WRITE: ProcessId, MsrIndex, Value
- MSR_BLOCKED: ProcessId, MsrIndex (blocked dangerous write)
- MEMORY_MAP: ProcessId, PhysicalAddress, Size
- IO_PORT: ProcessId, Port, Direction, Value
- PCI_CONFIG: ProcessId, PciAddress, RegAddress, Direction
```

## Contributing

Contributions are welcome! Please ensure:

1. Code follows the project style (see CLAUDE.md)
2. Security-critical code includes proper validation
3. All functions are ≤60 lines (extract helpers if needed)

## License

MIT License - see [LICENSE](LICENSE)

## References

- [CVE-2020-14979](https://nvd.nist.gov/vuln/detail/cve-2020-14979) - WinRing0 vulnerability
- [Microsoft Driver Security](https://docs.microsoft.com/en-us/windows-hardware/drivers/driversecurity/)
- [WdmlibIoCreateDeviceSecure](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdmsec/nf-wdmsec-wdmlibiocreatedevicesecure)

## Acknowledgments

- Original WinRing0 by hiyohiyo (2007-2009)
- Security research by Matt Hand (CVE-2020-14979 discovery)
- ziX Performance Labs (SafeRing0 implementation)
