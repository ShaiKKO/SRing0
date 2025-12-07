# SafeRing0 Security Architecture

## Overview

SafeRing0 is a secure replacement for the vulnerable WinRing0 driver. It provides the same hardware access functionality (MSR, physical memory, I/O ports, PCI configuration) while implementing multiple security layers to prevent exploitation.

## CVE-2020-14979 Remediation

### Original Vulnerability

WinRing0 versions prior to 1.2.0.5 created a device object with a NULL DACL (Discretionary Access Control List), allowing any authenticated user to open the device and access privileged hardware operations. This enabled:

- Local privilege escalation to SYSTEM
- Kernel code execution via MSR manipulation
- Arbitrary physical memory read/write
- Full system compromise from low-privileged accounts

**CVE:** [CVE-2020-14979](https://nvd.nist.gov/vuln/detail/CVE-2020-14979)
**Microsoft Defender Classification:** [VulnerableDriver:WinNT/Winring0.G](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=VulnerableDriver:WinNT/Winring0.G)

### SafeRing0 Fix

SafeRing0 addresses CVE-2020-14979 by using `WdmlibIoCreateDeviceSecure()` with an explicit SDDL string:

```c
SDDL_DEVOBJ_SYS_ALL_ADM_ALL
// Translates to: D:P(A;;GA;;;SY)(A;;GA;;;BA)
// SYSTEM: Full access
// Administrators: Full access
// Everyone else: Denied
```

This ensures only SYSTEM and local Administrators can open the device handle.

## Security Layers

### Layer 1: Device ACL (Authentication)

- **Implementation:** SDDL-based device security descriptor
- **Enforcement:** Windows kernel rejects `CreateFile()` from non-admin processes
- **Result:** Non-privileged users cannot open `\\.\SafeRing0`

### Layer 2: MSR Write Policy (Authorization)

A tiered policy controls which MSRs can be written:

#### Never-Writable MSRs (Always Blocked)

These MSRs are blocked regardless of configuration:

| MSR                      | Address     | Risk                                  |
| ------------------------ | ----------- | ------------------------------------- |
| IA32_LSTAR               | 0xC0000082  | Syscall entry - kernel code execution |
| IA32_CSTAR               | 0xC0000083  | Compat syscall entry                  |
| IA32_STAR                | 0xC0000081  | Syscall segment selectors             |
| IA32_SFMASK              | 0xC0000084  | Syscall flag mask                     |
| IA32_SYSENTER_CS/ESP/EIP | 0x174-0x176 | Legacy syscall entry                  |
| IA32_EFER                | 0xC0000080  | NX disable, SMM                       |
| IA32_DEBUGCTL            | 0x1D9       | Debug/trace control                   |
| IA32_PAT                 | 0x277       | Page attribute table                  |
| AMD_SYSCFG               | 0xC0010010  | SME/SEV configuration                 |
| VMX Range                | 0x480-0x48F | Virtualization control                |

#### Opt-In Whitelist (Configurable)

When registry opt-in is enabled, these MSRs can be written:

- **Intel Performance:** PERFEVTSEL0-3, PMC0-3, FIXED_CTR0-2
- **Intel Power:** PKG_POWER_LIMIT, ENERGY_PERF_BIAS, HWP_REQUEST
- **AMD Performance:** PERFEVTSEL0-3, PERFCTR0-3
- **AMD P-States:** PSTATE_DEF_0 through PSTATE_DEF_7 (undervolting)

Registry key: `HKLM\SYSTEM\CurrentControlSet\Services\SafeRing0\Parameters`
Value: `EnableMsrWrites` (DWORD, 1 = enabled)

### Layer 3: Physical Memory Validation

All physical memory access requests are validated:

- **Kernel address blocking:** Addresses >= 0xFFFF800000000000 are rejected
- **Size limits:** Maximum mapping size enforced (SR0_MAX_MAP_SIZE)
- **BIOS region protection:** Optional blocking of low memory regions

### Layer 4: Rate Limiting (DoS Prevention)

Prevents abuse via excessive operations:

- **Per-process limit:** 100 operations/second
- **Global limit:** 1000 operations/second total
- **Sliding window:** Uses FIFO queue for accurate rate calculation
- **Stale entry cleanup:** Automatic pruning after 5 minutes of inactivity

### Layer 5: ETW Telemetry (Forensics)

All operations are logged via Event Tracing for Windows:

- MSR reads/writes (including blocked attempts)
- Physical memory access
- I/O port access
- PCI configuration access
- Rate limit exceeded events

Provider GUID: `{your-guid-here}` (generated at build time)

## Attack Mitigation Summary

| Attack Vector           | WinRing0   | SafeRing0                 |
| ----------------------- | ---------- | ------------------------- |
| Non-admin device access | VULNERABLE | BLOCKED (SDDL ACL)        |
| Syscall hook via LSTAR  | VULNERABLE | BLOCKED (never-writable)  |
| NX bypass via EFER      | VULNERABLE | BLOCKED (never-writable)  |
| Kernel memory read      | VULNERABLE | BLOCKED (address check)   |
| DoS via flooding        | VULNERABLE | MITIGATED (rate limiting) |
| Audit trail             | NONE       | ETW logging               |

## Threat Model

### In Scope

SafeRing0 protects against:

1. **Local privilege escalation** from authenticated non-admin users
2. **Kernel code execution** via MSR manipulation
3. **Kernel memory disclosure** via physical memory mapping
4. **Denial of service** via request flooding

### Out of Scope

SafeRing0 does NOT protect against:

1. **Attacks from Administrator accounts** - by design, admins can access hardware
2. **Physical attacks** - hardware access with physical machine access
3. **Supply chain attacks** - compromised driver binary
4. **Hypervisor-level attacks** - assumes trusted hypervisor if virtualized

### Trust Boundaries

```
+------------------+
|  User Process    |  ← Untrusted, must be Administrator
+--------+---------+
         |
         | CreateFile() - ACL check
         v
+--------+---------+
| SafeRing0 Driver |  ← Trusted, validates all inputs
+--------+---------+
         |
         | Policy checks, rate limiting
         v
+--------+---------+
|    Hardware      |  ← Trusted, but protected by policy
+------------------+
```

## Security Testing

### Required Tests

1. **Non-admin access test:** Verify `CreateFile()` fails with ERROR_ACCESS_DENIED
2. **LSTAR write test:** Verify MSR 0xC0000082 write returns STATUS_ACCESS_DENIED
3. **Kernel address test:** Verify mapping 0xFFFF800000000000 returns STATUS_ACCESS_DENIED
4. **Rate limit test:** Verify 101st operation in 1 second returns STATUS_QUOTA_EXCEEDED
5. **ETW test:** Verify all operations generate trace events

### Fuzzing Recommendations

- Input buffer size fuzzing for all IOCTLs
- MSR index fuzzing (random 32-bit values)
- Physical address fuzzing (including kernel range boundaries)
- PCI address fuzzing (invalid bus/device/function combinations)

## Responsible Disclosure

If you discover a security vulnerability in SafeRing0:

1. **Do NOT** create a public GitHub issue
2. Email **colin@teraflux.app** with details
3. Allow 1-30 days for patch development/Microsoft coordination
4. public disclosure

## Version History

| Version | Date    | Security Changes                                |
| ------- | ------- | ----------------------------------------------- |
| 1.0.0   | 2025-12 | Initial release with full security architecture |
