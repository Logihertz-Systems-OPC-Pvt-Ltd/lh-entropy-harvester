# Security Policy

## Supported Versions

Logihertz Systems provides security maintenance and vulnerability updates for the following release branches of `lh-entropy-harvester`:

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Hardware TRNG Threat Model & Security Posture

`lh-entropy-harvester` addresses critical security and randomness integrity boundaries for hardware security modules (HSM), secure elements, cryptographic coprocessors, and embedded Linux devices harvesting physical entropy from uninitialized SRAM PUFs, ADC thermal jitter, and ring oscillator jitter:

1. **Noise Source Physical Failures & Stuck-at Faults (CWE-331 / CWE-693)**:
   - Hardware noise sources can suffer catastrophic physical failures such as frozen ADC converters, grounded zener diodes, or unpowered thermal noise channels.
   - Continuous Repetition Count Test (RCT per NIST SP 800-90B Section 4.4.1) halts entropy feed within deterministic bounds ($C_{\text{RCT}}$) upon detecting repeated symbols.
2. **Harmonic Coupling & Statistical Bias (CWE-1300 / CWE-338)**:
   - External clock interference, switch-mode power supply ripple, or intentional RF carrier injection can induce periodic structures into analog noise sources.
   - Continuous Adaptive Proportion Test (APT per NIST SP 800-90B Section 4.4.2) and lag-1 serial autocorrelation checks detect statistical bias and frequency injection before entropy is accepted.
3. **Cryptographic Conditioning & Kernel Pool Poisoning (CWE-338 / CWE-330)**:
   - Feeding unconditioned raw analog noise directly into `/dev/random` risks injecting correlated or partially predictable bits.
   - A multi-stage architecture (Von Neumann debiasing followed by NIST SP 800-90B vetted FIPS 180-4 SHA-256 / HMAC-SHA256 conditioning with $\ge 2.0\times$ compression) guarantees full entropy output.
4. **Memory Residuals & Process Isolation (CWE-226 / CWE-250)**:
   - All intermediate raw noise buffers and hash states are immediately zeroized via volatile memory barriers.
   - Memory is locked against paging (`mlockall`), and the daemon drops root privileges to retain only `CAP_SYS_ADMIN` under seccomp syscall filtering.

## Reporting a Vulnerability

If you discover a security flaw, entropy degradation vector, or cryptographic weakness in `lh-entropy-harvester`:

1. **Do not disclose publicly** through issue trackers or public discussions.
2. Email the maintainers directly at **`ops@logihertz.com`** and **`security@logihertz.com`** with the subject line:
   `[SECURITY] Vulnerability in lh-entropy-harvester: <Brief Description>`
3. Include in your report:
   - Affected subsystem (NIST SP 800-90B health tester, SHA-256 conditioner, posture auditor, or CLI).
   - Sample noise trace or configuration manifest reproducing the issue.
   - Theoretical or empirical impact on cryptographic key generation or `/dev/random` quality.
4. The Logihertz security response team will acknowledge receipt within 48 hours and provide a coordinated disclosure plan and patch advisory.
