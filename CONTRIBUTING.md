# Contributing to Logihertz Cryptographic Hardware Entropy Daemon

Thank you for your interest in contributing to `lh-entropy-harvester`. This project provides a production-grade C11 cryptographic hardware entropy daemon, SRAM and ADC thermal jitter harvester, NIST SP 800-90B continuous health tester, SHA-256 cryptographic conditioner, and 10-rule TRNG security posture auditor.

## Architectural Mandates & Principles

1. **Zero Third-Party Library Dependencies**:
   - The CLI and daemon binary (`bin/lh-entropy`) and test runner (`tests/test_runner`) must depend strictly on standard ISO C11 libc and the standard math library (`-lm`).
   - All cryptographic algorithms (FIPS 180-4 SHA-256, HMAC-SHA256), entropy estimators, and JSON parsers must remain self-contained without external libraries.
2. **Strict Compiler Conformance**:
   - Code must compile with zero warnings under both GCC and Clang:
     ```bash
     -std=c11 -O2 -Wall -Wextra -Werror -pedantic
     ```
3. **NIST SP 800-90B Mathematical Rigor**:
   - The Repetition Count Test (RCT) and Adaptive Proportion Test (APT) formulas must adhere strictly to NIST SP 800-90B Section 4.4.
   - Most Common Value (MCV) min-entropy calculations must implement the 99% confidence upper bound ($Z_{0.995} = 2.5758293$) per Section 6.3.1.
4. **Defensive Memory Handling**:
   - All cryptographic buffers, raw noise arrays, and key material must be sanitized using volatile zeroization (`lh_secure_zero`) prior to deallocation.

## Development Workflow

### Prerequisites

- GCC 10+ or Clang 12+
- GNU Make 4.0+
- Standard POSIX libc and math library (`-lm`)

### Building and Testing

```bash
# Build binary and run test suite
make all test

# Build with Clang (if installed)
make CC=clang clean all test

# Clean artifacts
make clean
```

### Submitting Pull Requests

1. Fork the repository and create a feature branch (`git checkout -b feature/apt-optimization`).
2. Adhere to Conventional Commits:
   - `feat(sp800-90b): add binomial tail approximation for APT`
   - `fix(conditioner): optimize message schedule unrolling in SHA-256`
   - `test(auditor): add test assertion for rail saturation guard`
3. Ensure `make all test` passes with 100% success and zero warnings.
4. Open a pull request against the `main` branch.
