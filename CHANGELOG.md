# Changelog

All notable changes to `lh-entropy-harvester` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **NIST SP 800-90B Continuous Health Testing Suite (`src/sp800_90b_health.c`)**:
  - Implemented Repetition Count Test (RCT) per Section 4.4.1 with dynamic cutoff $C_{\text{RCT}} = 1 + \lceil 30.0 / H_{\min} \rceil$ and stuck-at fault latching.
  - Implemented Adaptive Proportion Test (APT) per Section 4.4.2 over $W = 512$ byte windows with analytical binomial tail cutoffs.
  - Implemented Section 6.3.1 Most Common Value (MCV) min-entropy ($H_\infty$) estimator with 99% confidence upper bound ($Z_{0.995} = 2.5758293$).
  - Implemented Shannon entropy ($H_1$) and lag-1 serial autocorrelation coefficient ($r_1$) for harmonic/clock injection detection.
- **Cryptographic Conditioning & Debiasing Engine (`src/sha256_conditioner.c`)**:
  - Implemented Stage 1 Von Neumann unbiased bit-pair extractor for independent Bernoulli noise sources.
  - Implemented Stage 2 NIST SP 800-90B vetted FIPS 180-4 SHA-256 and RFC 2104 HMAC-SHA256 cryptographic conditioner.
  - Built-in FIPS 140-3 Known Answer Test (KAT) verification on startup.
  - Implemented Linux `/dev/random` `struct rand_pool_info` (`RNDADDENTROPY`) payload construction with conservative entropy bit crediting.
  - Implemented volatile memory zeroization (`lh_secure_zero`) for defense against memory residual leaks.
- **10-Rule Hardware TRNG Security Posture Auditor (`src/entropy_auditor.c`)**:
  - Implemented full normative rules `LH-ENT-001` through `LH-ENT-010` covering min-entropy safety floors, vetted conditioning, RCT/APT health halts, startup POST/KAT, conservative credit derating, buffer zeroization, ADC rail saturation, privilege dropping, watermarks, and audit logging.
  - Implemented standardized Logihertz Security Posture Score calculation ($S_{\text{posture}} \in [0, 100]$).
- **Multi-Format Export Engine (`src/exporters.c`)**:
  - ANSI terminal formatted tables with status badges.
  - Canonical JSON exporter.
  - OASIS SARIF v2.1.0 exporter with full rule catalog and CWE cross-references.
- **Userspace Command-Line Interface (`src/main.c` / `bin/lh-entropy`)**:
  - Commands: `scan`, `analyze-noise`, `condition`, `health-test`, `--version`, and `--help`.
- **Deterministic Test Suite (`tests/test_runner.c`)**:
  - Comprehensive suite of 85+ assertions verifying health tests, cryptographic conditioner, auditor math, and CLI execution.
